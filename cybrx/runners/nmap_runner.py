"""nmap runner (SPEC.md task 1.2): run nmap safely on in-scope targets and parse its XML.

Safety rules applied here (SECURITY.md):
- every target goes through the scope guard first; nmap only ever sees addresses the guard
  checked: hostnames are replaced by the IPs the guard resolved, and nmap runs with -n so it
  never does its own DNS (SBD-01, SBD-03; stops DNS from changing between check and scan);
- the command is a list of arguments with no shell, built only from validated options:
  there is no way to pass free-form nmap flags (SBD-10, SBD-12);
- the run is stopped if it exceeds its time limit, its output limit, or the scope's end time
  (SBD-04, SBD-13);
- each launch is written to the audit log with the exact command line (SBD-50).

Example:
    raw = run(lab_scope("Ahad"), ["192.168.56.104"])
    for host in parse(raw).hosts:
        for s in host.open_services:
            print(s.port, s.name, s.product, s.version)   # 21 ftp vsftpd 2.3.4 ...
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from cybrx import config
from cybrx.scope import Decision, Resolver, Scope, check_targets, default_resolver, parse_target

logger = logging.getLogger("cybrx.nmap")
audit = logging.getLogger("cybrx.audit")

_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
# T0/T1 are impractically slow; T5 is aggressive enough to disrupt fragile hosts (SBD-14).
TIMINGS = ("T2", "T3", "T4")
_MAX_STDERR_BYTES = 1024 * 1024


@dataclass(frozen=True)
class NmapOptions:
    """The only knobs a caller can turn. No free-form nmap arguments exist on purpose.

    ports: None = nmap's default top 1000 TCP ports, or e.g. "21,22,80-90".
    """

    ports: str | None = None
    timing: str = "T3"
    service_detection: bool = True
    host_timeout_minutes: int = 30
    max_runtime_seconds: int = config.NMAP_MAX_RUNTIME_SECONDS
    max_output_bytes: int = config.NMAP_MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if self.ports is not None:
            if len(self.ports) > 500 or not _PORTS_RE.match(self.ports):
                raise ValueError(f"invalid ports {self.ports!r}: use e.g. '21,22,80-90'")
            for part in self.ports.split(","):
                low, _, high = part.partition("-")
                lo, hi = int(low), int(high or low)
                if not 1 <= lo <= hi <= 65535:
                    raise ValueError(f"invalid port range {part!r}")
        if self.timing not in TIMINGS:
            raise ValueError(f"timing must be one of {TIMINGS}")
        if not 1 <= self.host_timeout_minutes <= 240:
            raise ValueError("host_timeout_minutes must be 1-240")
        if self.max_runtime_seconds <= 0 or self.max_output_bytes <= 0:
            raise ValueError("limits must be positive")


@dataclass(frozen=True)
class RawResult:
    """What one nmap launch produced, before parsing.

    stopped_reason: None (finished normally), "no_targets" (nothing in scope, nmap never ran),
    "timeout", "scope_expired" or "output_limit" (nmap was stopped; results may be partial).
    """

    command: tuple[str, ...]
    targets: tuple[str, ...]
    blocked: tuple[Decision, ...]
    xml: bytes
    stderr: str
    returncode: int | None
    started_at: datetime
    finished_at: datetime
    stopped_reason: str | None

    @property
    def partial(self) -> bool:
        return self.stopped_reason not in (None, "no_targets")


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    state: str
    name: str
    product: str
    version: str
    extrainfo: str
    cpe: tuple[str, ...]


@dataclass(frozen=True)
class HostResult:
    address: str
    status: str
    mac: str | None
    mac_vendor: str | None
    hostnames: tuple[str, ...]
    services: tuple[Service, ...]

    @property
    def open_services(self) -> tuple[Service, ...]:
        return tuple(s for s in self.services if s.state == "open")


@dataclass(frozen=True)
class NmapRun:
    """Parsed nmap output. truncated=True when the XML was cut off (e.g. nmap was stopped):
    hosts then holds every host that was completely written before the cut."""

    nmap_version: str | None
    hosts: tuple[HostResult, ...]
    truncated: bool
    extra: dict[str, Any] = field(default_factory=dict)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def nmap_targets(allowed: Iterable[Decision]) -> tuple[list[str], list[Decision]]:
    """Turn allowed decisions into the addresses nmap may scan.

    Hostnames become the IPs the guard resolved (never the name). URLs are refused here:
    they belong to the web module. IPv6 is refused for now: nmap needs a separate -6 run.
    Example: metasploitable.lab (resolved to 192.168.56.104) -> "192.168.56.104".
    """
    addresses: list[str] = []
    refused: list[Decision] = []
    for decision in allowed:
        target = parse_target(decision.target)
        if target.kind == "url":
            refused.append(Decision(decision.target, False, "URL targets belong to the web module, not nmap"))
            continue
        candidates = list(decision.resolved_ips) if target.kind == "hostname" else [target.host]
        if not candidates:
            refused.append(Decision(decision.target, False, "no checked address to scan"))
            continue
        for candidate in candidates:
            if ipaddress.ip_network(candidate, strict=False).version != 4:
                refused.append(Decision(decision.target, False, "IPv6 scanning is not supported yet"))
                break
        else:
            addresses.extend(c for c in candidates if c not in addresses)
    return addresses, refused


def build_command(addresses: list[str], options: NmapOptions, xml_path: Path) -> list[str]:
    """Build the nmap command as a list (never a shell string).

    Example: ["nmap", "-n", "-T3", "--host-timeout", "30m", "--noninteractive",
              "-sV", "-oX", "/tmp/cybrx-nmap-x/out.xml", "192.168.56.104"]
    """
    for address in addresses:  # defence in depth: only IPs/CIDRs ever reach the command line
        ipaddress.ip_network(address, strict=False)
        if address.startswith("-"):
            raise ValueError(f"refusing address {address!r}")
    cmd = [
        config.NMAP_BINARY, "-n", f"-{options.timing}",
        "--host-timeout", f"{options.host_timeout_minutes}m", "--noninteractive",
    ]
    if options.service_detection:
        cmd.append("-sV")
    if options.ports:
        cmd += ["-p", options.ports]
    cmd += ["-oX", str(xml_path)]
    return cmd + list(addresses)


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _stop(proc: Any) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def run(
    scope: Scope,
    targets: Iterable[str],
    options: NmapOptions | None = None,
    *,
    resolver: Resolver = default_resolver,
    clock: Callable[[], datetime] = _utcnow,
    sleep: Callable[[float], None] = time.sleep,
    popen: Callable[..., Any] = subprocess.Popen,
    poll_seconds: float = 1.0,
) -> RawResult:
    """Scope-check the targets, run nmap on the allowed ones, and return the raw output.

    clock, sleep and popen exist so tests can run without nmap or a network.
    """
    options = options or NmapOptions()
    started = clock()
    allowed, blocked = check_targets(scope, list(targets), now=started, resolver=resolver)
    addresses, refused = nmap_targets(allowed)
    for decision in refused:
        logger.warning(json.dumps({"event": "target_refused", "target": decision.target,
                                   "reason": decision.reason}))
    blocked_all = tuple(blocked + refused)

    if not addresses:
        return RawResult((), (), blocked_all, b"", "", None, started, clock(), "no_targets")

    if popen is subprocess.Popen and shutil.which(config.NMAP_BINARY) is None:
        raise FileNotFoundError(f"{config.NMAP_BINARY!r} not found: install nmap (task 0.4)")

    workdir = Path(tempfile.mkdtemp(prefix="cybrx-nmap-"))  # private (0700) temp directory
    try:
        xml_path, err_path = workdir / "out.xml", workdir / "stderr.txt"
        cmd = build_command(addresses, options, xml_path)
        audit.info(json.dumps({
            "event": "scan_started", "tool": "nmap", "command": cmd, "targets": addresses,
            "authorised_by": scope.authorised_by, "started_at": started.isoformat(),
        }))
        reason: str | None = None
        with open(err_path, "wb") as err:
            proc = popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=err, shell=False, close_fds=True)
            try:
                while proc.poll() is None:
                    now = clock()
                    if (now - started).total_seconds() > options.max_runtime_seconds:
                        reason = "timeout"
                    elif now > scope.ends_at:
                        reason = "scope_expired"
                    elif _size(xml_path) > options.max_output_bytes or _size(err_path) > _MAX_STDERR_BYTES:
                        reason = "output_limit"
                    if reason:
                        _stop(proc)
                        break
                    sleep(poll_seconds)
            except BaseException:
                _stop(proc)
                raise
        with open(xml_path, "rb") if xml_path.exists() else _empty() as fh:
            xml = fh.read(options.max_output_bytes)
        stderr = err_path.read_bytes()[:10_000].decode("utf-8", "replace")
        finished = clock()
        audit.info(json.dumps({
            "event": "scan_finished", "tool": "nmap", "returncode": proc.returncode,
            "stopped_reason": reason, "finished_at": finished.isoformat(),
        }))
        return RawResult(tuple(cmd), tuple(addresses), blocked_all, xml, stderr,
                         proc.returncode, started, finished, reason)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


class _empty:
    def __enter__(self) -> "_empty":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _: int) -> bytes:
        return b""


def parse(raw: RawResult | bytes) -> NmapRun:
    """Parse nmap XML into hosts and services. Keeps every complete host from cut-off XML.

    Raises ValueError for XML that declares entities or is not nmap output.
    """
    data = raw.xml if isinstance(raw, RawResult) else raw
    if not data.strip():
        return NmapRun(None, (), truncated=isinstance(raw, RawResult) and raw.partial)
    if b"<!ENTITY" in data:
        raise ValueError("refusing XML with entity declarations")
    parser = ET.XMLPullParser(events=("start", "end"))
    truncated = False
    try:
        parser.feed(data)
        parser.close()
    except ET.ParseError:
        truncated = True
    version: str | None = None
    hosts: list[HostResult] = []
    first = True
    for event, elem in parser.read_events():
        if first:
            if elem.tag != "nmaprun":
                raise ValueError("not nmap XML output")
            version = elem.get("version")
            first = False
        if event == "end" and elem.tag == "host":
            hosts.append(_parse_host(elem))
            elem.clear()
    if first:
        raise ValueError("not nmap XML output")
    return NmapRun(version, tuple(hosts), truncated)


def _parse_host(elem: ET.Element) -> HostResult:
    status_el = elem.find("status")
    address, mac, vendor = "", None, None
    for a in elem.findall("address"):
        if a.get("addrtype") in ("ipv4", "ipv6"):
            address = a.get("addr", "")
        elif a.get("addrtype") == "mac":
            mac, vendor = a.get("addr"), a.get("vendor")
    hostnames = tuple(h.get("name", "") for h in elem.findall("hostnames/hostname"))
    services = []
    for p in elem.findall("ports/port"):
        state_el, svc = p.find("state"), p.find("service")
        services.append(Service(
            port=int(p.get("portid", "0")),
            protocol=p.get("protocol", ""),
            state=state_el.get("state", "") if state_el is not None else "",
            name=svc.get("name", "") if svc is not None else "",
            product=svc.get("product", "") if svc is not None else "",
            version=svc.get("version", "") if svc is not None else "",
            extrainfo=svc.get("extrainfo", "") if svc is not None else "",
            cpe=tuple(c.text or "" for c in svc.findall("cpe")) if svc is not None else (),
        ))
    return HostResult(address, status_el.get("state", "") if status_el is not None else "",
                      mac, vendor, hostnames, tuple(services))


def main(argv: list[str] | None = None) -> int:
    """Lab CLI: python -m cybrx.runners.nmap_runner --by "Ahad" 192.168.56.104"""
    ap = argparse.ArgumentParser(prog="python -m cybrx.runners.nmap_runner",
                                 description="Run nmap on lab targets through the scope guard.")
    ap.add_argument("targets", nargs="+", help="IPs, CIDRs or hostnames in the lab")
    ap.add_argument("--by", required=True, help="who authorised this lab scan (SBD-05)")
    ap.add_argument("--ports", help="e.g. 21,22,80-90 (default: top 1000 TCP ports)")
    ap.add_argument("--timing", default="T3", choices=TIMINGS)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s", stream=sys.stderr)
    from cybrx.lab import lab_scope  # local import keeps the runner free of lab defaults

    raw = run(lab_scope(args.by), args.targets, NmapOptions(ports=args.ports, timing=args.timing))
    for d in raw.blocked:
        print(f"BLOCKED  {d.target}: {d.reason}", file=sys.stderr)
    if raw.stopped_reason == "no_targets":
        print("Nothing in scope to scan.", file=sys.stderr)
        return 2
    result = parse(raw)
    for host in result.hosts:
        print(f"\n{host.address}  ({host.status})")
        for s in host.open_services:
            detail = " ".join(x for x in (s.product, s.version, f"({s.extrainfo})" if s.extrainfo else "") if x)
            print(f"  {s.port:>5}/{s.protocol:<4} {s.name:<12} {detail}")
    total = sum(len(h.open_services) for h in result.hosts)
    print(f"\n{len(result.hosts)} host(s), {total} open port(s); nmap {result.nmap_version}")
    if raw.stopped_reason:
        print(f"WARNING: nmap was stopped ({raw.stopped_reason}); results may be incomplete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
