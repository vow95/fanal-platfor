"""Tests for the nmap runner (SPEC.md task 1.2). No real nmap or network: a fake process
writes the saved Metasploitable 2 XML, and a fake clock drives time limits."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cybrx.lab import lab_scope
from cybrx.runners import nmap_runner as nr
from cybrx.runners.nmap_runner import NmapOptions, build_command, parse, run

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_metasploitable2.xml"
START = datetime(2026, 11, 19, 20, 0, tzinfo=timezone.utc)
DNS = {"metasploitable.lab": ["192.168.56.104"], "rebind.evil.test": ["127.0.0.1"]}


def resolver(name: str) -> list[str]:
    if name not in DNS:
        raise OSError("not found")
    return DNS[name]


class FakeClock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class FakeNmap:
    """Stands in for subprocess.Popen. mode: 'finish', 'hang' or 'flood'."""

    def __init__(self, mode: str = "finish", xml: bytes | None = None) -> None:
        self.mode, self.xml = mode, xml if xml is not None else FIXTURE.read_bytes()
        self.calls: list[tuple[list[str], dict]] = []
        self.terminated = False
        self.returncode: int | None = None

    def __call__(self, cmd: list[str], **kwargs: object) -> "FakeNmap":
        self.calls.append((cmd, kwargs))
        out = Path(cmd[cmd.index("-oX") + 1])
        if self.mode == "finish":
            out.write_bytes(self.xml)
        elif self.mode == "flood":
            out.write_bytes(b"x" * 5000)
        elif self.mode == "hang":
            out.write_bytes(self.xml[: len(self.xml) // 2])  # nmap stopped half way
        return self

    def poll(self) -> int | None:
        if self.mode == "finish":
            self.returncode = 0
        return self.returncode

    def terminate(self) -> None:
        self.terminated, self.returncode = True, -15

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int | None:
        return self.returncode


def scope(hours: int = 4):
    return lab_scope("Lab owner", hours=hours, now=START)


def do_run(targets, fake=None, options=None, hours=4, clock=None):
    fake = fake or FakeNmap()
    clock = clock or FakeClock()
    raw = run(scope(hours), targets, options, resolver=resolver, clock=clock,
              sleep=clock.sleep, popen=fake, poll_seconds=60)
    return raw, fake


# --- Parsing ------------------------------------------------------------------------

def test_parse_metasploitable_fixture():
    result = parse(FIXTURE.read_bytes())
    assert result.nmap_version == "7.99" and not result.truncated
    (host,) = result.hosts
    assert host.address == "192.168.56.104" and host.status == "up"
    assert host.mac == "08:00:27:6C:43:BC"
    assert len(host.open_services) == 23
    ftp = next(s for s in host.services if s.port == 21)
    assert (ftp.name, ftp.product, ftp.version) == ("ftp", "vsftpd", "2.3.4")
    assert ftp.cpe == ("cpe:/a:vsftpd:vsftpd:2.3.4",)
    assert {s.port for s in host.open_services} >= {21, 22, 80, 445, 1524, 3306, 6667, 8180}


def test_parse_truncated_xml_keeps_complete_hosts():
    two_hosts = FIXTURE.read_bytes().replace(b"</host>", b"</host>\n<host><status state=\"up\"/>", 1)
    cut = two_hosts[: two_hosts.index(b"<host><status")+30]  # second host cut off
    result = parse(cut)
    assert result.truncated
    assert len(result.hosts) == 1 and len(result.hosts[0].open_services) == 23


def test_parse_refuses_entities_and_non_nmap_xml():
    with pytest.raises(ValueError, match="entity"):
        parse(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>')
    with pytest.raises(ValueError, match="not nmap"):
        parse(b"<html><body>hi</body></html>")


def test_parse_empty_output():
    assert parse(b"").hosts == ()


# --- Command building (SBD-10, SBD-12) ------------------------------------------------

def test_command_is_a_list_with_safe_flags(tmp_path):
    cmd = build_command(["192.168.56.104"], NmapOptions(ports="21,22,80-90"), tmp_path / "o.xml")
    assert cmd[0] == "nmap" and isinstance(cmd, list)
    assert "-n" in cmd                      # nmap does no DNS of its own
    assert cmd[cmd.index("-p") + 1] == "21,22,80-90"
    assert cmd[-1] == "192.168.56.104"


@pytest.mark.parametrize("bad", ["-oN /etc/passwd", "8.8.8.8 --script evil", "evil.host"])
def test_command_refuses_anything_but_addresses(tmp_path, bad):
    with pytest.raises(ValueError):
        build_command([bad], NmapOptions(), tmp_path / "o.xml")


@pytest.mark.parametrize("kwargs", [
    {"ports": "21;id"}, {"ports": "0"}, {"ports": "70000"}, {"ports": "90-80"},
    {"ports": "--script=vuln"}, {"timing": "T5"}, {"timing": "T0"},
    {"host_timeout_minutes": 0}, {"max_runtime_seconds": 0},
])
def test_options_are_validated(kwargs):
    with pytest.raises(ValueError):
        NmapOptions(**kwargs)


# --- Running through the scope guard (SBD-01, SBD-03) -------------------------------------

def test_run_scans_metasploitable_and_parses():
    raw, fake = do_run(["192.168.56.104"])
    assert raw.stopped_reason is None and raw.returncode == 0
    cmd, kwargs = fake.calls[0]
    assert kwargs["shell"] is False and cmd[-1] == "192.168.56.104"
    assert len(parse(raw).hosts[0].open_services) == 23


def test_out_of_scope_targets_never_reach_nmap():
    raw, fake = do_run(["192.168.56.104", "8.8.8.8", "192.168.56.1", "169.254.169.254"])
    cmd, _ = fake.calls[0]
    assert raw.targets == ("192.168.56.104",)
    for bad in ("8.8.8.8", "192.168.56.1", "169.254.169.254"):
        assert bad not in cmd
    assert {d.target for d in raw.blocked} == {"8.8.8.8", "192.168.56.1", "169.254.169.254"}


def test_nothing_in_scope_means_nmap_never_starts():
    raw, fake = do_run(["8.8.8.8", "rebind.evil.test"])
    assert raw.stopped_reason == "no_targets"
    assert fake.calls == []


def test_hostname_is_replaced_by_checked_ip():
    raw, fake = do_run(["metasploitable.lab"])
    cmd, _ = fake.calls[0]
    assert "metasploitable.lab" not in cmd and cmd[-1] == "192.168.56.104"


def test_urls_are_refused_for_nmap():
    raw, fake = do_run(["http://192.168.56.103:3000", "192.168.56.104"])
    assert raw.targets == ("192.168.56.104",)
    assert any("web module" in d.reason for d in raw.blocked)


def test_duplicate_targets_scanned_once():
    raw, _ = do_run(["192.168.56.104", "metasploitable.lab", "192.168.56.104"])
    assert raw.targets == ("192.168.56.104",)


# --- Limits while running (SBD-04, SBD-13) ----------------------------------------------

def test_run_stopped_after_time_limit():
    raw, fake = do_run(["192.168.56.104"], FakeNmap("hang"), NmapOptions(max_runtime_seconds=600))
    assert raw.stopped_reason == "timeout" and fake.terminated and raw.partial
    assert parse(raw).truncated


def test_run_stopped_when_scope_expires_mid_scan():
    # Scope valid for 1 hour; nmap would run 2 hours.
    raw, fake = do_run(["192.168.56.104"], FakeNmap("hang"), hours=1)
    assert raw.stopped_reason == "scope_expired" and fake.terminated


def test_run_stopped_when_output_too_large():
    raw, fake = do_run(["192.168.56.104"], FakeNmap("flood"), NmapOptions(max_output_bytes=1000))
    assert raw.stopped_reason == "output_limit" and fake.terminated
    assert len(raw.xml) <= 1000


def test_temp_files_are_removed():
    raw, fake = do_run(["192.168.56.104"])
    cmd, _ = fake.calls[0]
    assert not Path(cmd[cmd.index("-oX") + 1]).parent.exists()


# --- Audit (SBD-50) ----------------------------------------------------------------------

def test_launch_is_audited_with_exact_command(caplog):
    with caplog.at_level(logging.INFO, logger="cybrx.audit"):
        raw, _ = do_run(["192.168.56.104"])
    events = [json.loads(r.message) for r in caplog.records if r.name == "cybrx.audit"]
    started = next(e for e in events if e["event"] == "scan_started")
    assert started["command"] == list(raw.command)
    assert started["authorised_by"] == "Lab owner"
    assert any(e["event"] == "scan_finished" for e in events)


# --- Real subprocess path (a stand-in "nmap" program, still no network) ---------------------

def test_real_subprocess_path_end_to_end(tmp_path, monkeypatch):
    import sys
    from cybrx import config
    fake_nmap = tmp_path / "nmap"
    fake_nmap.write_text(
        f"#!{sys.executable}\n"
        "import sys, shutil\n"
        "args = sys.argv[1:]\n"
        f"shutil.copy({str(FIXTURE)!r}, args[args.index('-oX') + 1])\n"
    )
    fake_nmap.chmod(0o755)
    monkeypatch.setattr(config, "NMAP_BINARY", str(fake_nmap))
    raw = run(scope(), ["192.168.56.104"], resolver=resolver, poll_seconds=0.05,
              clock=lambda: START + timedelta(seconds=1))
    assert raw.returncode == 0 and raw.stopped_reason is None
    assert len(parse(raw).hosts[0].open_services) == 23
