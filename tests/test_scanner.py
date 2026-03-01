from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from net_audit_report.scanner import (
    ScanProfile, ScanConfig, build_nmap_command, run_scan,
    check_nmap_installed, list_profiles, SCAN_PROFILES,
)


# ── build_nmap_command tests ─────────────────────────────────────────────────


def test_build_command_quick_profile():
    config = ScanConfig(targets=["192.168.1.0/24"], profile=ScanProfile.QUICK)
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert cmd[0] == "nmap"
    assert "-sV" in cmd
    assert "--top-ports" in cmd
    assert "100" in cmd
    assert "-oX" in cmd
    assert "/tmp/out.xml" in cmd
    assert "192.168.1.0/24" in cmd


def test_build_command_full_profile():
    config = ScanConfig(targets=["10.0.0.1"], profile=ScanProfile.FULL)
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "-p-" in cmd
    assert "--script" in cmd
    assert "-O" in cmd


def test_build_command_with_sudo():
    config = ScanConfig(targets=["10.0.0.1"], profile=ScanProfile.UDP, sudo=True)
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert cmd[0] == "sudo"
    assert cmd[1] == "nmap"


def test_build_command_custom_ports():
    config = ScanConfig(targets=["10.0.0.1"], profile=ScanProfile.QUICK, ports="22,80,443")
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "-p" in cmd
    idx = cmd.index("-p")
    assert cmd[idx + 1] == "22,80,443"


def test_build_command_top_ports():
    config = ScanConfig(targets=["10.0.0.1"], top_ports=50)
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "--top-ports" in cmd
    assert "50" in cmd


def test_build_command_custom_scripts():
    config = ScanConfig(targets=["10.0.0.1"], scripts="vuln,ssl-cert")
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "--script" in cmd
    idx = cmd.index("--script")
    assert cmd[idx + 1] == "vuln,ssl-cert"


def test_build_command_timing():
    config = ScanConfig(targets=["10.0.0.1"], timing=4)
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "-T4" in cmd


def test_build_command_interface():
    config = ScanConfig(targets=["10.0.0.1"], interface="eth0")
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "-e" in cmd
    assert "eth0" in cmd


def test_build_command_exclude():
    config = ScanConfig(targets=["10.0.0.0/24"], exclude="10.0.0.1,10.0.0.2")
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "--exclude" in cmd
    assert "10.0.0.1,10.0.0.2" in cmd


def test_build_command_extra_args():
    config = ScanConfig(targets=["10.0.0.1"], extra_args=["--max-retries", "2", "-v"])
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "--max-retries" in cmd
    assert "2" in cmd
    assert "-v" in cmd


def test_build_command_multiple_targets():
    config = ScanConfig(targets=["10.0.0.1", "10.0.0.2", "192.168.1.0/24"])
    cmd = build_nmap_command(config, "/tmp/out.xml")
    assert "10.0.0.1" in cmd
    assert "10.0.0.2" in cmd
    assert "192.168.1.0/24" in cmd


def test_build_command_xml_output_always_present():
    config = ScanConfig(targets=["10.0.0.1"])
    cmd = build_nmap_command(config, "/tmp/test.xml")
    assert "-oX" in cmd
    assert "/tmp/test.xml" in cmd


# ── list_profiles tests ─────────────────────────────────────────────────────


def test_list_profiles():
    profiles = list_profiles()
    assert len(profiles) == len(ScanProfile)
    names = {p["name"] for p in profiles}
    assert "quick" in names
    assert "full" in names
    assert "vuln" in names
    assert "ssl" in names
    assert "udp" in names


def test_all_profiles_have_descriptions():
    for p in list_profiles():
        assert p["description"], f"Profile {p['name']} missing description"
        assert p["args"], f"Profile {p['name']} missing args"


# ── check_nmap_installed tests ───────────────────────────────────────────────


def test_check_nmap_not_found():
    with patch("shutil.which", return_value=None):
        installed, msg = check_nmap_installed()
        assert not installed
        assert "not found" in msg


def test_check_nmap_found():
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        mock_result = MagicMock()
        mock_result.stdout = "Nmap version 7.94 ( https://nmap.org )\n"
        with patch("subprocess.run", return_value=mock_result):
            installed, msg = check_nmap_installed()
            assert installed
            assert "7.94" in msg


# ── run_scan tests (mocked) ─────────────────────────────────────────────────


SAMPLE_XML_CONTENT = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_run_scan_success():
    """Test a successful scan with mocked subprocess."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w") as tmp:
        xml_path = tmp.name

    def mock_run(cmd, **kwargs):
        # Write sample XML to the output path
        # Find -oX in cmd and get the next arg
        for i, arg in enumerate(cmd):
            if arg == "-oX" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(SAMPLE_XML_CONTENT)
                break
        result = MagicMock()
        result.returncode = 0
        result.stdout = "Nmap done: 1 IP address (1 host up)"
        result.stderr = ""
        return result

    try:
        config = ScanConfig(
            targets=["10.0.0.1"],
            profile=ScanProfile.QUICK,
            output_xml=xml_path,
        )
        with patch("subprocess.run", side_effect=mock_run):
            result = run_scan(config)
            assert result.success
            assert result.return_code == 0
            assert result.duration_seconds >= 0
            assert Path(result.xml_path).exists()

            # Verify the XML can be parsed
            from net_audit_report.nmap_parser import parse_nmap_xml
            hosts = parse_nmap_xml(result.xml_path)
            assert len(hosts) == 1
            assert hosts[0].address == "10.0.0.1"
    finally:
        Path(xml_path).unlink(missing_ok=True)


def test_run_scan_failure():
    """Test a failed scan with mocked subprocess."""
    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stdout = ""
        result.stderr = "Failed to resolve host"
        return result

    config = ScanConfig(
        targets=["nonexistent.invalid"],
        profile=ScanProfile.QUICK,
    )
    with patch("subprocess.run", side_effect=mock_run):
        result = run_scan(config)
        assert not result.success
        assert result.return_code == 1


def test_run_scan_timeout():
    """Test a scan that times out."""
    import subprocess as sp

    config = ScanConfig(
        targets=["10.0.0.1"],
        profile=ScanProfile.QUICK,
        timeout=1,
    )
    with patch("subprocess.run", side_effect=sp.TimeoutExpired(cmd="nmap", timeout=1)):
        result = run_scan(config)
        assert not result.success
        assert "timed out" in result.stderr.lower()


def test_run_scan_nmap_not_installed():
    """Test when nmap binary is not found."""
    config = ScanConfig(
        targets=["10.0.0.1"],
        profile=ScanProfile.QUICK,
    )
    with patch("subprocess.run", side_effect=FileNotFoundError("nmap not found")):
        result = run_scan(config)
        assert not result.success
        assert "nmap" in result.stderr.lower()


def test_run_scan_command_includes_targets():
    """Verify the built command is passed to subprocess."""
    captured_cmd = []

    def mock_run(cmd, **kwargs):
        captured_cmd.extend(cmd)
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        return result

    config = ScanConfig(
        targets=["192.168.1.0/24"],
        profile=ScanProfile.QUICK,
    )
    with patch("subprocess.run", side_effect=mock_run):
        run_scan(config)
        assert "192.168.1.0/24" in captured_cmd
        assert "nmap" in captured_cmd


# ── ScanProfile coverage ────────────────────────────────────────────────────


def test_all_profiles_have_args():
    for profile in ScanProfile:
        assert profile in SCAN_PROFILES
        assert len(SCAN_PROFILES[profile]) > 0


def test_ping_profile_has_no_port_scan():
    args = SCAN_PROFILES[ScanProfile.PING]
    assert "-sn" in args


def test_ssl_profile_targets_ssl_ports():
    args = SCAN_PROFILES[ScanProfile.SSL]
    assert "-p" in args
    port_idx = args.index("-p")
    ports_str = args[port_idx + 1]
    assert "443" in ports_str
