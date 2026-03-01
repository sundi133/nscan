from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import xml.etree.ElementTree as ET
import re


@dataclass(frozen=True)
class ScriptResult:
    script_id: str
    output: str
    elements: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    state: str
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    tunnel: Optional[str] = None
    scripts: list[ScriptResult] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class OSMatch:
    name: str
    accuracy: int
    os_family: Optional[str] = None
    os_gen: Optional[str] = None
    cpe: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Host:
    address: str
    hostname: Optional[str]
    status: str
    services: list[Service]
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    os_matches: list[OSMatch] = field(default_factory=list)
    host_scripts: list[ScriptResult] = field(default_factory=list)
    uptime_seconds: Optional[int] = None
    distance_hops: Optional[int] = None


def _get_host_address(host_el: ET.Element) -> tuple[str, Optional[str], Optional[str]]:
    """Returns (ip_address, mac_address, mac_vendor)."""
    addrs = host_el.findall("address")
    if not addrs:
        return "unknown", None, None

    ip_addr = "unknown"
    mac_addr = None
    mac_vendor = None

    for a in addrs:
        addrtype = a.get("addrtype", "")
        if addrtype == "mac":
            mac_addr = a.get("addr")
            mac_vendor = a.get("vendor")
        elif addrtype in ("ipv4", "ipv6") and ip_addr == "unknown":
            ip_addr = a.get("addr", "unknown")

    if ip_addr == "unknown" and addrs:
        ip_addr = addrs[0].get("addr", "unknown")

    return ip_addr, mac_addr, mac_vendor


def _get_hostname(host_el: ET.Element) -> Optional[str]:
    hn = host_el.find("hostnames/hostname")
    if hn is not None:
        return hn.get("name")
    return None


def _parse_scripts(parent_el: ET.Element) -> list[ScriptResult]:
    """Parse <script> elements from a port or host element."""
    results: list[ScriptResult] = []
    for script_el in parent_el.findall("script"):
        script_id = script_el.get("id", "unknown")
        output = script_el.get("output", "")

        elements: dict[str, str] = {}
        for elem in script_el.findall(".//elem"):
            key = elem.get("key", "")
            if key and elem.text:
                elements[key] = elem.text

        # Also capture table/elem nesting for structured scripts
        for table in script_el.findall(".//table"):
            table_key = table.get("key", "")
            for elem in table.findall("elem"):
                key = elem.get("key", "")
                if key and elem.text:
                    full_key = f"{table_key}.{key}" if table_key else key
                    elements[full_key] = elem.text

        results.append(ScriptResult(script_id=script_id, output=output, elements=elements))

    return results


def _parse_cpe(parent_el: ET.Element) -> list[str]:
    """Extract CPE strings from service or OS elements."""
    cpes: list[str] = []
    for cpe_el in parent_el.findall("cpe"):
        if cpe_el.text:
            cpes.append(cpe_el.text)
    return cpes


def _parse_os(host_el: ET.Element) -> list[OSMatch]:
    """Parse OS detection results."""
    matches: list[OSMatch] = []
    os_el = host_el.find("os")
    if os_el is None:
        return matches

    for osmatch in os_el.findall("osmatch"):
        name = osmatch.get("name", "unknown")
        accuracy = int(osmatch.get("accuracy", "0"))

        os_family = None
        os_gen = None
        cpes: list[str] = []

        for osclass in osmatch.findall("osclass"):
            os_family = os_family or osclass.get("osfamily")
            os_gen = os_gen or osclass.get("osgen")
            cpes.extend(_parse_cpe(osclass))

        matches.append(OSMatch(
            name=name,
            accuracy=accuracy,
            os_family=os_family,
            os_gen=os_gen,
            cpe=cpes,
        ))

    return matches


def parse_nmap_xml(xml_path: str) -> list[Host]:
    """
    Parse Nmap XML output (-oX), including NSE script results, OS detection,
    and CPE data. This function does not scan anything; it only parses a file
    you provide from an authorized scan.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    hosts: list[Host] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        addr, mac_addr, mac_vendor = _get_host_address(host_el)
        hostname = _get_hostname(host_el)

        # Parse OS detection
        os_matches = _parse_os(host_el)

        # Parse host-level scripts
        hostscript_el = host_el.find("hostscript")
        host_scripts = _parse_scripts(hostscript_el) if hostscript_el is not None else []

        # Parse uptime
        uptime_seconds = None
        uptime_el = host_el.find("uptime")
        if uptime_el is not None:
            try:
                uptime_seconds = int(uptime_el.get("seconds", "0"))
            except ValueError:
                pass

        # Parse traceroute hop count
        distance_hops = None
        distance_el = host_el.find("distance")
        if distance_el is not None:
            try:
                distance_hops = int(distance_el.get("value", "0"))
            except ValueError:
                pass

        services: list[Service] = []
        for port_el in host_el.findall("ports/port"):
            proto = port_el.get("protocol", "tcp")
            portid = int(port_el.get("portid", "0"))

            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"

            # Parse port-level scripts
            port_scripts = _parse_scripts(port_el)

            svc_el = port_el.find("service")
            if svc_el is not None:
                svc_cpes = _parse_cpe(svc_el)
                services.append(
                    Service(
                        port=portid,
                        protocol=proto,
                        state=state,
                        name=svc_el.get("name"),
                        product=svc_el.get("product"),
                        version=svc_el.get("version"),
                        extrainfo=svc_el.get("extrainfo"),
                        tunnel=svc_el.get("tunnel"),
                        scripts=port_scripts,
                        cpe=svc_cpes,
                    )
                )
            else:
                services.append(Service(
                    port=portid, protocol=proto, state=state, scripts=port_scripts,
                ))

        hosts.append(Host(
            address=addr,
            hostname=hostname,
            status=status,
            services=services,
            mac_address=mac_addr,
            mac_vendor=mac_vendor,
            os_matches=os_matches,
            host_scripts=host_scripts,
            uptime_seconds=uptime_seconds,
            distance_hops=distance_hops,
        ))

    return hosts


def extract_cves_from_scripts(scripts: list[ScriptResult]) -> list[str]:
    """Extract CVE identifiers from NSE script output."""
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    cves: set[str] = set()
    for s in scripts:
        cves.update(cve_pattern.findall(s.output))
        for v in s.elements.values():
            cves.update(cve_pattern.findall(v))
    return sorted(cves)
