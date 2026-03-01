from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import xml.etree.ElementTree as ET


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


@dataclass(frozen=True)
class Host:
    address: str
    hostname: Optional[str]
    status: str
    services: list[Service]


def _get_host_address(host_el: ET.Element) -> str:
    # Prefer IPv4, then IPv6, then first address element
    addrs = host_el.findall("address")
    if not addrs:
        return "unknown"
    for t in ("ipv4", "ipv6"):
        for a in addrs:
            if a.get("addrtype") == t and a.get("addr"):
                return a.get("addr")  # type: ignore[return-value]
    return addrs[0].get("addr", "unknown")


def _get_hostname(host_el: ET.Element) -> Optional[str]:
    hn = host_el.find("hostnames/hostname")
    if hn is not None:
        return hn.get("name")
    return None


def parse_nmap_xml(xml_path: str) -> list[Host]:
    """
    Parse Nmap XML output (-oX).
    This function does not scan anything; it only parses a file you provide.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    hosts: list[Host] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        addr = _get_host_address(host_el)
        hostname = _get_hostname(host_el)

        services: list[Service] = []
        for port_el in host_el.findall("ports/port"):
            proto = port_el.get("protocol", "tcp")
            portid = int(port_el.get("portid", "0"))

            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"

            svc_el = port_el.find("service")
            if svc_el is not None:
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
                    )
                )
            else:
                services.append(Service(port=portid, protocol=proto, state=state))

        hosts.append(Host(address=addr, hostname=hostname, status=status, services=services))

    return hosts
