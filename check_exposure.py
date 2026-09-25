#!/usr/bin/env python3
"""
check_exposure.py - Check what your router has exposed to the internet via
UPnP automatic port mapping.

How it works: sends an SSDP discovery multicast on the LAN to find your
router's UPnP Internet Gateway Device service, then asks it (via SOAP) to
list its current port-mapping table. This only talks to your own router --
no data leaves your network and no router login is required.

Limitation: UPnP mappings are only the DYNAMIC ones apps/devices register
automatically. Manually configured "Port Forwarding" rules in the router's
admin UI are invisible to this and must be checked by hand.
"""

import re
import socket
import sys
import urllib.error
import urllib.request

SSDP_ADDR = ("239.255.255.250", 1900)
SEARCH_TARGETS = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "upnp:rootdevice",
]

HIGH_RISK_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 137: "NetBIOS", 139: "NetBIOS",
    445: "SMB", 990: "FTPS", 3389: "RDP", 5900: "VNC",
}


def ssdp_discover(timeout=4):
    locations = set()
    for st in SEARCH_TARGETS:
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            f"ST: {st}\r\n\r\n"
        ).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        try:
            sock.sendto(msg, SSDP_ADDR)
            while True:
                data, _ = sock.recvfrom(65507)
                text = data.decode(errors="ignore")
                m = re.search(r"LOCATION:\s*(.+)", text, re.IGNORECASE)
                if m:
                    locations.add(m.group(1).strip())
        except socket.timeout:
            pass
        finally:
            sock.close()
    return locations


def get_control_url(location):
    with urllib.request.urlopen(location, timeout=5) as resp:
        xml_text = resp.read().decode(errors="ignore")
    base = "/".join(location.split("/")[:3])
    blocks = re.findall(r"<service>(.*?)</service>", xml_text, re.DOTALL)
    for block in blocks:
        for service_type in ("WANIPConnection", "WANPPPConnection"):
            if service_type in block:
                m = re.search(r"<controlURL>([^<]*)</controlURL>", block)
                if m:
                    control_path = m.group(1)
                    control_url = control_path if control_path.startswith("http") else base + control_path
                    return control_url, service_type
    return None, None


def soap_request(control_url, service_type, action, arguments=""):
    soap_body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="urn:schemas-upnp-org:service:{service_type}:1">'
        f"{arguments}"
        f"</u:{action}>"
        "</s:Body></s:Envelope>"
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"urn:schemas-upnp-org:service:{service_type}:1#{action}"',
    }
    req = urllib.request.Request(control_url, data=soap_body.encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode(errors="ignore")


def list_port_mappings(control_url, service_type):
    mappings = []
    index = 0
    while index < 200:
        args = f"<NewPortMappingIndex>{index}</NewPortMappingIndex>"
        try:
            resp_xml = soap_request(control_url, service_type, "GetGenericPortMappingEntry", args)
        except urllib.error.HTTPError:
            break  # router returns a SOAP fault once the index is out of range
        except urllib.error.URLError:
            break

        ext_port = re.search(r"<NewExternalPort>(\d+)</NewExternalPort>", resp_xml)
        if not ext_port:
            break
        protocol = re.search(r"<NewProtocol>(\w+)</NewProtocol>", resp_xml)
        int_client = re.search(r"<NewInternalClient>([^<]*)</NewInternalClient>", resp_xml)
        int_port = re.search(r"<NewInternalPort>(\d+)</NewInternalPort>", resp_xml)
        desc = re.search(r"<NewPortMappingDescription>([^<]*)</NewPortMappingDescription>", resp_xml)
        enabled = re.search(r"<NewEnabled>([\w]+)</NewEnabled>", resp_xml)

        mappings.append({
            "external_port": ext_port.group(1),
            "protocol": protocol.group(1) if protocol else "?",
            "internal_ip": int_client.group(1) if int_client else "?",
            "internal_port": int_port.group(1) if int_port else "?",
            "description": (desc.group(1) if desc else "").strip(),
            "enabled": enabled.group(1) if enabled else "?",
        })
        index += 1
    return mappings


def main():
    print("Discovering UPnP Internet Gateway Devices on your LAN...")
    locations = ssdp_discover()

    if not locations:
        print(
            "\nNo UPnP gateway responded.\n"
            "This usually means UPnP is disabled on your router (good for security),\n"
            "or it doesn't support UPnP discovery. This does NOT rule out manually\n"
            "configured port-forwarding rules -- check your router's Port Forwarding\n"
            "page by hand to be sure."
        )
        return

    all_mappings = []
    seen = set()
    for location in locations:
        control_url, service_type = get_control_url(location)
        if not control_url:
            continue
        for m in list_port_mappings(control_url, service_type):
            key = (m["external_port"], m["protocol"], m["internal_ip"], m["internal_port"])
            if key in seen:
                continue
            seen.add(key)
            all_mappings.append(m)

    if not all_mappings:
        print(
            "\nUPnP gateway found, but it has NO active port mappings.\n"
            "Nothing appears to be auto-forwarded to the internet right now.\n"
            "Still worth a manual glance at the router's Port Forwarding page for\n"
            "static rules, since those don't show up here."
        )
        return

    print(f"\nFound {len(all_mappings)} UPnP port mapping(s):\n")
    print(f"{'EXT PORT':<10}{'PROTO':<7}{'INTERNAL':<22}{'ENABLED':<9}DESCRIPTION")
    print("-" * 80)
    flagged = []
    for m in all_mappings:
        internal = f"{m['internal_ip']}:{m['internal_port']}"
        print(f"{m['external_port']:<10}{m['protocol']:<7}{internal:<22}{m['enabled']:<9}{m['description']}")
        risk_name = HIGH_RISK_PORTS.get(int(m["internal_port"]) if m["internal_port"].isdigit() else -1)
        if risk_name:
            flagged.append((m, risk_name))

    if flagged:
        print("\n*** HIGH-RISK EXPOSURE ***")
        for m, risk_name in flagged:
            print(
                f"  - {risk_name} on {m['internal_ip']}:{m['internal_port']} is reachable from the "
                f"internet via external port {m['external_port']}/{m['protocol']}"
            )
    else:
        print("\nNone of the mapped ports match common high-risk services (SSH/RDP/SMB/FTP/Telnet/VNC).")

    print(
        "\nReminder: this list is UPnP's dynamic mappings only. Also check your\n"
        "router's Port Forwarding admin page for manually configured rules."
    )


if __name__ == "__main__":
    main()
