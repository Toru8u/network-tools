#!/usr/bin/env python3
"""
Ein Python-Skript für macOS, das automatisch:
1. Die Standard-Netzwerk-Schnittstelle ermittelt
2. IP-Adresse und Subnetzmaske abruft
3. ARP-Scan mit arp-scan durchführt (Duplikate entfernt)
4. Nmap-Scan auf gefundene Hosts ausführt (OS-Erkennung + offene Ports) und XML-Ausgabe in Datei speichert
5. Ergebnisse in CSV-Datei (`netzwerk_uebersicht.csv`) exportiert

Voraussetzungen:
- arp-scan (`brew install arp-scan`)
- nmap (`brew install nmap`)
- Python-Module: netifaces
"""
import subprocess
import netifaces
import ipaddress
import xml.etree.ElementTree as ET
import csv
import sys
import os


def get_default_interface():
    gateways = netifaces.gateways()
    default = gateways.get('default', {})
    iface = default.get(netifaces.AF_INET)
    if iface and len(iface) >= 2:
        return iface[1]
    raise RuntimeError("Keine Standard-IPv4-Schnittstelle gefunden.")


def get_ip_and_netmask(iface):
    addrs = netifaces.ifaddresses(iface)
    if netifaces.AF_INET not in addrs:
        raise RuntimeError(f"Schnittstelle {iface} hat keine IPv4-Adresse.")
    info = addrs[netifaces.AF_INET][0]
    return info['addr'], info['netmask']


def arp_scan(iface, network):
    print(f"Starte ARP-Scan auf {network} via {iface}...")
    cmd = ['sudo', 'arp-scan', '--interface='+iface, '--localnet']
    result = subprocess.run(cmd, capture_output=True, text=True)
    hosts = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            try:
                if ipaddress.IPv4Address(ip) in network:
                    hosts[ip] = parts[1]
            except ipaddress.AddressValueError:
                continue
    return [{'ip': ip, 'mac': mac} for ip, mac in hosts.items()]


def nmap_scan(hosts, xml_file='nmap_results.xml'):
    ips = sorted({h['ip'] for h in hosts})
    print(f"Starte Nmap-Scan auf {len(ips)} Hosts... (Ausgabe: {xml_file})")
    # Ausgabe direkt in Datei
    nm_cmd = ['nmap', '-O', '-sV', '-oX', xml_file] + ips
    result = subprocess.run(nm_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Warnung: Nmap lieferte Fehlerstatus {result.returncode}.")
        print("Fehlerausgabe:\n", result.stderr)
    if not os.path.exists(xml_file):
        raise RuntimeError(f"XML-Datei {xml_file} nicht gefunden.")
    with open(xml_file, 'r') as f:
        return f.read()


def parse_nmap_xml(xml_data):
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        print(f"Fehler beim Parsen der XML: {e}")
        return {}
    info = {}
    for host in root.findall('host'):
        addr4 = host.find("address[@addrtype='ipv4']")
        if addr4 is None: continue
        ip = addr4.get('addr')
        mac_elem = host.find("address[@addrtype='mac']")
        mac = mac_elem.get('addr') if mac_elem is not None else ''
        os_elem = host.find('os/osmatch')
        os_name = os_elem.get('name') if os_elem is not None else 'unbekannt'
        ports = []
        for p in host.findall('ports/port'):
            state = p.find('state')
            if state is not None and state.get('state') == 'open':
                svc = p.find('service')
                name = svc.get('name', '') if svc is not None else ''
                portid = p.get('portid', '')
                ports.append(f"{name}/{portid}" if name else portid)
        info[ip] = {'mac_nmap': mac, 'os': os_name, 'ports': ports}
    return info


def merge_results(arp_hosts, nmap_info):
    merged = []
    for h in arp_hosts:
        ip = h['ip']
        mac = h.get('mac', '')
        entry = {'IP': ip, 'MAC': mac, 'Gerätetyp/OS': '', 'Offene Ports': ''}
        ni = nmap_info.get(ip)
        if ni:
            entry['Gerätetyp/OS'] = ni['os']
            entry['Offene Ports'] = "; ".join(ni['ports'])
            if not mac and ni['mac_nmap']:
                entry['MAC'] = ni['mac_nmap']
        merged.append(entry)
    return merged


def write_csv(entries, filename='netzwerk_uebersicht.csv'):
    print(f"Schreibe Ergebnisse in {filename}...")
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['IP','MAC','Gerätetyp/OS','Offene Ports'])
        writer.writeheader()
        writer.writerows(entries)


def main():
    try:
        iface = get_default_interface()
        ip, mask = get_ip_and_netmask(iface)
    except Exception as e:
        print(f"Fehler: {e}")
        sys.exit(1)

    network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    arp_hosts = arp_scan(iface, network)
    if not arp_hosts:
        print("Keine Hosts gefunden. Ende.")
        sys.exit(0)

    xml = nmap_scan(arp_hosts)
    nmap_info = parse_nmap_xml(xml)
    merged = merge_results(arp_hosts, nmap_info)
    write_csv(merged)
    print("Fertig. Datei 'netzwerk_uebersicht.csv' erstellt.")

if __name__ == '__main__':
    main()

