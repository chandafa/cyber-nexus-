# nexus/python/parsers/nmap_parser.py
"""Parser XML output Nmap menjadi struktur dict yang rapi."""
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_string: str) -> dict:
    """Parse string XML nmap -> {host, ports[]}."""
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return {'host': None, 'ports': []}
    host = root.find('host')
    if host is None:
        return {'host': None, 'ports': []}

    addr = host.find("address[@addrtype='ipv4']")
    ip = addr.get('addr') if addr is not None else ''
    hn = host.find('.//hostname')
    hostname = hn.get('name') if hn is not None else ''
    os_el = host.find('.//osmatch')
    os_guess = os_el.get('name') if os_el is not None else 'Unknown'

    ports = []
    for port_el in host.findall('.//port'):
        st = port_el.find('state')
        if st is None or st.get('state') != 'open':
            continue
        svc = port_el.find('service')
        ports.append({
            'port': int(port_el.get('portid')),
            'protocol': port_el.get('protocol', 'tcp'),
            'service': svc.get('name', '') if svc is not None else '',
            'product': svc.get('product', '') if svc is not None else '',
            'version': svc.get('version', '') if svc is not None else '',
        })
    return {'host': {'ip': ip, 'hostname': hostname, 'os': os_guess}, 'ports': ports}
