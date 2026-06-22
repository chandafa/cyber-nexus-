#!/usr/bin/env python3
# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

"""
Uji parsers/ — nmap (XML), nikto (JSON), hydra (teks), tshark (field '|').

Logika murni: memberi tiap parser potongan output tool yang representatif lalu
memverifikasi struktur hasil (ports/findings/creds/packets). Tanpa jaringan,
tanpa tool eksternal, tanpa DB.
"""
import os
import sys

# Windows: paksa stdout UTF-8 agar karakter non-ASCII (panah, dsb.) tak crash cp1252.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PYDIR = os.path.dirname(HERE)
sys.path.insert(0, PYDIR)

from parsers import nmap_parser, nikto_parser, hydra_parser, tshark_parser  # noqa: E402

FAILED = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILED.append(name)


# --------------------------------------------------------------------- nmap
NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="web.local" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.15" accuracy="95"/></os>
  </host>
</nmaprun>"""


def test_nmap():
    print("== nmap XML ==")
    r = nmap_parser.parse_nmap_xml(NMAP_XML)
    check("nmap host ip terurai", r["host"]["ip"] == "192.168.1.10")
    check("nmap hostname terurai", r["host"]["hostname"] == "web.local")
    check("nmap os match terurai", r["host"]["os"] == "Linux 5.15")
    check("nmap hanya port OPEN (closed dilewati)", len(r["ports"]) == 2)
    p22 = next((p for p in r["ports"] if p["port"] == 22), None)
    check("nmap port 22 = ssh OpenSSH 8.9p1",
          p22 and p22["service"] == "ssh" and p22["product"] == "OpenSSH"
          and p22["version"] == "8.9p1" and p22["protocol"] == "tcp")
    check("nmap port adalah int", p22 and isinstance(p22["port"], int))
    # XML rusak → struktur kosong aman (tak crash).
    bad = nmap_parser.parse_nmap_xml("<not valid xml")
    check("nmap XML rusak → host None & ports kosong",
          bad["host"] is None and bad["ports"] == [])
    # host tak ada → kosong.
    empty = nmap_parser.parse_nmap_xml("<nmaprun></nmaprun>")
    check("nmap tanpa host → kosong", empty["host"] is None and empty["ports"] == [])


# --------------------------------------------------------------------- nikto
NIKTO_JSON = """{
  "host": "10.0.0.5",
  "vulnerabilities": [
    {"id": "999001", "msg": "X-Frame-Options header tidak diset", "url": "/", "method": "GET"},
    {"id": "999002", "msg": "/admin/ ditemukan", "url": "/admin/", "method": "GET"}
  ]
}"""


def test_nikto():
    print("== nikto JSON ==")
    out = nikto_parser.parse_nikto_json(NIKTO_JSON)
    check("nikto 2 temuan terurai", len(out) == 2)
    check("nikto temuan punya tool=nikto", all(v["tool"] == "nikto" for v in out))
    check("nikto vuln_id & title benar",
          out[0]["vuln_id"] == "999001" and "X-Frame" in out[0]["title"])
    check("nikto url & method benar",
          out[1]["url"] == "/admin/" and out[1]["method"] == "GET")
    check("nikto severity ternormalisasi (medium)", out[0]["severity"] == "medium")
    # JSON rusak / non-dict → list kosong aman.
    check("nikto JSON rusak → []", nikto_parser.parse_nikto_json("{bad") == [])
    check("nikto tanpa kunci vulnerabilities → []",
          nikto_parser.parse_nikto_json('{"host":"x"}') == [])


# --------------------------------------------------------------------- hydra
HYDRA_OUTPUT = """\
Hydra v9.4 (c) 2022 by van Hauser/THC
[DATA] attacking ssh://192.168.1.10:22/
[22][ssh] host: 192.168.1.10   login: admin   password: P@ssw0rd
[22][ssh] host: 192.168.1.10   login: root   password: toor
1 of 1 target successfully completed, 2 valid passwords found
"""


def test_hydra():
    print("== hydra teks ==")
    creds = hydra_parser.parse_hydra_output(HYDRA_OUTPUT)
    check("hydra 2 kredensial terurai", len(creds) == 2)
    check("hydra kredensial pertama benar",
          creds[0] == {"host": "192.168.1.10", "login": "admin", "password": "P@ssw0rd"})
    check("hydra kredensial kedua benar",
          creds[1]["login"] == "root" and creds[1]["password"] == "toor")
    # tanpa baris kredensial → kosong.
    check("hydra output tanpa cred → []",
          hydra_parser.parse_hydra_output("[DATA] no creds here\n1 of 1") == [])


# --------------------------------------------------------------------- tshark
def test_tshark():
    print("== tshark field '|' ==")
    line = "5|0.123|10.0.0.1|10.0.0.2|6|TCP|74|51000|443"
    pkt = tshark_parser.parse_tshark_line(line)
    check("tshark frame_number benar", pkt.get("frame_number") == "5")
    check("tshark ip_src/ip_dst benar",
          pkt.get("ip_src") == "10.0.0.1" and pkt.get("ip_dst") == "10.0.0.2")
    check("tshark protocol benar", pkt.get("protocol") == "TCP")
    check("tshark frame_len jadi int", pkt.get("frame_len") == 74 and isinstance(pkt["frame_len"], int))
    check("tshark tcp ports benar",
          pkt.get("tcp_srcport") == "51000" and pkt.get("tcp_dstport") == "443")
    # baris header (kolom non-numerik di frame_number) → {}.
    header = "frame_number|time|src|dst|proto|protocol|len|sport|dport"
    check("tshark header diabaikan → {}", tshark_parser.parse_tshark_line(header) == {})
    # baris terlalu pendek → {}.
    check("tshark baris pendek → {}", tshark_parser.parse_tshark_line("1|2|3") == {})
    # frame_len non-int → fallback 0.
    bad_len = "9|0.1|a|b|6|TCP|xx|1|2"
    check("tshark frame_len invalid → 0", tshark_parser.parse_tshark_line(bad_len)["frame_len"] == 0)


def main():
    test_nmap()
    test_nikto()
    test_hydra()
    test_tshark()
    print()
    if FAILED:
        print(f"GAGAL ({len(FAILED)}): " + ", ".join(FAILED))
        return 1
    print("SEMUA TES PARSERS LULUS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
