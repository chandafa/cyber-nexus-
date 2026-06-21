# NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
# Part of the Nexus security platform. Proprietary and confidential.
# Unauthorized copying, modification, or distribution is prohibited.
# This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
# Contact: ck271138@gmail.com

# nexus_manager/__main__.py
"""
nexus-manager — entrypoint standalone.

    python -m nexus_manager run    [--host 0.0.0.0] [--port 8765]
    python -m nexus_manager info             # tampilkan enrollment key & admin token
    python -m nexus_manager status [--host --port]

Env:
    NEXUS_FLEET_DB   path file SQLite (default ./fleet_manager.db)
    NEXUS_FLEET_HOME folder data bila NEXUS_FLEET_DB tak diset
"""
import argparse
import json
import os
import sys

# Pastikan paket fleet (nexus_common, dst.) ada di sys.path saat dijalankan langsung.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus_manager import server  # noqa: E402
from nexus_common import protocol as fc  # noqa: E402
from nexus_common import __version__  # noqa: E402


def _gen_self_signed(cert, key, cn):
    """Buat sertifikat self-signed. Coba `cryptography` dulu, lalu openssl.
    Kembalikan None bila sukses, atau pesan error."""
    # 1) cryptography (paling portabel bila terpasang)
    try:
        import datetime
        import ipaddress as _ip
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        sans = [x509.IPAddress(_ip.ip_address("127.0.0.1"))]
        try:
            sans.append(x509.IPAddress(_ip.ip_address(cn)))
        except ValueError:
            sans.append(x509.DNSName(cn))
        now = datetime.datetime.now(datetime.timezone.utc)
        crt = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(k.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=825))
               .add_extension(x509.SubjectAlternativeName(sans), critical=False)
               .sign(k, hashes.SHA256()))
        with open(key, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
        with open(cert, "wb") as f:
            f.write(crt.public_bytes(serialization.Encoding.PEM))
        return None
    except ImportError:
        pass
    except Exception as e:
        return str(e)
    # 2) openssl (cari di PATH + lokasi Git umum)
    import shutil
    import subprocess
    openssl = shutil.which("openssl")
    if not openssl and os.name == "nt":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramW6432", ""), r"C:\Program Files", r"D:\program"):
            for sub in (r"Git\usr\bin\openssl.exe", r"Git\mingw64\bin\openssl.exe"):
                p = os.path.join(base, sub) if base else ""
                if p and os.path.isfile(p):
                    openssl = p
                    break
            if openssl:
                break
    if not openssl:
        return "openssl/cryptography tidak ditemukan"
    try:
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                        "-out", cert, "-sha256", "-days", "825", "-nodes",
                        "-subj", f"/CN={cn}", "-addext",
                        f"subjectAltName=DNS:{cn},IP:127.0.0.1"],
                       check=True, capture_output=True)
        return None
    except Exception as e:
        return str(e)


def main(argv=None):
    p = argparse.ArgumentParser(prog="nexus-manager",
                                description="Server pusat Nexus Fleet (penerima event & policy).")
    p.add_argument("-V", "--version", action="version", version=f"nexus-manager {__version__}")
    sub = p.add_subparsers(dest="action", required=True)
    r = sub.add_parser("run", help="jalankan server (blocking)")
    r.add_argument("--host", default="0.0.0.0")
    r.add_argument("--port", default=str(fc.DEFAULT_MANAGER_PORT))
    r.add_argument("--cert", default="", help="path sertifikat TLS (aktifkan HTTPS)")
    r.add_argument("--key", default="", help="path private key TLS")
    gc = sub.add_parser("gencert", help="buat sertifikat self-signed (butuh openssl)")
    gc.add_argument("--out", default="nexus", help="prefix output (-> <out>_cert.pem/_key.pem)")
    gc.add_argument("--cn", default="nexus-manager", help="Common Name / hostname")
    sub.add_parser("info", help="tampilkan enrollment key & admin token")
    vi = sub.add_parser("vuln-import", help="impor basis data CVE (offline) dari file JSON")
    vi.add_argument("--file", required=True)
    s = sub.add_parser("status", help="cek apakah manager hidup")
    s.add_argument("--host", default=fc.DEFAULT_MANAGER_HOST)
    s.add_argument("--port", default=str(fc.DEFAULT_MANAGER_PORT))
    args = p.parse_args(argv)

    if args.action == "gencert":
        cert, key = f"{args.out}_cert.pem", f"{args.out}_key.pem"
        err = _gen_self_signed(cert, key, args.cn)
        if err:
            print(f"[error] gagal buat cert: {err}\n"
                  "Pasang `pip install cryptography` ATAU openssl, lalu coba lagi.",
                  file=sys.stderr)
            return 1
        print(json.dumps({"cert": cert, "key": key,
                          "run": f"nexus-manager run --cert {cert} --key {key}"}, indent=2))
        return 0

    if args.action == "run":
        if args.cert and args.key:
            os.environ["NEXUS_TLS_CERT"] = args.cert
            os.environ["NEXUS_TLS_KEY"] = args.key
        res = server.serve_blocking(args.host, args.port)
        return 0 if res.get("status") != "error" else 1
    if args.action == "vuln-import":
        try:
            with open(args.file, encoding="utf-8") as f:
                data = f.read()
        except Exception as e:
            print(f"[error] gagal baca file: {e}", file=sys.stderr)
            return 1
        print(json.dumps(server.set_vulndb(data), indent=2))
        return 0

    if args.action == "info":
        print(json.dumps({"enroll_key": server.get_enroll_key(),
                          "admin_token": server.get_admin_token(),
                          "db": fc.manager_db_path()}, indent=2))
        return 0
    if args.action == "status":
        print(json.dumps(server.manager_status(args.host, args.port), indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
