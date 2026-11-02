#!/usr/bin/env python3
"""
ollama_pull_retry.py - laedt Ollama-Modelle und startet den Download bei
Abbruechen/Haengern automatisch neu, bis er fertig ist.

Warum das funktioniert: Ollama speichert angefangene Layer als Teil-Blobs und
setzt beim naechsten "pull" an der Stelle fort. Ein Neustart kostet also kaum
Fortschritt - ein haengender Download wird so einfach "angestossen".

Nutzt die Ollama-HTTP-API (/api/pull) statt der CLI. Dadurch kann der
Fortschritt (Bytes) ueberwacht und ein Stillstand erkannt werden.
Nur Python-Standardbibliothek, laeuft unter Windows/Linux/macOS.

Beispiele:
  python ollama_pull_retry.py llama3.1:8b qwen2.5-coder:14b
  python ollama_pull_retry.py -f modelle.txt --stall-timeout 45
  python ollama_pull_retry.py --host 192.168.1.20:11434 gemma3:27b
  python ollama_pull_retry.py --diagnose
  python ollama_pull_retry.py --proxy http://127.0.0.1:8080 llama3.1:8b
  python ollama_pull_retry.py --direct gemma3:27b         # Blobs selbst laden, dann registrieren
  python ollama_pull_retry.py --gentle llama3.1:8b        # client2 + MAXSTREAMS=1
  python ollama_pull_retry.py --server-env OLLAMA_DOWNLOAD_PARTS=4 llama3.1:8b
"""

import argparse
import atexit
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

FATAL_HINTS = (
    "file does not exist",
    "not found",
    "invalid model name",
    "invalid model",
    "unauthorized",
    "pull model manifest: 404",
    "does not exist",
)


CERT_ERRORS = []
TLS_CTX = None  # gesetzt durch configure_tls()


PROBE_URL = "https://registry.ollama.ai/v2/"
SYSTEM_CA_FILES = (
    "/etc/ssl/certs/ca-certificates.crt",                 # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",                   # RHEL/Fedora
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL/Fedora
    "/etc/ssl/ca-bundle.pem",                             # openSUSE
    "/etc/ssl/cert.pem",                                  # Alpine/macOS/BSD
    "/opt/homebrew/etc/ca-certificates/cert.pem",         # Homebrew (Apple Silicon)
    "/usr/local/etc/openssl/cert.pem",                    # Homebrew (Intel)
)


def _tls_check(ctx, url: str) -> str:
    """'ok' (Verbindung + Zertifikat in Ordnung), 'cert' (Zertifikatsfehler) oder 'net' (sonstiger Fehler)."""
    opener = (urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
              if ctx else urllib.request.build_opener())
    try:
        opener.open(urllib.request.Request(url), timeout=15).close()
        return "ok"
    except urllib.error.HTTPError:
        return "ok"  # Server antwortet -> TLS hat funktioniert
    except Exception as e:
        return "cert" if is_cert_error(e) else "net"


def _ctx_from_file(path: str):
    try:
        return ssl.create_default_context(cafile=path)
    except (OSError, ssl.SSLError):
        return None


def _ctx_macos_keychain():
    """Zertifikate aus den macOS-Schluesselbunden exportieren (wie sie auch Browser/Go nutzen)."""
    if sys.platform != "darwin" or not shutil.which("security"):
        return None
    keychains = ["/System/Library/Keychains/SystemRootCertificates.keychain",
                 "/Library/Keychains/System.keychain",
                 os.path.expanduser("~/Library/Keychains/login.keychain-db")]
    pem = ""
    for kc in keychains:
        if os.path.exists(kc):
            try:
                pem += subprocess.run(["security", "find-certificate", "-a", "-p", kc],
                                      capture_output=True, text=True, timeout=30).stdout
            except Exception:
                pass
    if "BEGIN CERTIFICATE" not in pem:
        return None
    tmp = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    tmp.write(pem)
    tmp.close()
    atexit.register(lambda: os.path.exists(tmp.name) and os.remove(tmp.name))
    return _ctx_from_file(tmp.name)


def _ctx_windows_store():
    if not hasattr(ssl, "enum_certificates"):
        return None
    ctx = ssl.create_default_context()
    for store in ("ROOT", "CA"):
        try:
            for cert, enc, _trust in ssl.enum_certificates(store):
                if enc == "x509_asn":
                    try:
                        ctx.load_verify_locations(cadata=cert)
                    except ssl.SSLError:
                        pass
        except OSError:
            pass
    return ctx


def configure_tls(ca_bundle=None, insecure=False, strict=False, probe_url=PROBE_URL) -> bool:
    """TLS-Vertrauen einrichten, ohne dass der Nutzer etwas vorbereiten muss.

    Reihenfolge: eigenes CA-Bundle -> Python-Standard (+ truststore, falls installiert) -> System-CA-Dateien
    -> macOS-Schluesselbund -> Windows-Zertifikatsspeicher -> (nur ohne --strict) ungeprueft mit Warnung.
    Gibt False zurueck, wenn keine funktionierende Variante gefunden wurde.
    """
    global TLS_CTX

    def use(ctx, label):
        global TLS_CTX
        TLS_CTX = ctx
        if ctx:
            urllib.request.install_opener(
                urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)))
        print(f"TLS: {label}")
        return True

    def unverified():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    if insecure:
        print("WARNUNG: --insecure - TLS-Zertifikate werden NICHT geprueft. Integritaet sichern nur die "
              "SHA256-Pruefung der Blobs und der anschliessende 'ollama pull' (Manifest ueber Ollamas eigene "
              "TLS-Verbindung).")
        return use(unverified(), "ungeprueft (--insecure)")

    if ca_bundle:
        ctx = _ctx_from_file(ca_bundle)
        if not ctx:
            print(f"FEHLER: CA-Bundle nicht lesbar: {ca_bundle}")
            return False
        return use(ctx, f"CA-Bundle {ca_bundle}")

    try:  # optional: pip install truststore (Python 3.10+) -> OS-Zertifikatsspeicher
        import truststore
        truststore.inject_into_ssl()
    except Exception:
        pass

    candidates = [("Python-Standard", lambda: None)]
    for f in SYSTEM_CA_FILES:
        if os.path.isfile(f):
            candidates.append((f"System-CA-Datei {f}", lambda f=f: _ctx_from_file(f)))
    candidates.append(("macOS-Schluesselbund", _ctx_macos_keychain))
    candidates.append(("Windows-Zertifikatsspeicher", _ctx_windows_store))

    saw_cert_error = False
    for label, make in candidates:
        ctx = make()
        if ctx is None and label != "Python-Standard":
            continue
        result = _tls_check(ctx, probe_url)
        if result == "ok":
            return use(ctx, label)
        if result == "net":
            # Kein Zertifikatsproblem (offline, Firewall ...): hier hilft kein anderes Vertrauen.
            if not saw_cert_error:
                return True
            break
        saw_cert_error = True

    if strict:
        print("TLS: kein vertrauenswuerdiges Zertifikat gefunden (--strict, kein Fallback).")
        return False
    print("WARNUNG: Zertifikat der Registry wird auf diesem System von keinem Zertifikatsspeicher akzeptiert "
          "(vermutlich TLS-Inspektion). Fahre OHNE Zertifikatspruefung fort. Integritaet sichern die "
          "SHA256-Pruefung der Blobs und der anschliessende 'ollama pull'. Mit --strict abschalten, "
          "oder --ca-bundle bzw. 'pip install truststore' nutzen.")
    return use(unverified(), "ungeprueft (automatischer Fallback)")


def is_cert_error(e: BaseException) -> bool:
    reason = getattr(e, "reason", None)
    return (isinstance(e, ssl.SSLCertVerificationError)
            or isinstance(reason, ssl.SSLCertVerificationError)
            or "CERTIFICATE_VERIFY_FAILED" in str(e)
            or "local issuer certificate" in str(e))


def cert_hint() -> None:
    print(
        "\nTLS-Zertifikatsfehler ('unable to get local issuer certificate'). Kein Retry sinnvoll. Typische Ursachen:\n"
        "  1. Firmen-/Proxy-Inspektion mit eigener CA: CA als PEM exportieren und\n"
        "     '--ca-bundle firmen-ca.pem' (oder SSL_CERT_FILE) setzen - oder 'pip install truststore'\n"
        "     (nutzt dann den System-Zertifikatsspeicher von Windows/macOS/Linux).\n"
        "  2. macOS mit python.org-Python: '/Applications/Python 3.x/Install Certificates.command' ausfuehren.\n"
        "  3. Linux: Paket 'ca-certificates' installieren/aktualisieren.\n"
        "  4. Ohne --strict faellt das Skript im Direkt-/Diagnosemodus selbst auf ungeprueft zurueck.\n"
        "Hinweis: Betrifft der Fehler 'ollama pull' selbst (Go: 'x509: certificate signed by unknown\n"
        "authority'), braucht der Ollama-SERVER die CA: --server-env SSL_CERT_FILE=/pfad/ca.pem (eigener Server)\n"
        "bzw. die CA im System-Speicher des Servers.")


class Stalled(Exception):
    pass


class FatalPullError(Exception):
    pass


def norm_host(h: str) -> str:
    h = (h or "127.0.0.1:11434").strip()
    if "://" not in h:
        h = "http://" + h
    scheme, rest = h.split("://", 1)
    rest = rest.rstrip("/")
    if rest.startswith("0.0.0.0"):
        rest = rest.replace("0.0.0.0", "127.0.0.1", 1)
    if ":" not in rest:
        rest += ":11434"
    return f"{scheme}://{rest}"


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"

REGISTRY = "registry.ollama.ai"
# Blob-CDN (Cloudflare R2), aus dem Issue #8484 bekannt; wird von manchen ISPs gestoert.
CDN_HOST = "dd20bb891979d25aebc8bec07b2b3bbc.r2.cloudflarestorage.com"
DOH_SERVERS = {
    "Cloudflare-DoH": "https://cloudflare-dns.com/dns-query",
    "Google-DoH": "https://dns.google/resolve",
}


def doh_lookup(url: str, name: str):
    req = urllib.request.Request(
        f"{url}?name={name}&type=A", headers={"accept": "application/dns-json"}
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        data = json.load(r)
    return [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]


def probe_ip(ip: str, hostname: str, timeout: int = 8):
    """TCP+TLS+HTTP-Test gegen eine IP (SNI/Host = hostname)."""
    t0 = time.time()
    ctx = TLS_CTX or ssl.create_default_context()
    with socket.create_connection((ip, 443), timeout=timeout) as s:
        t_conn = time.time() - t0
        with ctx.wrap_socket(s, server_hostname=hostname) as ss:
            ss.sendall(
                f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode()
            )
            first = ss.recv(64).split(b"\r\n")[0].decode(errors="replace")
    return t_conn, time.time() - t0, first


def diagnose_host(hostname: str) -> bool:
    print(f"--- {hostname} ---")
    sources = {}  # ip -> [quellen]
    try:
        infos = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
        for ip in sorted({i[4][0] for i in infos}):
            sources.setdefault(ip, []).append("System-DNS")
    except OSError as e:
        print(f"System-DNS: FEHLER ({e})")
    for name, url in DOH_SERVERS.items():
        try:
            for ip in doh_lookup(url, hostname):
                sources.setdefault(ip, []).append(name)
        except Exception as e:
            print(f"{name}: FEHLER ({e})")

    if not sources:
        print("Keine IPs ermittelt - Netzwerk/DNS gestoert?\n")
        return False

    results = []
    print(f"{'IP':<18}{'Quelle':<34}{'TCP':>8}{'Gesamt':>9}  Antwort")
    for ip, src in sources.items():
        try:
            tc, tt, first = probe_ip(ip, hostname)
            results.append((tt, ip))
            print(f"{ip:<18}{', '.join(src):<34}{tc*1000:>6.0f}ms{tt*1000:>7.0f}ms  {first}")
        except Exception as e:
            print(f"{ip:<18}{', '.join(src):<34}{'-':>8}{'-':>9}  FEHLER: {e}")
            if is_cert_error(e):
                CERT_ERRORS.append(hostname)

    if not results:
        print("Keine IP erreichbar. Pruefe Firewall/Proxy/VPN (ISP-Sperre moeglich).\n")
        return False
    best = min(results)[1]
    sys_ips = [ip for ip, s in sources.items() if "System-DNS" in s]
    print(f"Schnellste IP: {best}")
    if best not in sys_ips:
        print("System-DNS liefert diese IP NICHT. Moeglicher Workaround - hosts-Eintrag")
        print("(Linux/macOS: /etc/hosts, Windows: C:\\Windows\\System32\\drivers\\etc\\hosts):")
        print(f"  {best} {hostname}")
    else:
        print("System-DNS liefert bereits die schnellste IP.")
    print()
    return True


def diagnose() -> int:
    """Testet Registry und Blob-CDN: System-DNS vs. DNS-over-HTTPS, TCP/TLS-Zeiten."""
    ok_reg = diagnose_host(REGISTRY)
    ok_cdn = diagnose_host(CDN_HOST)
    print(
        "Hinweis: Ollama laedt die grossen Blobs vom CDN-Host (Weiterleitung der Registry). "
        "Die Host-Adresse kann sich aendern; der Eintrag stammt aus Issue #8484."
    )
    print(
        "Zusatztest (wie von rick-github vorgeschlagen), Geschwindigkeit pruefen:\n"
        "  curl -L -C - -o test.gguf https://registry.ollama.ai/v2/library/<modell>/blobs/sha256:<digest>"
    )
    if CERT_ERRORS:
        cert_hint()
    return 0 if (ok_reg and ok_cdn) else 1


def server_up(host: str) -> bool:
    try:
        urllib.request.urlopen(host + "/api/version", timeout=3).read()
        return True
    except Exception:
        return False


def start_server(host: str, extra_env: dict):
    """Startet einen eigenen 'ollama serve' mit zusaetzlichen Umgebungsvariablen."""
    exe = shutil.which("ollama")
    if not exe:
        print("FEHLER: 'ollama' wurde nicht im PATH gefunden.")
        sys.exit(2)
    if server_up(host):
        print(
            "FEHLER: Auf diesem Host laeuft bereits ein Ollama-Server. Die Variablen wirken nur auf einen\n"
            "vom Skript gestarteten Server. Beende Ollama zuerst (Dienst/Tray-App) und starte neu."
        )
        sys.exit(2)
    env = os.environ.copy()
    env.update(extra_env)
    env["OLLAMA_HOST"] = host.split("://", 1)[1]
    print("Starte 'ollama serve' mit: " + ", ".join(f"{k}={v}" for k, v in extra_env.items()))
    proc = subprocess.Popen([exe, "serve"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        if server_up(host):
            return proc
        if proc.poll() is not None:
            break
        time.sleep(0.5)
    proc.terminate()
    print("FEHLER: Ollama-Server ist nicht hochgekommen.")
    sys.exit(2)


def models_dir_free(host: str):
    """Freier Platz im Modellordner - nur sinnvoll, wenn der Server lokal laeuft."""
    if not any(x in host for x in ("127.0.0.1", "localhost")):
        return None
    d = os.environ.get("OLLAMA_MODELS") or os.path.join(os.path.expanduser("~"), ".ollama", "models")
    try:
        return shutil.disk_usage(d if os.path.isdir(d) else os.path.dirname(d)).free, d
    except OSError:
        return None


def pull_once(host: str, model: str, stall_timeout: int, state: dict) -> None:
    """Ein Pull-Versuch. Kehrt bei Erfolg zurueck, wirft sonst eine Exception."""
    body = json.dumps({"model": model, "name": model, "stream": True}).encode()
    req = urllib.request.Request(
        host + "/api/pull", data=body, headers={"Content-Type": "application/json"}
    )
    last_key = None
    last_change = time.time()
    t0 = time.time()
    start_bytes = None

    with urllib.request.urlopen(req, timeout=stall_timeout) as resp:
        for raw in resp:
            raw = raw.strip()
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if "error" in msg:
                err = str(msg["error"])
                if any(h in err.lower() for h in FATAL_HINTS):
                    raise FatalPullError(err)
                raise RuntimeError(err)

            status = msg.get("status", "")
            total = msg.get("total")
            completed = msg.get("completed", 0)
            digest = msg.get("digest")

            key = (digest, completed, status)
            if key != last_key:
                last_key = key
                last_change = time.time()
                if completed:
                    state["progressed"] = True
            elif time.time() - last_change > stall_timeout:
                raise Stalled(f"kein Fortschritt seit {stall_timeout}s")

            if total and total > 100 * 1024**2 and not state.get("disk_checked"):
                state["disk_checked"] = True
                info = models_dir_free(host)
                if info and info[0] < (total - completed) * 1.05:
                    print(f"\nWARNUNG: Nur {fmt_size(info[0])} frei in {info[1]}, "
                          f"aber {fmt_size(total - completed)} noetig. Voller Datentraeger verursacht "
                          f"dieselben Symptome (Issue #8484).")

            if total:
                if start_bytes is None:
                    start_bytes = completed
                elapsed = max(time.time() - t0, 0.001)
                speed = (completed - start_bytes) / elapsed
                pct = completed / total * 100
                line = (
                    f"  {status[:28]:<28} {pct:5.1f}%  "
                    f"{fmt_size(completed)}/{fmt_size(total)}  {fmt_size(speed)}/s"
                )
                sys.stdout.write("\r" + line.ljust(100))
                sys.stdout.flush()
            else:
                sys.stdout.write("\r" + f"  {status[:90]}".ljust(100))
                sys.stdout.flush()

            if status == "success":
                sys.stdout.write("\n")
                return

    raise RuntimeError("Verbindung vom Server beendet, bevor 'success' kam")


def pull_with_retry(host, model, stall_timeout, max_retries, max_wait) -> bool:
    attempt = 0
    delay = 2
    print(f"\n=== {model} ===")
    while True:
        attempt += 1
        state = {"progressed": False}
        try:
            print(f"Versuch {attempt} ...")
            pull_once(host, model, stall_timeout, state)
            print(f"OK: {model} fertig (nach {attempt} Versuch(en)).")
            return True
        except FatalPullError as e:
            print(f"\nFEHLER (kein Retry sinnvoll): {e}")
            return False
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403, 404):
                print(f"\nFEHLER HTTP {e.code} (kein Retry sinnvoll): {e.reason}")
                return False
            reason = f"HTTP {e.code} {e.reason}"
        except (Stalled, socket.timeout, TimeoutError) as e:
            reason = f"Stillstand/Timeout ({e})"
        except urllib.error.URLError as e:
            reason = f"Server nicht erreichbar ({e.reason}) - laeuft 'ollama serve'?"
        except (ConnectionError, OSError) as e:
            reason = f"Verbindungsfehler ({e})"
        except RuntimeError as e:
            reason = str(e)

        print(f"\nAbgebrochen: {reason}")

        if max_retries and attempt >= max_retries:
            print(f"Maximale Versuche ({max_retries}) erreicht - gebe {model} auf.")
            return False

        # Hat der Versuch Fortschritt gebracht, Backoff zuruecksetzen.
        if state["progressed"]:
            delay = 2
        print(f"Neuer Versuch in {delay}s (Teil-Download wird fortgesetzt) ...")
        time.sleep(delay)
        delay = min(delay * 2, max_wait)


# ---------------------------------------------------------------------------
# Direkt-Download der Blobs (umgeht den Ollama-Downloader, mit Resume + SHA256)
# ---------------------------------------------------------------------------

def parse_model(name: str):
    """'llama3.1:8b' -> (host, namespace, name, tag). Nur registry.ollama.ai wird unterstuetzt."""
    parts = name.split("/")
    host = REGISTRY
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        host, parts = parts[0], parts[1:]
    ns = "library" if len(parts) == 1 else "/".join(parts[:-1])
    rest = parts[-1]
    mname, _, tag = rest.partition(":")
    return host, ns, mname, tag or "latest"


def systemd_models_dir():
    """OLLAMA_MODELS aus der systemd-Unit 'ollama' lesen (nur Linux)."""
    if not shutil.which("systemctl"):
        return None
    try:
        out = subprocess.run(["systemctl", "show", "ollama", "-p", "Environment"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    for tok in out.replace("Environment=", "", 1).split():
        if tok.startswith("OLLAMA_MODELS="):
            return tok.split("=", 1)[1].strip('"')
    return None


def default_models_dir() -> str:
    """Modellordner erkennen: Env -> systemd-Dienst -> ~/.ollama -> /usr/share/ollama."""
    if os.environ.get("OLLAMA_MODELS"):
        return os.environ["OLLAMA_MODELS"]
    d = systemd_models_dir()
    if d:
        return d
    home = os.path.join(os.path.expanduser("~"), ".ollama", "models")
    svc = "/usr/share/ollama/.ollama/models"
    if not os.path.isdir(home) and os.path.isdir(svc):
        return svc
    return home


def fix_owner(path: str, ref_dir: str) -> None:
    """Laeuft das Skript als root (sudo), gehoert die neue Datei dem Besitzer des blobs-Ordners
    (z. B. 'ollama'), damit der Dienst sie lesen/verwalten kann."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        st = os.stat(ref_dir)
        if st.st_uid != 0:
            os.chown(path, st.st_uid, st.st_gid)
    except OSError as e:
        print(f"  Hinweis: chown fehlgeschlagen ({e})")


def fetch_manifest(host: str, ns: str, name: str, tag: str) -> dict:
    url = f"https://{host}/v2/{ns}/{name}/manifests/{tag}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.docker.distribution.manifest.v2+json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def download_blob(url: str, digest: str, size: int, blobs_dir: str,
                  stall_timeout: int, max_retries: int, max_wait: int) -> bool:
    """Laedt einen Blob mit Range-Resume, prueft SHA256 und benennt ihn zu sha256-<hex> um."""
    hexd = digest.split(":", 1)[1]
    final = os.path.join(blobs_dir, "sha256-" + hexd)
    tmp = final + ".dl"
    if os.path.exists(final) and os.path.getsize(final) == size:
        print(f"  {hexd[:12]}  vorhanden ({fmt_size(size)}) - uebersprungen")
        return True

    attempt, delay = 0, 2
    while True:
        attempt += 1
        have = os.path.getsize(tmp) if os.path.exists(tmp) else 0
        if have > size:
            os.remove(tmp)
            have = 0
        progressed = False
        try:
            if have < size:
                headers = {"Range": f"bytes={have}-"} if have else {}
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=stall_timeout) as r:
                    if have and r.status != 206:
                        have = 0  # Server ignoriert Range -> von vorn
                    t0, got0 = time.time(), have
                    with open(tmp, "ab" if have else "wb") as f:
                        while True:
                            chunk = r.read(1024 * 1024)
                            if not chunk:
                                break
                            f.write(chunk)
                            have += len(chunk)
                            progressed = True
                            speed = (have - got0) / max(time.time() - t0, 0.001)
                            sys.stdout.write("\r" + (
                                f"  {hexd[:12]}  {have / size * 100:5.1f}%  "
                                f"{fmt_size(have)}/{fmt_size(size)}  {fmt_size(speed)}/s").ljust(100))
                            sys.stdout.flush()
                sys.stdout.write("\n")
            have = os.path.getsize(tmp)
            if have != size:
                raise RuntimeError(f"unvollstaendig ({have}/{size} Bytes)")
            print("  Pruefe SHA256 ...")
            if sha256_file(tmp) != hexd:
                os.remove(tmp)
                raise RuntimeError("SHA256 stimmt nicht - Datei verworfen")
            os.replace(tmp, final)
            fix_owner(final, blobs_dir)
            print(f"  {hexd[:12]}  OK")
            return True
        except urllib.error.HTTPError as e:
            if e.code == 416:      # Range passt nicht -> neu beginnen
                if os.path.exists(tmp):
                    os.remove(tmp)
                reason = "HTTP 416, beginne neu"
            elif e.code in (400, 401, 403, 404):
                print(f"\nFEHLER HTTP {e.code} (kein Retry sinnvoll): {e.reason}")
                return False
            else:
                reason = f"HTTP {e.code} {e.reason}"
        except OSError as e:
            if is_cert_error(e):
                cert_hint()
                return False
            if isinstance(e, (PermissionError,)) or getattr(e, "errno", None) in (13, 28, 30):
                print(f"\nFEHLER (Schreibrechte/Platz?): {e}")
                return False
            reason = f"{type(e).__name__}: {e}"
        except Exception as e:  # IncompleteRead, RuntimeError, ...
            reason = f"{type(e).__name__}: {e}"

        print(f"\nAbgebrochen: {reason}")
        if max_retries and attempt >= max_retries:
            print("Maximale Versuche erreicht.")
            return False
        if progressed:
            delay = 2
        print(f"Neuer Versuch in {delay}s (Resume ab {fmt_size(os.path.getsize(tmp) if os.path.exists(tmp) else 0)}) ...")
        time.sleep(delay)
        delay = min(delay * 2, max_wait)


def direct_download(model: str, models_dir: str, stall_timeout: int,
                    max_retries: int, max_wait: int) -> bool:
    """Alle Blobs eines Modells direkt laden. Danach registriert 'ollama pull' das Modell."""
    host, ns, name, tag = parse_model(model)
    if host != REGISTRY:
        print(f"Direkt-Modus unterstuetzt nur {REGISTRY} (Modell: {model}). Nutze normalen Pull.")
        return True
    blobs = os.path.join(models_dir, "blobs")
    print(f"\n=== {model}: Direkt-Download nach {blobs} ===")
    if not os.path.isdir(blobs):
        print("Hinweis: Ordner existiert noch nicht - wird angelegt. Falsche Stelle? Mit --models-dir angeben.")
    try:
        os.makedirs(blobs, exist_ok=True)
        if not os.access(blobs, os.W_OK):
            raise PermissionError(blobs)
    except OSError as e:
        owner = ""
        try:
            import pwd
            owner = f" (Besitzer: {pwd.getpwuid(os.stat(blobs).st_uid).pw_name})"
        except Exception:
            pass
        print(f"FEHLER: Kein Schreibzugriff auf {blobs}{owner}: {e}")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("Starte das Skript mit sudo (z. B. 'sudo python3 ollama_pull_retry.py --direct ...'). "
                  "Neue Dateien bekommen automatisch den Besitzer des blobs-Ordners.")
        return False
    try:
        manifest = fetch_manifest(host, ns, name, tag)
    except Exception as e:
        print(f"FEHLER beim Manifest ({e})")
        if is_cert_error(e):
            cert_hint()
        return False

    layers = [manifest["config"]] + manifest.get("layers", [])
    total = sum(l["size"] for l in layers)
    free = shutil.disk_usage(blobs).free
    if free < total * 1.02:
        print(f"WARNUNG: {fmt_size(free)} frei, bis zu {fmt_size(total)} noetig.")
    for l in sorted(layers, key=lambda x: x["size"]):
        url = f"https://{host}/v2/{ns}/{name}/blobs/{l['digest']}"
        if not download_blob(url, l["digest"], l["size"], blobs, stall_timeout, max_retries, max_wait):
            return False
    return True


def read_models_file(path: str):
    models = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                models.append(line)
    return models


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Ollama-Modelle laden und bei Fehlern automatisch wiederholen."
    )
    ap.add_argument("models", nargs="*", help="Modellnamen, z. B. llama3.1:8b")
    ap.add_argument("-f", "--file", help="Textdatei mit einem Modell pro Zeile (# = Kommentar)")
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "127.0.0.1:11434"),
                    help="Ollama-Host (Standard: $OLLAMA_HOST oder 127.0.0.1:11434)")
    ap.add_argument("--stall-timeout", type=int, default=30,
                    help="Sekunden ohne Fortschritt, bis neu gestartet wird (Standard: 30)")
    ap.add_argument("--diagnose", action="store_true",
                    help="DNS/Erreichbarkeit von registry.ollama.ai pruefen (System-DNS vs. DoH) und beenden")
    ap.add_argument("--proxy", metavar="URL",
                    help="Eigenen 'ollama serve' mit diesem HTTP(S)-Proxy starten (z. B. http://127.0.0.1:8080)")
    ap.add_argument("--ca-bundle", metavar="PEM",
                    help="Eigenes CA-Bundle (PEM) fuer HTTPS zur Registry, z. B. Firmen-CA bei TLS-Inspektion "
                         "(--direct/--diagnose). Alternativ: SSL_CERT_FILE oder 'pip install truststore'")
    ap.add_argument("--strict", action="store_true",
                    help="Kein automatischer Fallback auf ungepruefte TLS-Verbindungen (--direct/--diagnose)")
    ap.add_argument("--insecure", action="store_true",
                    help="TLS-Zertifikate nicht pruefen (nur --direct/--diagnose). Blobs werden weiterhin per SHA256 "
                         "geprueft; 'ollama pull' holt das Manifest danach ueber Ollamas eigene Verbindung")
    ap.add_argument("--direct", action="store_true",
                    help="Blobs selbst laden (Resume + SHA256) und danach per 'ollama pull' registrieren. "
                         "Nur lokal, nur registry.ollama.ai")
    ap.add_argument("--models-dir", default=None,
                    help="Ollama-Modellordner fuer --direct (Standard: $OLLAMA_MODELS oder ~/.ollama/models)")
    ap.add_argument("--gentle", action="store_true",
                    help="Eigenen 'ollama serve' mit OLLAMA_EXPERIMENT=client2 und OLLAMA_REGISTRY_MAXSTREAMS=1 "
                         "starten (reduziert Bandbreite/Streams; Mitigation aus Issue #8484)")
    ap.add_argument("--server-env", action="append", default=[], metavar="KEY=VALUE",
                    help="Weitere Umgebungsvariable fuer den eigenen Server, mehrfach nutzbar "
                         "(z. B. OLLAMA_DOWNLOAD_PARTS=4)")
    ap.add_argument("--max-retries", type=int, default=0,
                    help="Max. Versuche pro Modell, 0 = unbegrenzt (Standard: 0)")
    ap.add_argument("--max-wait", type=int, default=60,
                    help="Max. Wartezeit zwischen Versuchen in Sekunden (Standard: 60)")
    args = ap.parse_args()

    if args.direct or args.diagnose or args.ca_bundle or args.insecure:
        if not configure_tls(args.ca_bundle or os.environ.get("SSL_CERT_FILE"), args.insecure, args.strict):
            cert_hint()
            return 1
    if args.diagnose:
        return diagnose()

    models = list(args.models)
    if args.file:
        models += read_models_file(args.file)
    if not models:
        ap.error("Bitte mindestens ein Modell angeben (oder -f datei.txt).")

    host = norm_host(args.host)
    print(f"Ollama-Server: {host}")

    extra_env = {}
    if args.gentle:
        extra_env.update({"OLLAMA_EXPERIMENT": "client2", "OLLAMA_REGISTRY_MAXSTREAMS": "1"})
    for kv in args.server_env:
        if "=" not in kv:
            ap.error(f"--server-env erwartet KEY=VALUE, bekam: {kv}")
        k, v = kv.split("=", 1)
        extra_env[k.strip()] = v.strip()
    if args.proxy:
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            extra_env[k] = args.proxy
    server_proc = start_server(host, extra_env) if extra_env else None

    failed = []
    try:
        for m in models:
            if args.direct and not direct_download(
                    m, args.models_dir or default_models_dir(),
                    args.stall_timeout, args.max_retries, args.max_wait):
                failed.append(m)
                continue
            if not pull_with_retry(host, m, args.stall_timeout, args.max_retries, args.max_wait):
                failed.append(m)
    except KeyboardInterrupt:
        print("\nAbgebrochen durch Benutzer.")
        return 130
    finally:
        if server_proc:
            server_proc.terminate()

    print("\n--- Zusammenfassung ---")
    print(f"Erfolgreich: {len(models) - len(failed)}/{len(models)}")
    if failed:
        print("Fehlgeschlagen: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
