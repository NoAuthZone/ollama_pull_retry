#!/usr/bin/env python3
"""
Project: ollama_pull_retry by NoAuthZone
GitHub:  https://github.com/NoAuthZone/ollama_pull_retry

ollama_pull_retry.py - downloads Ollama models and automatically restarts the
download after failures/stalls until it completes.

Why this works: Ollama stores partially downloaded layers as partial blobs and
resumes where it left off on the next "pull". A restart therefore costs hardly
any progress - a stalled download is simply "kicked" again.

Uses the Ollama HTTP API (/api/pull) instead of the CLI. This allows monitoring
progress (bytes) and detecting a stall.
Python standard library only; runs on Windows/Linux/macOS.

Examples:
  python ollama_pull_retry.py llama3.1:8b qwen2.5-coder:14b
  python ollama_pull_retry.py -f modelle.txt --stall-timeout 45
  python ollama_pull_retry.py --host 192.168.1.20:11434 gemma3:27b
  python ollama_pull_retry.py --diagnose
  python ollama_pull_retry.py --proxy http://127.0.0.1:8080 llama3.1:8b
  python ollama_pull_retry.py --direct gemma3:27b         # download blobs yourself, then register
  python ollama_pull_retry.py --gentle llama3.1:8b        # client2 + MAXSTREAMS=1
  python ollama_pull_retry.py --server-env OLLAMA_DOWNLOAD_PARTS=4 llama3.1:8b
"""

import argparse
import atexit
import hashlib
import json
import os
import re
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
TLS_CTX = None  # set by configure_tls()


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
    """'ok' (connection + certificate fine), 'cert' (certificate error) or 'net' (any other error)."""
    opener = (urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
              if ctx else urllib.request.build_opener())
    try:
        opener.open(urllib.request.Request(url), timeout=15).close()
        return "ok"
    except urllib.error.HTTPError:
        return "ok"  # server answered -> TLS worked
    except Exception as e:
        return "cert" if is_cert_error(e) else "net"


def _ctx_from_file(path: str):
    try:
        return ssl.create_default_context(cafile=path)
    except (OSError, ssl.SSLError):
        return None


def _ctx_macos_keychain():
    """Export certificates from the macOS keychains (the same ones browsers/Go use)."""
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
    """Set up TLS trust without the user having to prepare anything.

    Order: own CA bundle -> Python default (+ truststore, if installed) -> system CA files
    -> macOS keychain -> Windows certificate store -> (only without --strict) unverified, with a warning.
    Returns False if no working variant was found.
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
        print("WARNING: --insecure - TLS certificates are NOT verified. Integrity is only ensured by the "
              "SHA256 check of the blobs and the subsequent 'ollama pull' (manifest over Ollama's own "
              "TLS connection).")
        return use(unverified(), "unverified (--insecure)")

    if ca_bundle:
        ctx = _ctx_from_file(ca_bundle)
        if not ctx:
            print(f"ERROR: cannot read CA bundle: {ca_bundle}")
            return False
        return use(ctx, f"CA bundle {ca_bundle}")

    try:  # optional: pip install truststore (Python 3.10+) -> OS certificate store
        import truststore
        truststore.inject_into_ssl()
    except Exception:
        pass

    candidates = [("Python default", lambda: None)]
    for f in SYSTEM_CA_FILES:
        if os.path.isfile(f):
            candidates.append((f"system CA file {f}", lambda f=f: _ctx_from_file(f)))
    candidates.append(("macOS keychain", _ctx_macos_keychain))
    candidates.append(("Windows certificate store", _ctx_windows_store))

    saw_cert_error = False
    for label, make in candidates:
        ctx = make()
        if ctx is None and label != "Python default":
            continue
        result = _tls_check(ctx, probe_url)
        if result == "ok":
            return use(ctx, label)
        if result == "net":
            # Not a certificate problem (offline, firewall ...): other trust sources will not help.
            if not saw_cert_error:
                return True
            break
        saw_cert_error = True

    if strict:
        print("TLS: no trusted certificate found (--strict, no fallback).")
        return False
    print("WARNING: the registry certificate is not accepted by any certificate store on this system "
          "(probably TLS inspection). Continuing WITHOUT certificate verification. Integrity is ensured by the "
          "SHA256 check of the blobs and the subsequent 'ollama pull'. Disable this with --strict, "
          "or use --ca-bundle / 'pip install truststore'.")
    return use(unverified(), "unverified (automatic fallback)")


def is_cert_error(e: BaseException) -> bool:
    reason = getattr(e, "reason", None)
    return (isinstance(e, ssl.SSLCertVerificationError)
            or isinstance(reason, ssl.SSLCertVerificationError)
            or "CERTIFICATE_VERIFY_FAILED" in str(e)
            or "local issuer certificate" in str(e))


def cert_hint() -> None:
    print(
        "\nTLS certificate error ('unable to get local issuer certificate'). Retrying is pointless. Typical causes:\n"
        "  1. Corporate/proxy TLS inspection with its own CA: export the CA as PEM and set\n"
        "     '--ca-bundle corp-ca.pem' (or SSL_CERT_FILE) - or 'pip install truststore'\n"
        "     (then the OS certificate store of Windows/macOS/Linux is used).\n"
        "  2. macOS with python.org Python: run '/Applications/Python 3.x/Install Certificates.command'.\n"
        "  3. Linux: install/update the 'ca-certificates' package.\n"
        "  4. Without --strict the script falls back to unverified TLS in direct/diagnose mode by itself.\n"
        "Note: if the error comes from 'ollama pull' itself (Go: 'x509: certificate signed by unknown\n"
        "authority'), the Ollama SERVER needs the CA: --server-env SSL_CERT_FILE=/path/ca.pem (own server)\n"
        "or the CA in the server's system store.")


VERSION = "1.0"
GITHUB_URL = "https://github.com/NoAuthZone/ollama_pull_retry"
BANNER_WIDE = r'''
  ___  _    _      _   __  __   _       ___ _   _ _    _      ___ ___ _____ _____   __
 / _ \| |  | |    /_\ |  \/  | /_\     | _ \ | | | |  | |    | _ \ __|_   _| _ \ \ / /
| (_) | |__| |__ / _ \| |\/| |/ _ \    |  _/ |_| | |__| |__  |   / _|  | | |   /\ V /
 \___/|____|____/_/ \_\_|  |_/_/ \_\   |_|  \___/|____|____| |_|_\___| |_| |_|_\ |_|'''
BANNER_STACKED = r'''
  ___  _    _      _   __  __   _
 / _ \| |  | |    /_\ |  \/  | /_\
| (_) | |__| |__ / _ \| |\/| |/ _ \
 \___/|____|____/_/ \_\_|  |_/_/ \_\

 ___ _   _ _    _      ___ ___ _____ _____   __
| _ \ | | | |  | |    | _ \ __|_   _| _ \ \ / /
|  _/ |_| | |__| |__  |   / _|  | | |   /\ V /
|_|  \___/|____|____| |_|_\___| |_| |_|_\ |_|'''


def print_banner() -> None:
    # Side by side if the terminal is wide enough, otherwise stacked.
    wide = shutil.get_terminal_size((100, 24)).columns >= 90
    print(BANNER_WIDE if wide else BANNER_STACKED)
    print(f"  ollama_pull_retry v{VERSION} - resumable Ollama downloads")
    print(f"  by NoAuthZone - {GITHUB_URL}")
    print("  " + "-" * 62)
    print()


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
    """Human-readable size in decimal units (like Ollama and the macOS Finder)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1000
    return f"{n:.1f} TB"

class Progress:
    """Progress display: bar, percent with 2 decimals, transferred MB (even for GB sizes), speed (moving 5 s average) and ETA; adapts to the terminal width."""

    def __init__(self):
        self.samples = []      # (time, completed)
        self.last_draw = 0.0
        self.tty = sys.stdout.isatty()
        try:
            "█░".encode(sys.stdout.encoding or "ascii")
            self.chars = ("█", "░")
        except (UnicodeEncodeError, LookupError):
            self.chars = ("#", "-")

    def speed(self, now: float, completed: int, window: float = 5.0) -> float:
        self.samples.append((now, completed))
        while len(self.samples) > 2 and now - self.samples[0][0] > window:
            self.samples.pop(0)
        t0, c0 = self.samples[0]
        return (completed - c0) / (now - t0) if now > t0 else 0.0

    def line(self, label: str, completed: int, total: int, speed: float, cols: int = 0) -> str:
        cols = cols or shutil.get_terminal_size((100, 24)).columns
        completed = min(completed, total) if total else completed
        pct = completed / total * 100 if total else 0.0
        eta = ""
        if speed > 0 and total > completed:
            s = int((total - completed) / speed)
            eta = f"ETA {s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}" if s >= 3600 else f"ETA {s // 60}:{s % 60:02d}"
        line = ""
        for bar_w, with_gb, with_eta, with_speed in ((20, True, True, True), (20, False, True, True),
                                                     (12, False, True, True), (0, False, True, True),
                                                     (0, False, False, True), (0, False, False, False)):
            parts = [f"  {label}"]
            if bar_w:
                filled = int(bar_w * completed / total) if total else 0
                parts.append(self.chars[0] * filled + self.chars[1] * (bar_w - filled))
            parts.append(f"{pct:6.2f}%")
            if total >= 1_000_000:   # MB with one decimal, even for GB-sized blobs
                parts.append(f"{completed / 1e6:,.1f} / {total / 1e6:,.1f} MB")
            else:                    # small layers: B/KB
                parts.append(f"{fmt_size(completed)} / {fmt_size(total)}")
            if with_gb and total >= 1e9:
                parts.append(f"({completed / 1e9:.2f} / {total / 1e9:.2f} GB)")
            if with_speed and speed > 0 and total >= 1_000_000:   # speed is meaningless for tiny layers
                parts.append(f"{fmt_size(speed)}/s")
            if with_eta and eta:
                parts.append(eta)
            line = "  ".join(parts)
            if len(line) <= cols - 1:
                break
        return line[:cols - 1]

    def show(self, label: str, completed: int, total: int, final: bool = False) -> bool:
        """Draw the progress line. Returns True if something was written."""
        now = time.time()
        speed = self.speed(now, completed)
        if not final and now - self.last_draw < (0.1 if self.tty else 10.0):
            return False
        self.last_draw = now
        cols = shutil.get_terminal_size((100, 24)).columns
        text = self.line(label, completed, total, speed, cols)
        if self.tty:
            sys.stdout.write("\r" + text.ljust(cols - 1))
        else:
            sys.stdout.write(text + "\n")
        sys.stdout.flush()
        return self.tty



REGISTRY = "registry.ollama.ai"
# Blob CDN (Cloudflare R2), known from issue #8484; blocked by some ISPs.
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
    """TCP+TLS+HTTP test against one IP (SNI/Host = hostname)."""
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
    sources = {}  # ip -> [sources]
    try:
        infos = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
        for ip in sorted({i[4][0] for i in infos}):
            sources.setdefault(ip, []).append("system DNS")
    except OSError as e:
        print(f"system DNS: ERROR ({e})")
    for name, url in DOH_SERVERS.items():
        try:
            for ip in doh_lookup(url, hostname):
                sources.setdefault(ip, []).append(name)
        except Exception as e:
            print(f"{name}: ERROR ({e})")

    if not sources:
        print("No IPs found - network/DNS broken?\n")
        return False

    results = []
    print(f"{'IP':<18}{'Source':<34}{'TCP':>8}{'Total':>9}  Response")
    for ip, src in sources.items():
        try:
            tc, tt, first = probe_ip(ip, hostname)
            results.append((tt, ip))
            print(f"{ip:<18}{', '.join(src):<34}{tc*1000:>6.0f}ms{tt*1000:>7.0f}ms  {first}")
        except Exception as e:
            print(f"{ip:<18}{', '.join(src):<34}{'-':>8}{'-':>9}  ERROR: {e}")
            if is_cert_error(e):
                CERT_ERRORS.append(hostname)

    if not results:
        print("No IP reachable. Check firewall/proxy/VPN (ISP block possible).\n")
        return False
    best = min(results)[1]
    sys_ips = [ip for ip, s in sources.items() if "system DNS" in s]
    print(f"Fastest IP: {best}")
    if best not in sys_ips:
        print("System DNS does NOT return this IP. Possible workaround - hosts entry")
        print("(Linux/macOS: /etc/hosts, Windows: C:\\Windows\\System32\\drivers\\etc\\hosts):")
        print(f"  {best} {hostname}")
    else:
        print("System DNS already returns the fastest IP.")
    print()
    return True


def diagnose() -> int:
    """Test registry and blob CDN: system DNS vs. DNS-over-HTTPS, TCP/TLS timings."""
    ok_reg = diagnose_host(REGISTRY)
    ok_cdn = diagnose_host(CDN_HOST)
    print(
        "Note: Ollama downloads the large blobs from the CDN host (redirect from the registry). "
        "The host name may change; this entry comes from issue #8484."
    )
    print(
        "Additional test (as suggested by rick-github), check raw speed:\n"
        "  curl -L -C - -o test.gguf https://registry.ollama.ai/v2/library/<model>/blobs/sha256:<digest>"
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
    """Start your own 'ollama serve' with additional environment variables."""
    exe = shutil.which("ollama")
    if not exe:
        print("ERROR: 'ollama' not found in PATH.")
        sys.exit(2)
    if server_up(host):
        print(
            "ERROR: An Ollama server is already running on this host. The variables only affect a server\n"
            "started by this script. Stop Ollama first (service/tray app) and run again."
        )
        sys.exit(2)
    env = os.environ.copy()
    env.update(extra_env)
    env["OLLAMA_HOST"] = host.split("://", 1)[1]
    print("Starting 'ollama serve' with: " + ", ".join(f"{k}={v}" for k, v in extra_env.items()))
    proc = subprocess.Popen([exe, "serve"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        if server_up(host):
            return proc
        if proc.poll() is not None:
            break
        time.sleep(0.5)
    proc.terminate()
    print("ERROR: Ollama server did not come up.")
    sys.exit(2)


def models_dir_free(host: str):
    """Free space in the model directory - only meaningful if the server runs locally."""
    if not any(x in host for x in ("127.0.0.1", "localhost")):
        return None
    d = default_models_dir()
    try:
        return shutil.disk_usage(d if os.path.isdir(d) else os.path.dirname(d)).free, d
    except OSError:
        return None


def pull_once(host: str, model: str, stall_timeout: int, state: dict) -> None:
    """One pull attempt. Returns on success, raises an exception otherwise."""
    body = json.dumps({"model": model, "name": model, "stream": True}).encode()
    req = urllib.request.Request(
        host + "/api/pull", data=body, headers={"Content-Type": "application/json"}
    )
    last_key = None
    last_change = time.time()
    prog = Progress()
    cur_digest = None
    cur_label, cur_total, cur_open = "", 0, False
    last_status = None
    finished = set()

    def finish_layer():
        """Ollama handles layers one after another: a new digest or status means the previous layer is
        complete, even if its last progress message was below 100 %. Draw it as finished."""
        nonlocal cur_open
        if cur_open:
            prog.show(cur_label, cur_total, cur_total, final=True)
            if prog.tty:
                sys.stdout.write("\n")
            finished.add(cur_digest)
            cur_open = False

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
                raise Stalled(f"no progress for {stall_timeout}s")

            if total and total > 100 * 1024**2 and not state.get("disk_checked"):
                state["disk_checked"] = True
                info = models_dir_free(host)
                if info and info[0] < (total - completed) * 1.05:
                    print(f"\nWARNING: only {fmt_size(info[0])} free in {info[1]}, "
                          f"but {fmt_size(total - completed)} needed. A full disk causes "
                          f"the same symptoms (issue #8484).")

            if total:
                if digest != cur_digest:
                    finish_layer()
                    cur_digest = digest
                    prog = Progress()   # new layer -> new speed measurement
                if digest not in finished:
                    cur_label, cur_total, cur_open = status[:28], total, True
                    if completed >= total:
                        finish_layer()
                    else:
                        prog.show(cur_label, completed, total)
            elif status != last_status:
                finish_layer()
                print(f"  {status[:90]}")
                last_status = status

            if status == "success":
                finish_layer()
                return

    raise RuntimeError("Server closed the connection before 'success'")


_PARTIAL_HINT_SHOWN = False


def partial_hint(reason: str) -> None:
    """Hint for the Ollama-internal error 'remove ...-partial-N: no such file or directory'."""
    global _PARTIAL_HINT_SHOWN
    m = re.search(r"remove (.+?)-partial-\d+: no such file", reason)
    if not m or _PARTIAL_HINT_SHOWN:
        return
    _PARTIAL_HINT_SHOWN = True
    print(
        "\nNote: this is an Ollama-internal state error. If a download is aborted and restarted immediately,\n"
        "the old and the new run overlap and one deletes the other's part files.\n"
        "Options:\n"
        "  1. Leave Ollama alone (stop any hanging 'ollama pull'), wait a moment, run again.\n"
        f"  2. Delete the part files of this blob (only if no download is running):  rm '{m.group(1)}'-partial*\n"
        "  3. Use --direct: the script downloads the large blob itself and bypasses Ollama's downloader.")


def pull_with_retry(host, model, stall_timeout, max_retries, max_wait) -> bool:
    attempt = 0
    delay = 8  # Ollama needs a moment to finish the old run (otherwise a race, see partial_hint)
    print(f"\n=== {model} ===")
    while True:
        attempt += 1
        state = {"progressed": False}
        try:
            print(f"Attempt {attempt} ...")
            pull_once(host, model, stall_timeout, state)
            print(f"OK: {model} done (after {attempt} attempt(s)).")
            return True
        except FatalPullError as e:
            print(f"\nERROR (retrying is pointless): {e}")
            return False
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403, 404):
                print(f"\nERROR HTTP {e.code} (retrying is pointless): {e.reason}")
                return False
            reason = f"HTTP {e.code} {e.reason}"
        except (Stalled, socket.timeout, TimeoutError) as e:
            reason = f"stall/timeout ({e})"
        except urllib.error.URLError as e:
            reason = f"server not reachable ({e.reason}) - is 'ollama serve' running?"
        except (ConnectionError, OSError) as e:
            reason = f"connection error ({e})"
        except RuntimeError as e:
            reason = str(e)

        print(f"\nAborted: {reason}")
        partial_hint(reason)

        if max_retries and attempt >= max_retries:
            print(f"Maximum attempts ({max_retries}) reached - giving up on {model}.")
            return False

        # If the attempt made progress, reset the backoff.
        if state["progressed"]:
            delay = 8
        print(f"Next attempt in {delay}s (partial download will be resumed) ...")
        time.sleep(delay)
        delay = min(delay * 2, max_wait)


# ---------------------------------------------------------------------------
# Direct blob download (bypasses the Ollama downloader, with resume + SHA256)
# ---------------------------------------------------------------------------

def parse_model(name: str):
    """'llama3.1:8b' -> (host, namespace, name, tag). Only registry.ollama.ai is supported."""
    parts = name.split("/")
    host = REGISTRY
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        host, parts = parts[0], parts[1:]
    ns = "library" if len(parts) == 1 else "/".join(parts[:-1])
    rest = parts[-1]
    mname, _, tag = rest.partition(":")
    return host, ns, mname, tag or "latest"


def systemd_models_dir():
    """Read OLLAMA_MODELS from the 'ollama' systemd unit (Linux only)."""
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
    """Detect the model directory: env -> systemd service -> ~/.ollama -> /usr/share/ollama."""
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
    """If the script runs as root (sudo), give the new file the owner of the blobs directory
    (e.g. 'ollama') so the service can read/manage it."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        st = os.stat(ref_dir)
        if st.st_uid != 0:
            os.chown(path, st.st_uid, st.st_gid)
    except OSError as e:
        print(f"  Note: chown failed ({e})")


def fetch_manifest(host: str, ns: str, name: str, tag: str) -> dict:
    url = f"https://{host}/v2/{ns}/{name}/manifests/{tag}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.docker.distribution.manifest.v2+json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def sha256_file(path: str, label: str = None) -> str:
    """SHA256 of a file; shows a progress line for large files if a label is given."""
    h = hashlib.sha256()
    total = os.path.getsize(path)
    prog = Progress() if label and total > 50_000_000 else None
    done = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            if prog:
                prog.show(label, done, total)
    if prog:
        prog.show(label, done, total, final=True)
        if prog.tty:
            sys.stdout.write("\n")
    return h.hexdigest()


def recover_full_response(url: str, hexd: str, size: int, final: str, blobs_dir: str,
                          stall_timeout: int) -> bool:
    """Diagnosis after a persistent checksum error: fetch the complete server response without a size limit.

    If its SHA256 matches the digest, only the size in the manifest is wrong -> the blob is accepted.
    Otherwise the content is saved as .bad and described (suspicion: content altered in transit)."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=stall_timeout) as r:
            body = r.read(2 * size + 65536)
            hdr = {k: v for k, v in r.headers.items()
                   if k.lower() in ("content-length", "content-type", "content-encoding", "via", "server", "x-cache")}
    except Exception as e:
        print(f"  Diagnosis: cannot read the complete response ({e})")
        return False
    got = hashlib.sha256(body).hexdigest()
    print(f"  Diagnosis: server delivers {len(body)} bytes (manifest: {size}), SHA256 {got[:16]}...")
    print(f"  Diagnosis: headers {hdr}")
    if got == hexd:
        print("  The complete response matches the digest - only the size in the manifest is wrong. Accepting the blob.")
        tmp = final + ".dl"
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, final)
        fix_owner(final, blobs_dir)
        return True
    bad = final + ".bad"
    try:
        with open(bad, "wb") as f:
            f.write(body)
        print(f"  Diagnosis: response saved as {bad}")
    except OSError:
        pass
    print(f"  Diagnosis: first bytes (hex): {body[:32].hex(' ')}")
    print(f"  Diagnosis: beginning as text: {body[:80]!r}")
    print("  The content differs from the expected digest: is it altered in transit (TLS-inspecting proxy,\n"
          "  antivirus web shield, ISP)? Compare: 'curl -sL <url> | shasum -a 256' or use another network (hotspot).")
    return False


def download_blob(url: str, digest: str, size: int, blobs_dir: str, stall_timeout: int,
                  max_retries: int, max_wait: int, verify_existing: bool = False) -> bool:
    """Download a blob with Range resume, verify SHA256 and rename it to sha256-<hex>.

    At most `size` bytes are read (like Ollama itself, size according to the manifest). Extra bytes from the
    server are ignored; only the SHA256 sum decides whether the content is correct."""
    hexd = digest.split(":", 1)[1]
    final = os.path.join(blobs_dir, "sha256-" + hexd)
    tmp = final + ".dl"
    if (os.path.exists(final) and os.path.getsize(final) != size
            and os.path.getsize(final) <= 16 * 1024 * 1024 and sha256_file(final) == hexd):
        print(f"  {hexd[:12]}  already present ({fmt_size(os.path.getsize(final))}, manifest says {fmt_size(size)}; "
              "SHA256 matches) - skipped")
        return True
    if os.path.exists(final) and os.path.getsize(final) == size:
        if not verify_existing:
            print(f"  {hexd[:12]}  already present ({fmt_size(size)}) - skipped")
            return True
        print(f"  {hexd[:12]}  already present - verifying SHA256 ({fmt_size(size)}) ...")
        if sha256_file(final, f"{hexd[:12]} SHA256") == hexd:
            print(f"  {hexd[:12]}  OK")
            return True
        print("  SHA256 does NOT match - file will be replaced")
        os.remove(final)

    attempt, delay = 0, 2
    last_reason, same_count = None, 0
    tried_full = False
    while True:
        attempt += 1
        have = os.path.getsize(tmp) if os.path.exists(tmp) else 0
        if have > size:
            os.remove(tmp)
            have = 0
        progressed = False
        deterministic = False
        try:
            if have < size:
                headers = {"Range": f"bytes={have}-{size - 1}"}
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=stall_timeout) as r:
                    if have and r.status != 206:
                        have = 0  # server ignores Range -> start over
                    prog = Progress()
                    with open(tmp, "ab" if have else "wb") as f:
                        while have < size:
                            chunk = r.read(min(1024 * 1024, size - have))
                            if not chunk:
                                break
                            f.write(chunk)
                            have += len(chunk)
                            progressed = True
                            prog.show(hexd[:12], have, size)
                prog.show(hexd[:12], have, size, final=True)
                if prog.tty:
                    sys.stdout.write("\n")
            have = os.path.getsize(tmp)
            if have != size:
                raise RuntimeError(f"incomplete ({have}/{size} bytes)")
            print("  Verifying SHA256 ...")
            if sha256_file(tmp, f"{hexd[:12]} SHA256") != hexd:
                os.remove(tmp)
                deterministic = True
                raise RuntimeError("SHA256 mismatch - file discarded")
            os.replace(tmp, final)
            fix_owner(final, blobs_dir)
            print(f"  {hexd[:12]}  OK")
            return True
        except urllib.error.HTTPError as e:
            if e.code == 416:      # Range not satisfiable -> start over
                if os.path.exists(tmp):
                    os.remove(tmp)
                reason = "HTTP 416, starting over"
            elif e.code in (400, 401, 403, 404):
                print(f"\nERROR HTTP {e.code} (retrying is pointless): {e.reason}")
                return False
            else:
                reason = f"HTTP {e.code} {e.reason}"
        except OSError as e:
            if is_cert_error(e):
                cert_hint()
                return False
            if isinstance(e, (PermissionError,)) or getattr(e, "errno", None) in (13, 28, 30):
                print(f"\nERROR (write permission/disk space?): {e}")
                return False
            reason = f"{type(e).__name__}: {e}"
        except Exception as e:  # IncompleteRead, RuntimeError, ...
            reason = f"{type(e).__name__}: {e}"

        print(f"\nAborted: {reason}")
        if deterministic and not tried_full and size <= 16 * 1024 * 1024:
            tried_full = True   # manifest size may be wrong: check the complete response right away
            if recover_full_response(url, hexd, size, final, blobs_dir, stall_timeout):
                return True
        # The same checksum error again and again is not a network problem -> do not retry forever.
        if deterministic and reason == last_reason:
            same_count += 1
        else:
            same_count = 1
        last_reason = reason if deterministic else None
        if deterministic and same_count >= 3:
            print("Same checksum error 3 times in a row - not a network problem, no further retries.")
            return False
        if max_retries and attempt >= max_retries:
            print("Maximum attempts reached.")
            return False
        if progressed:
            delay = 2
        print(f"Next attempt in {delay}s (resuming from {fmt_size(os.path.getsize(tmp) if os.path.exists(tmp) else 0)}) ...")
        time.sleep(delay)
        delay = min(delay * 2, max_wait)


def direct_download(model: str, models_dir: str, stall_timeout: int,
                    max_retries: int, max_wait: int, verify_existing: bool = False) -> bool:
    """Download all blobs of a model directly. Afterwards 'ollama pull' registers the model."""
    host, ns, name, tag = parse_model(model)
    if host != REGISTRY:
        print(f"Direct mode only supports {REGISTRY} (model: {model}). Using the normal pull.")
        return True
    blobs = os.path.join(models_dir, "blobs")
    print(f"\n=== {model}: direct download to {blobs} ===")
    if not os.path.isdir(blobs):
        print("Note: directory does not exist yet - it will be created. Wrong location? Specify --models-dir.")
    try:
        os.makedirs(blobs, exist_ok=True)
        if not os.access(blobs, os.W_OK):
            raise PermissionError(blobs)
    except OSError as e:
        owner = ""
        try:
            import pwd
            owner = f" (owner: {pwd.getpwuid(os.stat(blobs).st_uid).pw_name})"
        except Exception:
            pass
        print(f"ERROR: no write access to {blobs}{owner}: {e}")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("Run the script with sudo (e.g. 'sudo python3 ollama_pull_retry.py --direct ...'). "
                  "New files automatically get the owner of the blobs directory.")
        return False
    try:
        manifest = fetch_manifest(host, ns, name, tag)
    except Exception as e:
        print(f"ERROR fetching the manifest ({e})")
        if is_cert_error(e):
            cert_hint()
        return False

    layers = [manifest["config"]] + manifest.get("layers", [])
    total = sum(l["size"] for l in layers)
    free = shutil.disk_usage(blobs).free
    if free < total * 1.02:
        print(f"WARNING: {fmt_size(free)} free, up to {fmt_size(total)} needed.")
    for l in sorted(layers, key=lambda x: x["size"]):
        url = f"https://{host}/v2/{ns}/{name}/blobs/{l['digest']}"
        if not download_blob(url, l["digest"], l["size"], blobs, stall_timeout, max_retries, max_wait,
                             verify_existing):
            if l["size"] < 64 * 1024 * 1024:
                print(f"  Note: small layer {l['digest'][7:19]} skipped - "
                      "the final 'ollama pull' will download it itself.")
                continue
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
        description="Download Ollama models and automatically retry on errors."
    )
    ap.add_argument("models", nargs="*", help="Model names, e.g. llama3.1:8b")
    ap.add_argument("-f", "--file", help="Text file with one model per line (# = comment)")
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "127.0.0.1:11434"),
                    help="Ollama host (default: $OLLAMA_HOST or 127.0.0.1:11434)")
    ap.add_argument("--stall-timeout", type=int, default=60,
                    help="Seconds without progress before restarting (default: 60)")
    ap.add_argument("--diagnose", action="store_true",
                    help="Check DNS/reachability of registry.ollama.ai (system DNS vs. DoH) and exit")
    ap.add_argument("--proxy", metavar="URL",
                    help="Start your own 'ollama serve' using this HTTP(S) proxy (e.g. http://127.0.0.1:8080)")
    ap.add_argument("--ca-bundle", metavar="PEM",
                    help="Custom CA bundle (PEM) for HTTPS to the registry, e.g. a corporate CA with TLS inspection "
                         "(--direct/--diagnose). Alternatively: SSL_CERT_FILE or 'pip install truststore'")
    ap.add_argument("--strict", action="store_true",
                    help="No automatic fallback to unverified TLS connections (--direct/--diagnose)")
    ap.add_argument("--insecure", action="store_true",
                    help="Do not verify TLS certificates (--direct/--diagnose only). Blobs are still verified by SHA256; "
                         "'ollama pull' fetches the manifest afterwards over Ollama's own connection")
    ap.add_argument("--direct", action="store_true",
                    help="Download blobs yourself (resume + SHA256), then register them via 'ollama pull'. "
                         "Local only, registry.ollama.ai only")
    ap.add_argument("--verify", action="store_true",
                    help="With --direct: verify existing complete blobs by SHA256 instead of size only "
                         "(takes a while for large models)")
    ap.add_argument("--models-dir", default=None,
                    help="Ollama model directory for --direct (default: auto-detected, $OLLAMA_MODELS or ~/.ollama/models)")
    ap.add_argument("--gentle", action="store_true",
                    help="Start your own 'ollama serve' with OLLAMA_EXPERIMENT=client2 and OLLAMA_REGISTRY_MAXSTREAMS=1 "
                         "(reduces bandwidth/streams; mitigation from issue #8484)")
    ap.add_argument("--server-env", action="append", default=[], metavar="KEY=VALUE",
                    help="Additional environment variable for your own server, repeatable "
                         "(e.g. OLLAMA_DOWNLOAD_PARTS=4)")
    ap.add_argument("--no-banner", action="store_true",
                    help="Do not show the startup banner (logo and GitHub link)")
    ap.add_argument("--max-retries", type=int, default=0,
                    help="Max. attempts per model, 0 = unlimited (default: 0)")
    ap.add_argument("--max-wait", type=int, default=60,
                    help="Max. wait between attempts in seconds (default: 60)")
    args = ap.parse_args()
    if not args.no_banner:
        print_banner()

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
        ap.error("Please specify at least one model (or -f file.txt).")

    host = norm_host(args.host)
    print(f"Ollama server: {host}")
    if any(x in host for x in ("127.0.0.1", "localhost")):
        mdir = args.models_dir or default_models_dir()
        note = ""
        try:
            check = mdir if os.path.isdir(mdir) else os.path.dirname(mdir)
            note = f"  ({fmt_size(shutil.disk_usage(check).free)} free)"
            if not os.path.isdir(mdir):
                note += "  [does not exist yet]"
        except OSError:
            pass
        print(f"Models folder: {mdir}{note}")
    else:
        print("Models folder: (remote server - local path unknown)")

    extra_env = {}
    if args.gentle:
        extra_env.update({"OLLAMA_EXPERIMENT": "client2", "OLLAMA_REGISTRY_MAXSTREAMS": "1"})
    for kv in args.server_env:
        if "=" not in kv:
            ap.error(f"--server-env expects KEY=VALUE, got: {kv}")
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
                    args.stall_timeout, args.max_retries, args.max_wait, args.verify):
                failed.append(m)
                continue
            if not pull_with_retry(host, m, args.stall_timeout, args.max_retries, args.max_wait):
                failed.append(m)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 130
    finally:
        if server_proc:
            server_proc.terminate()

    print("\n--- Summary ---")
    print(f"Succeeded: {len(models) - len(failed)}/{len(models)}")
    if failed:
        print("Failed: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
