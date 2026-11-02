# ollama_pull_retry

Downloads Ollama models and automatically restarts the download after a failure or stall until it completes.

Background: `ollama pull` often aborts or jumps back in progress on unstable connections
(see [ollama/ollama#8484](https://github.com/ollama/ollama/issues/8484)). Causes include a hard-coded
5-second no-data limit and problems with the blob CDN (Cloudflare R2). Partial downloads are kept,
so a restart resumes where it left off.

- Single Python file, standard library only (Python 3.8+)
- Windows, Linux, macOS

## Quick start

```bash
python ollama_pull_retry.py llama3.1:8b qwen2.5-coder:14b
python ollama_pull_retry.py -f modelle.txt
```

`modelle.txt`: one model per line, `#` starts a comment.

```
qwen3-coder:30b
embeddinggemma:300m   # embeddings
```

Prerequisite: an Ollama server is running (`ollama serve` or the service/tray app) and reachable at `--host`.

## How it works

Default mode: the script uses the Ollama HTTP API (`/api/pull`) and monitors progress in bytes.
If nothing happens for `--stall-timeout` seconds, it aborts and restarts. After errors it waits with an
increasing delay (2 s, 4 s, 8 s ... up to `--max-wait`). If an attempt made progress, the delay resets to 2 s.
Permanent errors (model does not exist, HTTP 400/401/403/404) are not retried.

## Options

| Option | Meaning |
|---|---|
| `MODEL ...` | One or more model names |
| `-f, --file FILE` | Model list from a text file |
| `--host HOST` | Ollama server (default: `$OLLAMA_HOST` or `127.0.0.1:11434`) |
| `--stall-timeout SEC` | Seconds without progress before restart (default: 30) |
| `--max-retries N` | Max attempts per model, `0` = unlimited (default: 0) |
| `--max-wait SEC` | Max delay between attempts (default: 60) |
| `--direct` | Download blobs yourself (resume + SHA256), then let Ollama register them |
| `--models-dir PATH` | Model directory for `--direct` (default: auto-detected) |
| `--gentle` | Start your own `ollama serve` with `OLLAMA_EXPERIMENT=client2` and `OLLAMA_REGISTRY_MAXSTREAMS=1` |
| `--server-env K=V` | Additional environment variable for your own server (repeatable) |
| `--proxy URL` | Start your own `ollama serve` using an HTTP(S) proxy |
| `--diagnose` | Check DNS and reachability of the registry and blob CDN, then exit |

## When a plain pull is not enough

### 1. `--diagnose`

```bash
python ollama_pull_retry.py --diagnose
```

Resolves `registry.ollama.ai` and the blob CDN host via system DNS and via Cloudflare and Google
DNS-over-HTTPS, and tests TCP/TLS timings per IP. If your system DNS does not return the fastest IP,
the script suggests a `hosts` entry. The CDN host may change; it is taken from issue #8484.

### 2. `--direct` (download blobs yourself)

```bash
python ollama_pull_retry.py --direct gemma3:27b
python ollama_pull_retry.py --direct --models-dir D:\ollama\models llama3.1:8b
```

Flow:
1. Fetch the manifest from `registry.ollama.ai`
2. Download all blobs (config and layers) with `Range` resume, skipping complete existing blobs
3. Verify SHA256 and only then rename to `sha256-<hash>`
4. Run a normal pull via the API: Ollama writes the manifest and downloads nothing more

Notes:
- Local only, `registry.ollama.ai` only (other sources such as `hf.co/...` use the normal pull)
- Model directory detection order: `--models-dir`, `$OLLAMA_MODELS`, `OLLAMA_MODELS` from the
  `ollama` systemd unit, `~/.ollama/models`, `/usr/share/ollama/.ollama/models`
- **Linux system service:** the directory usually belongs to the `ollama` user. Run with `sudo`; finished
  files automatically get the owner and group of the `blobs` directory:
  ```bash
  sudo python3 ollama_pull_retry.py --direct gemma3:27b
  ```
- Docker: pass the host path of the volume via `--models-dir`
- SELinux: if the service cannot read the files, `restorecon -R <directory>` helps
- The server must be running for the last step (registering)

### 3. `--gentle`, `--server-env`, `--proxy`

These options start **your own** `ollama serve` with the requested environment variables and stop it
again at the end:

```bash
python ollama_pull_retry.py --gentle llama3.1:8b
python ollama_pull_retry.py --server-env OLLAMA_DOWNLOAD_PARTS=4 llama3.1:8b
python ollama_pull_retry.py --proxy http://127.0.0.1:8080 llama3.1:8b
```

Important: no other Ollama server may be running on the host (stop the service/tray app first),
otherwise the script aborts with a message. The variables only affect the server started by the script.
Whether `client2`/`MAXSTREAMS=1` helps varies per the issue thread: it works for some users, not for others.

## Miscellaneous

- **A full disk** causes the same symptoms as network problems. The script warns if the local model
  directory has less free space than the download needs.
- **Exit codes:** `0` all models downloaded, `1` at least one failed, `2` server start failed,
  `130` interrupted with Ctrl+C.
- Check raw line speed:
  `curl -L -C - -o test.gguf https://registry.ollama.ai/v2/library/<model>/blobs/sha256:<digest>`
