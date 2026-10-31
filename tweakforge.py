#!/usr/bin/env python3
"""
TweakForge - build iOS jailbreak tweaks (Theos projects) from a source .zip on Arch Linux.

  ./start.sh                      terminal menu (first run installs everything)
  tweakforge.py web               browser UI instead
  tweakforge.py build tweak.zip   build from the command line
  tweakforge.py setup | doctor    install / check Theos, SDKs, ldid
"""
import argparse
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

VERSION = "2.0.0"
THEOS = Path(os.environ.get("THEOS", Path.home() / "theos"))
OUT_DIR = Path(os.environ.get("TWEAKFORGE_OUT", Path.home() / "TweakForge-Output"))
SCHEMES = ["auto", "rootful", "rootless", "roothide"]
ARCH_CHOICES = {"auto": None, "arm64+arm64e": "arm64 arm64e", "arm64": "arm64", "arm64e": "arm64e"}
MAX_UPLOAD = 500 * 1024 * 1024

PACMAN_DEPS = [
    "base-devel", "git", "clang", "lld", "perl", "rsync", "curl", "unzip",
    "fakeroot", "libarchive", "xz", "zstd", "openssl", "libplist", "python",
]
THEOS_INSTALLER = "https://raw.githubusercontent.com/theos/theos/master/bin/install-theos"
THEOS_REPO = "https://github.com/theos/theos.git"
SDK_REPO = "https://github.com/theos/sdks.git"
LDID_REPO = "https://github.com/ProcursusTeam/ldid.git"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class Runner:
    """Runs commands, streams output line by line to `log`, can be cancelled."""

    def __init__(self, log):
        self.log = log
        self.proc = None
        self.cancelled = False

    def run(self, cmd, cwd=None, env=None, shell=False):
        shown = cmd if isinstance(cmd, str) else " ".join(shlex.quote(c) for c in cmd)
        self.log(f"$ {shown}")
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=cwd, env=env, shell=shell, text=True, bufsize=1,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except FileNotFoundError as e:
            self.log(f"!! command not found: {e.filename}")
            return 127
        for line in self.proc.stdout:
            line = ANSI_RE.sub("", line.rstrip("\n"))
            self.log(line.split("\r")[-1] if "\r" in line else line)
        return self.proc.wait()

    def cancel(self):
        self.cancelled = True
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass


def tool_paths():
    return [
        str(THEOS / "bin"),
        str(THEOS / "toolchain" / "linux" / "iphone" / "bin"),
        str(THEOS / "toolchain" / "swift" / "bin"),
        str(Path.home() / ".local" / "bin"),
    ]


def build_env(scheme):
    env = os.environ.copy()
    env["THEOS"] = str(THEOS)
    env["PATH"] = os.pathsep.join(tool_paths() + [env.get("PATH", "")])
    if scheme in ("rootless", "roothide"):
        env["THEOS_PACKAGE_SCHEME"] = scheme
    elif scheme == "rootful":
        env.pop("THEOS_PACKAGE_SCHEME", None)
    return env


def which(name):
    return shutil.which(name, path=os.pathsep.join(tool_paths() + [os.environ.get("PATH", "")]))


def safe_extract(zip_path, dest):
    """Extract a zip, refusing path traversal and skipping macOS junk and symlinks."""
    dest = Path(dest).resolve()
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename
            if name.startswith("__MACOSX/") or name.endswith(".DS_Store"):
                continue
            target = (dest / name).resolve()
            if dest != target and dest not in target.parents:
                raise RuntimeError(f"unsafe path in zip: {name}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            mode = (info.external_attr >> 16) & 0o777
            if mode:
                os.chmod(target, mode | 0o600)


def find_project_root(base):
    """Shallowest dir with a Theos Makefile (falls back to any Makefile)."""
    makefiles = sorted(
        (p for p in Path(base).rglob("Makefile") if ".theos" not in p.parts and "packages" not in p.parts),
        key=lambda p: len(p.parts),
    )
    for mk in makefiles:
        try:
            txt = mk.read_text(errors="ignore")
        except OSError:
            continue
        if "theos" in txt.lower():
            return mk.parent
    return makefiles[0].parent if makefiles else None


def read_source_info(root):
    """Package/version from `control`, scheme/archs hints from the Makefile."""
    info = {}
    ctl = root / "control"
    if ctl.is_file():
        for line in ctl.read_text(errors="ignore").splitlines():
            if line.startswith("Package:"):
                info["package"] = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                info["version"] = line.split(":", 1)[1].strip()
    mk = (root / "Makefile").read_text(errors="ignore")
    m = re.search(r"THEOS_PACKAGE_SCHEME\s*[:?]?=\s*(\w+)", mk)
    if m:
        info["scheme_src"] = m.group(1)
    m = re.search(r"^\s*ARCHS\s*[:?]?=\s*(.+)$", mk, re.M)
    if m:
        info["archs_src"] = m.group(1).strip()
    return info


# --------------------------------------------------------------------------- #
# doctor / setup
# --------------------------------------------------------------------------- #
def problems():
    out = []
    if not (THEOS / "makefiles").is_dir():
        out.append("Theos not installed")
    elif not (THEOS / "sdks").is_dir() or not any((THEOS / "sdks").glob("*.sdk")):
        out.append("iOS SDKs missing")
    for tool in ("make", "clang", "perl", "fakeroot", "rsync", "ldid"):
        if not which(tool):
            out.append(f"{tool} missing")
    return out


def doctor(log=print):
    p = problems()
    log(f"Theos path: {THEOS}")
    for item in p:
        log(f"[!!] {item}")
    log("[ok] everything looks good" if not p else "-> run ./start.sh (or: tweakforge.py setup)")
    return not p


def setup(runner, log=print):
    log("== 1/4 system packages ==")
    sudo = [] if os.geteuid() == 0 else ["sudo"]
    if runner.run(sudo + ["pacman", "-S", "--needed", "--noconfirm"] + PACMAN_DEPS) != 0:
        log("!! pacman failed - fix that first")
        return False

    log("== 2/4 Theos ==")
    if not (THEOS / "makefiles").is_dir():
        env = os.environ.copy()
        env["THEOS"] = str(THEOS)
        runner.run(f'bash -c "$(curl -fsSL {THEOS_INSTALLER})"', env=env, shell=True)
    if not (THEOS / "makefiles").is_dir():
        log("installer didn't finish, cloning Theos manually")
        if runner.run(["git", "clone", "--recursive", THEOS_REPO, str(THEOS)]) != 0:
            return False

    log("== 3/4 iOS SDKs ==")
    sdk_dir = THEOS / "sdks"
    if not (sdk_dir.is_dir() and any(sdk_dir.glob("*.sdk"))):
        shutil.rmtree(sdk_dir, ignore_errors=True)
        if runner.run(["git", "clone", "--depth=1", SDK_REPO, str(sdk_dir)]) != 0:
            return False

    log("== 4/4 ldid ==")
    if not which("ldid"):
        src = Path(tempfile.mkdtemp(prefix="ldid-"))
        prefix = str(Path.home() / ".local")
        steps = [
            ["git", "clone", "--depth=1", LDID_REPO, str(src)],
            ["make", f"-j{os.cpu_count() or 2}"],
            ["make", "install", f"PREFIX={prefix}"],
        ]
        for i, cmd in enumerate(steps):
            if runner.run(cmd, cwd=None if i == 0 else src) != 0:
                log("!! ldid build failed. Try the AUR: yay -S ldid-procursus")
                return False
        shutil.rmtree(src, ignore_errors=True)

    log("setup done")
    return True


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #
def build_zip(zip_path, out_dir, scheme="auto", archs="auto", target="auto", debug=False,
              jobs=None, keep=False, make_args=None, runner=None, log=print,
              status=None, info=None):
    """Returns list of produced .deb paths (empty on failure)."""
    runner = runner or Runner(log)
    status = status or (lambda m: None)
    info = info or (lambda **k: None)
    zip_path = Path(zip_path).expanduser()
    out_dir = Path(out_dir).expanduser()

    if not zip_path.is_file() or not zipfile.is_zipfile(zip_path):
        log(f"!! not a valid zip: {zip_path}")
        return []
    if not (THEOS / "makefiles").is_dir():
        log(f"!! Theos not found at {THEOS}. Run ./start.sh to set it up.")
        return []
    if scheme == "roothide":
        log("note: roothide needs the roothide fork of Theos (github.com/roothide/theos)")

    work = Path(tempfile.mkdtemp(prefix="tweakforge-"))
    try:
        status("Extracting source…")
        log(f"extracting {zip_path.name} ...")
        safe_extract(zip_path, work)
        root = find_project_root(work)
        if not root:
            log("!! no Makefile found in that zip - is it a Theos project?")
            return []
        log(f"project root: {root.relative_to(work) if root != work else '.'}")

        src = read_source_info(root)
        info(package=src.get("package", "—"), version=src.get("version", "—"),
             scheme=scheme if scheme != "auto" else (src.get("scheme_src") or "rootful (Theos default)"),
             archs=(ARCH_CHOICES.get(archs) if archs != "auto" else None) or src.get("archs_src") or "Theos default")

        started = time.time()
        extra = []
        if ARCH_CHOICES.get(archs):
            extra.append(f"ARCHS={ARCH_CHOICES[archs]}")
        if target not in (None, "", "auto"):
            extra.append(f"TARGET=iphone:clang:latest:{target}")
        cmd = ["make", f"-j{jobs or os.cpu_count() or 2}", "clean", "package"]
        if not debug:
            cmd.append("FINALPACKAGE=1")
        cmd += extra + list(make_args or [])

        status("Compiling and packaging…")
        rc = runner.run(cmd, cwd=root, env=build_env(scheme))
        if runner.cancelled:
            log("cancelled")
            return []
        if rc != 0:
            log(f"!! build failed (exit {rc})")
            return []

        pk = root / "packages"
        debs = [p for p in pk.glob("*.deb") if p.stat().st_mtime >= started - 5] if pk.is_dir() else []
        if not debs:
            log("!! build finished but no .deb was produced")
            return []
        out_dir.mkdir(parents=True, exist_ok=True)
        results = []
        for d in debs:
            dest = out_dir / d.name
            shutil.copy2(d, dest)
            results.append(dest)
            log(f"built: {dest}")
        return results
    except Exception as e:  # noqa: BLE001
        log(f"!! {e}")
        return []
    finally:
        if keep:
            log(f"kept work dir: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------- #
# web UI (local, 127.0.0.1 only)
# --------------------------------------------------------------------------- #
TOKEN = secrets.token_urlsafe(24)
JOBS = {}
BUILD_SLOT = threading.Semaphore(1)


class Job:
    def __init__(self, jid, filename):
        self.id = jid
        self.filename = filename
        self.state = "queued"
        self.message = "Waiting in queue…"
        self.lines = []
        self.lock = threading.Lock()
        self.created = time.time()
        self.started = None
        self.finished = None
        self.meta = {"package": "—", "version": "—", "scheme": "—", "archs": "—"}
        self.debs = []
        self.runner = Runner(self.log)

    def log(self, line):
        with self.lock:
            self.lines.append(line)

    def set_info(self, **kw):
        self.meta.update(kw)

    def elapsed(self):
        if not self.started:
            return 0
        return int((self.finished or time.time()) - self.started)

    def to_dict(self):
        return {"id": self.id, "state": self.state, "message": self.message,
                "elapsed": self.elapsed(), "debs": [d.name for d in self.debs], **self.meta}


def run_job(job, zip_path, opts):
    try:
        with BUILD_SLOT:
            if job.runner.cancelled:
                job.state, job.message = "cancelled", "Build cancelled."
                return
            job.state, job.started = "running", time.time()
            res = build_zip(zip_path, OUT_DIR, opts["scheme"], opts["archs"], opts["target"],
                            runner=job.runner, log=job.log,
                            status=lambda m: setattr(job, "message", m), info=job.set_info)
            job.debs = res
            if job.runner.cancelled:
                job.state, job.message = "cancelled", "Build cancelled."
            elif res:
                job.state, job.message = "complete", "Build finished successfully"
            else:
                job.state, job.message = "failed", "Build failed. Check the terminal output."
    finally:
        job.finished = job.finished or time.time()
        shutil.rmtree(Path(zip_path).parent, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "TweakForge"

    def log_message(self, *a):
        pass

    # -- helpers
    def _host_ok(self):
        return self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")

    def _send(self, code, body, ctype="application/json", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        if not self._host_ok() or self.headers.get("X-Token") != TOKEN:
            self._send(403, {"error": "forbidden"})
            return False
        return True

    def _job(self, jid):
        job = JOBS.get(jid)
        if not job:
            self._send(404, {"error": "no such job"})
        return job

    # -- routes
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            if not self._host_ok():
                return self._send(403, "forbidden", "text/plain")
            return self._send(200, PAGE.replace("__TOKEN__", TOKEN), "text/html; charset=utf-8")
        if not self._auth():
            return
        parts = u.path.strip("/").split("/")
        if u.path == "/api/status":
            p = problems()
            return self._send(200, {"ready": not p, "problems": p})
        if len(parts) >= 3 and parts[:2] == ["api", "jobs"]:
            job = self._job(parts[2])
            if not job:
                return
            sub = parts[3] if len(parts) > 3 else ""
            if sub == "":
                return self._send(200, job.to_dict())
            if sub == "log":
                off = int(parse_qs(u.query).get("offset", ["0"])[0])
                with job.lock:
                    chunk = job.lines[off:]
                return self._send(200, {"lines": chunk, "next": off + len(chunk)})
            if sub == "full-log":
                with job.lock:
                    text = "\n".join(job.lines) + "\n"
                return self._send(200, text, "text/plain; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="build.log"'})
            if sub == "deb" and job.debs:
                data = job.debs[0].read_bytes()
                return self._send(200, data, "application/vnd.debian.binary-package",
                                  {"Content-Disposition": f'attachment; filename="{job.debs[0].name}"'})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        u = urlparse(self.path)
        parts = u.path.strip("/").split("/")
        if u.path == "/api/jobs":
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            opts = {"scheme": q.get("scheme", "auto"), "archs": q.get("archs", "auto"),
                    "target": q.get("target", "auto")}
            if opts["scheme"] not in SCHEMES or opts["archs"] not in ARCH_CHOICES or \
                    not re.fullmatch(r"auto|\d+(\.\d+)?", opts["target"]):
                return self._send(400, {"error": "bad settings"})
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_UPLOAD:
                return self._send(400, {"error": "bad upload size"})
            tmp = Path(tempfile.mkdtemp(prefix="tweakforge-up-"))
            zpath = tmp / "source.zip"
            with open(zpath, "wb") as f:
                left = length
                while left:
                    chunk = self.rfile.read(min(1 << 20, left))
                    if not chunk:
                        break
                    f.write(chunk)
                    left -= len(chunk)
            if not zipfile.is_zipfile(zpath):
                shutil.rmtree(tmp, ignore_errors=True)
                return self._send(400, {"error": "that isn't a zip file"})
            job = Job(secrets.token_hex(6), self.headers.get("X-Filename", "source.zip")[:200])
            JOBS[job.id] = job
            threading.Thread(target=run_job, args=(job, zpath, opts), daemon=True).start()
            return self._send(200, {"id": job.id})
        if len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] == "cancel":
            job = self._job(parts[2])
            if job:
                job.runner.cancelled = True
                job.runner.cancel()
                return self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})


def serve(open_browser=True, port=8765):
    srv = make_server(port)
    if not srv:
        print("couldn't open a port")
        return 1
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"\nTweakForge is running at {url}\nPress Ctrl+C to quit.\n")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("bye")
    return 0


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<title>Tweak Builder</title>
<style>
:root{--bg:#0b0d12;--card:#141821;--line:#242a37;--text:#e8ebf2;--mute:#8b93a7;--acc:#4f8cff;--ok:#34c77b;--bad:#ff5c6c;--warn:#f5b84a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}
main{max-width:760px;margin:0 auto;padding:40px 20px 80px}
h1{font-size:30px;margin:0 0 6px;letter-spacing:-.02em}
.sub{color:var(--mute);margin:0 0 18px}
.pill{display:inline-flex;gap:10px;align-items:center;font-size:13px;color:var(--mute);margin-bottom:22px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--warn)}
.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}
.pill button{background:none;border:0;color:var(--acc);cursor:pointer;font:inherit;padding:0}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}
.card h2{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--mute);margin:0 0 12px;font-weight:600}
.drop{border:1.5px dashed var(--line);border-radius:12px;padding:26px;text-align:center;cursor:pointer;color:var(--mute);transition:.15s}
.drop:hover,.drop.over{border-color:var(--acc);color:var(--text);background:#4f8cff10}
.drop b{color:var(--text);display:block;margin-bottom:2px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
@media(max-width:620px){.grid{grid-template-columns:1fr}}
label{display:block;font-size:12px;color:var(--mute);margin-bottom:5px}
select{width:100%;background:#0e1118;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:10px;font:inherit}
.row{display:flex;gap:10px;margin-bottom:16px}
.btn{flex:1;border:0;border-radius:11px;padding:13px;font:inherit;font-weight:600;cursor:pointer;background:var(--acc);color:#fff}
.btn.sec{flex:0 0 auto;background:#1c2230;color:var(--text);border:1px solid var(--line);padding:13px 20px}
.btn:disabled{opacity:.4;cursor:not-allowed}
.status{display:flex;justify-content:space-between;align-items:center}
.status strong{font-size:16px}.time{color:var(--mute);font-variant-numeric:tabular-nums}
.bar{height:4px;background:#0e1118;border-radius:4px;overflow:hidden;margin:12px 0}
.bar i{display:block;height:100%;width:0;background:var(--acc);transition:width .3s}
.bar.run i{width:40%;animation:s 1.2s infinite ease-in-out}
@keyframes s{0%{margin-left:-40%}100%{margin-left:100%}}
.meta{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:6px}
@media(max-width:620px){.meta{grid-template-columns:repeat(2,1fr)}}
.meta span{display:block;font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em}
.meta div{font-size:13px;word-break:break-word}
.done{display:none;border-color:#34c77b55;background:#34c77b12}
.done.show{display:block}.done.fail{border-color:#ff5c6c55;background:#ff5c6c12}
.done h3{margin:0 0 10px;font-size:16px}
.done .row{margin:0}
pre{margin:0;background:#07090d;border-radius:10px;padding:14px;height:300px;overflow:auto;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#c8cfdd;white-space:pre-wrap;word-break:break-all}
.hint{color:var(--mute);font-size:12.5px;margin-top:22px}
code{background:#1c2230;padding:1px 6px;border-radius:5px}
</style></head><body><main>
<h1>Tweak Builder</h1>
<p class="sub">Drop a Theos source ZIP and build it right here on your machine. Nothing leaves your computer, and temporary files are deleted when the build finishes.</p>
<div class="pill"><span class="dot" id="dot"></span><span id="ptxt">Checking builder…</span><button id="retry">Retry</button></div>

<div class="card"><h2>Source File</h2>
<div class="drop" id="drop"><b id="fname">Tweak Source ZIP</b><span id="fsub">Click to choose, or drag a .zip here</span></div>
<input type="file" id="file" accept=".zip" hidden></div>

<div class="card"><h2>Build Settings</h2><div class="grid">
<div><label>Package Scheme</label><select id="scheme"><option value="auto">Auto detect</option><option value="rootful">Rootful</option><option value="rootless">Rootless</option><option value="roothide">Roothide</option></select></div>
<div><label>Architectures</label><select id="archs"><option value="auto">Auto / preserve source</option><option value="arm64+arm64e">arm64 + arm64e</option><option value="arm64">arm64 only</option><option value="arm64e">arm64e only</option></select></div>
<div><label>Deployment Target</label><select id="target"><option value="auto">Auto / preserve source</option><option value="14.0">iOS 14.0+</option><option value="15.0">iOS 15.0+</option><option value="16.0">iOS 16.0+</option></select></div>
</div></div>

<div class="row"><button class="btn" id="build" disabled>Build Tweak</button><button class="btn sec" id="cancel" disabled>Cancel Build</button></div>

<div class="card"><div class="status"><strong id="msg">Ready</strong><span class="time" id="time">0s</span></div>
<div class="bar" id="bar"><i></i></div>
<div class="meta"><div><span>Package</span><div id="m_package">—</div></div><div><span>Version</span><div id="m_version">—</div></div><div><span>Scheme</span><div id="m_scheme">—</div></div><div><span>Architectures</span><div id="m_archs">—</div></div></div></div>

<div class="card done" id="done"><h3 id="donetitle">Build finished successfully</h3>
<div class="row"><button class="btn" id="dl">Download .deb</button><button class="btn sec" id="dllog">Download full log</button></div></div>

<div class="card"><h2>Terminal output</h2><pre id="log">Waiting for build…</pre></div>
<p class="hint">Finished packages are also saved to <code>~/TweakForge-Output</code>. Only build source you trust, since a tweak's Makefile can run any command.</p>
</main>
<script>
const T="__TOKEN__", H={"X-Token":T}, $=id=>document.getElementById(id);
let file=null, job=null, off=0, timer=null;
const fmt=b=>b>1048576?(b/1048576).toFixed(1)+" MB":Math.max(1,Math.round(b/1024))+" KB";
async function check(){
  $("dot").className="dot";$("ptxt").textContent="Checking builder…";
  try{const r=await (await fetch("/api/status",{headers:H})).json();
    if(r.ready){$("dot").className="dot ok";$("ptxt").textContent="Builder ready";}
    else{$("dot").className="dot bad";$("ptxt").textContent="Setup needed: "+r.problems.join(", ")+" (run ./start.sh in a terminal)";}
  }catch(e){$("dot").className="dot bad";$("ptxt").textContent="Can't reach TweakForge";}
}
function pick(f){ if(!f)return; file=f; $("fname").textContent=f.name; $("fsub").textContent=fmt(f.size); $("build").disabled=false; }
$("drop").onclick=()=>$("file").click();
$("file").onchange=e=>pick(e.target.files[0]);
["dragover","dragenter"].forEach(ev=>$("drop").addEventListener(ev,e=>{e.preventDefault();$("drop").classList.add("over")}));
["dragleave","drop"].forEach(ev=>$("drop").addEventListener(ev,e=>{e.preventDefault();$("drop").classList.remove("over")}));
$("drop").addEventListener("drop",e=>pick(e.dataTransfer.files[0]));
$("retry").onclick=check;

async function download(url,name){
  const r=await fetch(url,{headers:H}); const b=await r.blob(); const a=document.createElement("a");
  a.href=URL.createObjectURL(b); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),2000);
}
$("build").onclick=async()=>{
  if(!file)return;
  $("build").disabled=true; $("cancel").disabled=false; $("done").className="card done";
  $("log").textContent=""; off=0;
  for(const k of ["package","version","scheme","archs"]) $("m_"+k).textContent="—";
  $("msg").textContent="Uploading…"; $("bar").className="bar run"; $("time").textContent="0s";
  const q=new URLSearchParams({scheme:$("scheme").value,archs:$("archs").value,target:$("target").value});
  try{
    const r=await fetch("/api/jobs?"+q,{method:"POST",headers:{...H,"X-Filename":file.name},body:file});
    const j=await r.json(); if(!r.ok) throw new Error(j.error||"upload failed");
    job=j.id; timer=setInterval(poll,1000); poll();
  }catch(e){ $("msg").textContent=e.message; $("bar").className="bar"; $("build").disabled=false; $("cancel").disabled=true; }
};
$("cancel").onclick=()=>{ if(job) fetch(`/api/jobs/${job}/cancel`,{method:"POST",headers:H}); $("cancel").disabled=true; };
async function poll(){
  const l=await (await fetch(`/api/jobs/${job}/log?offset=${off}`,{headers:H})).json();
  if(l.lines.length){const p=$("log"),stick=p.scrollTop+p.clientHeight>=p.scrollHeight-30;
    p.textContent+=l.lines.join("\n")+"\n"; off=l.next; if(stick)p.scrollTop=p.scrollHeight;}
  const s=await (await fetch(`/api/jobs/${job}`,{headers:H})).json();
  $("msg").textContent=s.message; $("time").textContent=s.elapsed+"s";
  for(const k of ["package","version","scheme","archs"]) $("m_"+k).textContent=s[k];
  if(["complete","failed","cancelled"].includes(s.state)){
    clearInterval(timer); $("bar").className="bar"; $("build").disabled=false; $("cancel").disabled=true;
    const d=$("done"); d.className="card done show"+(s.state==="complete"?"":" fail");
    $("donetitle").textContent=s.state==="complete"?"Build finished successfully":(s.state==="cancelled"?"Build cancelled":"Build failed");
    $("dl").style.display=s.state==="complete"?"":"none";
    $("dl").onclick=()=>download(`/api/jobs/${job}/deb`,s.debs[0]);
    $("dllog").onclick=()=>download(`/api/jobs/${job}/full-log`,"build.log");
  }
}
check();
</script></body></html>
"""


# --------------------------------------------------------------------------- #
# TUI (checkra1n-style terminal menu)
# --------------------------------------------------------------------------- #
BANNER_BIG = r"""
████████╗██╗    ██╗███████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
   ██║   ██║ █╗ ██║█████╗  ███████║█████╔╝ █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
   ██║   ██║███╗██║██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
   ██║   ╚███╔███╔╝███████╗██║  ██║██║  ██╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""
BANNER_MID = r"""
 _______        _______    _    _  _______ ___  ____   ____ _____
|_   _\ \      / / ____|  / \  | |/ /  ___/ _ \|  _ \ / ___| ____|
  | |  \ \ /\ / /|  _|   / _ \ | ' /| |_ | | | | |_) | |  _|  _|
  | |   \ V  V / | |___ / ___ \| . \|  _|| |_| |  _ <| |_| | |___
  |_|    \_/\_/  |_____/_/   \_\_|\_\_|   \___/|_| \_\\____|_____|
"""
BANNER_MINI = "T W E A K F O R G E"

CFG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "tweakforge.json"
IOS_CHOICES = ["auto", "12.0", "13.0", "14.0", "15.0", "16.0", "17.0", "custom"]
SCHEME_LABEL = {"auto": "Auto detect", "rootful": "Rootful", "rootless": "Rootless", "roothide": "Roothide"}
ARCH_LABEL = {"auto": "Auto / preserve source", "arm64+arm64e": "arm64 + arm64e", "arm64": "arm64 only", "arm64e": "arm64e only"}


def banner_lines(width, height):
    if width >= 88 and height >= 28:
        return BANNER_BIG.strip("\n").split("\n")
    if width >= 68 and height >= 24:
        return BANNER_MID.strip("\n").split("\n")
    return [BANNER_MINI]


def load_cfg():
    cfg = {"zip": "", "scheme": "auto", "archs": "auto", "ios": "auto", "debug": False, "out": str(OUT_DIR)}
    try:
        cfg.update(json.loads(CFG_PATH.read_text()))
    except (OSError, ValueError):
        pass
    if cfg["scheme"] not in SCHEMES:
        cfg["scheme"] = "auto"
    if cfg["archs"] not in ARCH_CHOICES:
        cfg["archs"] = "auto"
    return cfg


def save_cfg(cfg):
    try:
        CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CFG_PATH.write_text(json.dumps(cfg, indent=2))
    except OSError:
        pass


def cycle(options, current, step):
    i = options.index(current) if current in options else 0
    return options[(i + step) % len(options)]


def ios_label(v):
    return "Auto / preserve source" if v == "auto" else f"iOS {v}+"


class TUI:
    def __init__(self, scr):
        import curses
        self.c = curses
        self.scr = scr
        self.cfg = load_cfg()
        self.sel = 0
        self.note = ""
        self.web = None
        curses.curs_set(0)
        self.color = curses.has_colors()
        if self.color:
            curses.start_color()
            curses.use_default_colors()
            for i, col in enumerate((curses.COLOR_CYAN, curses.COLOR_GREEN, curses.COLOR_RED,
                                     curses.COLOR_YELLOW, curses.COLOR_BLUE), 1):
                curses.init_pair(i, col, -1)

    # -- drawing helpers
    def attr(self, name):
        c = self.c
        if not self.color:
            return {"hl": c.A_REVERSE, "dim": c.A_DIM, "bold": c.A_BOLD}.get(name, 0)
        return {"banner": c.color_pair(1) | c.A_BOLD, "ok": c.color_pair(2) | c.A_BOLD,
                "bad": c.color_pair(3) | c.A_BOLD, "warn": c.color_pair(4),
                "hl": c.color_pair(1) | c.A_REVERSE | c.A_BOLD, "dim": c.A_DIM,
                "bold": c.A_BOLD, "head": c.color_pair(5) | c.A_BOLD}.get(name, 0)

    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and x < w:
            try:
                self.scr.addstr(y, max(0, x), text[: max(0, w - x - 1)], attr)
            except self.c.error:
                pass

    def center(self, y, text, attr=0):
        _, w = self.scr.getmaxyx()
        self.put(y, max(0, (w - len(text)) // 2), text, attr)

    def draw_banner(self, tagline=True):
        h, w = self.scr.getmaxyx()
        y = 1
        for line in banner_lines(w, h):
            self.center(y, line, self.attr("banner"))
            y += 1
        if tagline:
            self.center(y, f"iOS jailbreak tweak builder  -  v{VERSION}", self.attr("dim"))
            y += 1
        return y + 1

    # -- prompts
    def prompt(self, title, initial=""):
        c, scr = self.c, self.scr
        buf = list(initial)
        c.curs_set(1)
        scr.timeout(-1)
        try:
            while True:
                scr.erase()
                self.draw_banner(False)
                h, w = scr.getmaxyx()
                self.put(h // 2 - 1, 4, title, self.attr("head"))
                text = "".join(buf)
                shown = text[-(w - 10):]
                self.put(h // 2 + 1, 4, "> " + shown)
                self.put(h - 2, 2, "Enter confirm   Esc cancel", self.attr("dim"))
                scr.move(h // 2 + 1, min(w - 2, 6 + len(shown)))
                scr.refresh()
                k = scr.getch()
                if k in (10, 13, c.KEY_ENTER):
                    return "".join(buf).strip()
                if k == 27:
                    return None
                if k in (c.KEY_BACKSPACE, 127, 8):
                    if buf:
                        buf.pop()
                elif 32 <= k < 256:
                    buf.append(chr(k))
        finally:
            c.curs_set(0)

    def pick_file(self):
        c, scr = self.c, self.scr
        cur = Path(self.cfg["zip"]).parent if self.cfg["zip"] and Path(self.cfg["zip"]).exists() else None
        if not cur:
            dl = Path.home() / "Downloads"
            cur = dl if dl.is_dir() else Path.home()
        idx, top = 0, 0
        scr.timeout(-1)
        while True:
            try:
                kids = sorted(cur.iterdir(), key=lambda p: p.name.lower())
            except OSError:
                kids = []
            dirs = [p for p in kids if p.is_dir() and not p.name.startswith(".")]
            zips = [p for p in kids if p.is_file() and p.suffix.lower() == ".zip"]
            entries = [("..  (go up)", cur.parent, True)] + [(p.name + "/", p, True) for p in dirs] + \
                      [(p.name, p, False) for p in zips]
            idx = max(0, min(idx, len(entries) - 1))
            scr.erase()
            h, w = scr.getmaxyx()
            self.put(1, 2, "Choose your tweak source .zip", self.attr("head"))
            self.put(2, 2, str(cur), self.attr("dim"))
            rows = max(3, h - 7)
            top = max(0, min(top, idx), idx - rows + 1)
            for r, (label, p, isdir) in enumerate(entries[top: top + rows]):
                real = top + r
                a = self.attr("hl") if real == idx else (self.attr("bold") if not isdir else 0)
                self.put(4 + r, 2, ("  " + label).ljust(min(w - 5, 70)), a)
            if not zips:
                self.put(h - 4, 2, "no .zip files in this folder", self.attr("warn"))
            self.put(h - 2, 2, "Up/Down move   Enter open/select   Backspace up   / type a path   Esc back", self.attr("dim"))
            scr.refresh()
            k = scr.getch()
            if k in (c.KEY_UP, ord("k")):
                idx -= 1
            elif k in (c.KEY_DOWN, ord("j")):
                idx += 1
            elif k == c.KEY_PPAGE:
                idx -= rows
            elif k == c.KEY_NPAGE:
                idx += rows
            elif k in (c.KEY_BACKSPACE, 127, 8):
                cur, idx = cur.parent, 0
            elif k == ord("/"):
                p = self.prompt("Type or paste the path to your .zip (or a folder)", "")
                if p:
                    p = Path(p.strip("'\" ")).expanduser()
                    if not p.is_absolute():
                        p = cur / p
                    if p.is_file():
                        return str(p)
                    if p.is_dir():
                        cur, idx = p, 0
            elif k in (10, 13, c.KEY_ENTER, c.KEY_RIGHT):
                _, p, isdir = entries[idx]
                if isdir:
                    cur, idx = p, 0
                else:
                    return str(p)
            elif k in (27, c.KEY_LEFT):
                return None
            elif k == c.KEY_RESIZE:
                pass

    # -- main menu
    def items(self):
        cfg = self.cfg
        z = cfg["zip"]
        zshow = (Path(z).name if z else "-- choose a .zip --")
        ios = cfg["ios"]
        return [
            ("Source ZIP", zshow, "file"),
            ("Package scheme", SCHEME_LABEL[cfg["scheme"]], "choice"),
            ("Architectures", ARCH_LABEL[cfg["archs"]], "choice"),
            ("iOS version", ios_label(ios) if ios in IOS_CHOICES else f"iOS {ios}+", "choice"),
            ("Debug build", "ON" if cfg["debug"] else "off", "choice"),
            ("Output folder", cfg["out"], "text"),
            None,
            ("BUILD TWEAK", "", "build"),
            ("Setup / repair Theos", "", "setup"),
            ("Open web UI", "", "web"),
            ("Quit", "", "quit"),
        ]

    def draw_main(self):
        scr = self.scr
        scr.erase()
        h, w = scr.getmaxyx()
        y = self.draw_banner()
        p = problems()
        status = ("Builder ready" if not p else "Setup needed: " + ", ".join(p))
        self.center(y, ("● " if not p else "○ ") + status, self.attr("ok" if not p else "warn"))
        y += 2
        items = self.items()
        width = min(w - 4, 62)
        x = max(2, (w - width) // 2)
        for i, it in enumerate(items):
            if it is None:
                y += 1
                continue
            label, val, kind = it
            is_sel = (i == self.sel)
            if kind in ("build", "setup", "web", "quit"):
                text = f"  {'▶ ' if kind == 'build' else '  '}{label}".ljust(width)
                a = self.attr("hl") if is_sel else (self.attr("ok") if kind == "build" else 0)
            else:
                arrows = "‹ {} ›" if kind == "choice" else "[ {} ]"
                maxv = width - 22
                v = val if len(val) <= maxv else "…" + val[-(maxv - 1):]
                text = f"  {label:<18}{arrows.format(v)}".ljust(width)
                a = self.attr("hl") if is_sel else 0
            self.put(y, x, text, a)
            y += 1
        y += 1
        if self.note:
            self.center(min(y, h - 3), self.note, self.attr("warn"))
        if self.web:
            self.center(min(y + 1, h - 3), f"Web UI running at {self.web}", self.attr("ok"))
        self.center(h - 2, "Up/Down move   Left/Right change   Enter select   B build   Q quit", self.attr("dim"))
        scr.refresh()

    def selectable(self):
        return [i for i, it in enumerate(self.items()) if it is not None]

    def change(self, step):
        cfg, kind = self.cfg, self.items()[self.sel][2]
        label = self.items()[self.sel][0]
        if label == "Package scheme":
            cfg["scheme"] = cycle(SCHEMES, cfg["scheme"], step)
        elif label == "Architectures":
            cfg["archs"] = cycle(list(ARCH_CHOICES), cfg["archs"], step)
        elif label == "iOS version":
            nxt = cycle(IOS_CHOICES, cfg["ios"] if cfg["ios"] in IOS_CHOICES else "custom", step)
            if nxt == "custom":
                v = self.prompt("Custom iOS deployment target (e.g. 15.4)", "" if cfg["ios"] in IOS_CHOICES else cfg["ios"])
                if v and re.fullmatch(r"\d+(\.\d+)?", v):
                    cfg["ios"] = v
                else:
                    cfg["ios"] = "auto"
                    self.note = "Custom version must look like 15.4"
            else:
                cfg["ios"] = nxt
        elif label == "Debug build":
            cfg["debug"] = not cfg["debug"]
        save_cfg(cfg)

    def activate(self):
        label, _, kind = self.items()[self.sel]
        self.note = ""
        if kind == "file":
            p = self.pick_file()
            if p:
                self.cfg["zip"] = p
                save_cfg(self.cfg)
        elif kind == "choice":
            self.change(1)
        elif kind == "text":
            v = self.prompt("Where should the .deb go?", self.cfg["out"])
            if v:
                self.cfg["out"] = str(Path(v).expanduser())
                save_cfg(self.cfg)
        elif kind == "build":
            self.build_screen()
        elif kind == "setup":
            self.run_setup()
        elif kind == "web":
            self.start_web()
        elif kind == "quit":
            return False
        return True

    def run_setup(self):
        self.c.endwin()
        print("\n=== TweakForge setup (sudo password may be needed) ===\n")
        ok = setup(Runner(print))
        input("\n" + ("Done." if ok else "Setup hit an error.") + " Press Enter to go back...")
        self.scr.refresh()

    def start_web(self):
        if self.web:
            webbrowser.open(self.web)
            return
        srv = make_server()
        if not srv:
            self.note = "Couldn't open a port for the web UI"
            return
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.web = f"http://127.0.0.1:{srv.server_address[1]}/"
        webbrowser.open(self.web)

    def build_screen(self):
        cfg, c, scr = self.cfg, self.c, self.scr
        if not cfg["zip"] or not Path(cfg["zip"]).is_file():
            self.note = "Pick a source .zip first"
            self.sel = 0
            return
        p = problems()
        if p:
            self.note = "Setup needed first (" + ", ".join(p) + ")"
            self.sel = [i for i, it in enumerate(self.items()) if it and it[2] == "setup"][0]
            return

        lines, lock = [], threading.Lock()
        state = {"msg": "Starting…", "done": False, "result": [], "t0": time.time(), "t1": None,
                 "meta": {"package": "-", "version": "-", "scheme": "-", "archs": "-"}}

        def log(line):
            with lock:
                lines.append(line)

        runner = Runner(log)

        def work():
            state["result"] = build_zip(
                cfg["zip"], cfg["out"], cfg["scheme"], cfg["archs"], cfg["ios"], cfg["debug"],
                runner=runner, log=log, status=lambda m: state.update(msg=m),
                info=lambda **k: state["meta"].update(k))
            state["t1"] = time.time()
            state["done"] = True

        threading.Thread(target=work, daemon=True).start()
        spin = "|/-\\"
        n = 0
        scr.timeout(150)
        while True:
            scr.erase()
            h, w = scr.getmaxyx()
            y = 1
            self.center(y, BANNER_MINI, self.attr("banner"))
            y += 2
            m = state["meta"]
            self.put(y, 2, f"Package: {m['package']}   Version: {m['version']}", self.attr("bold"))
            self.put(y + 1, 2, f"Scheme: {m['scheme']}   Archs: {m['archs']}   Target: {ios_label(cfg['ios'])}", self.attr("dim"))
            y += 3
            el = int((state["t1"] or time.time()) - state["t0"])
            if not state["done"]:
                self.put(y, 2, f"{spin[n % 4]} {state['msg']}   {el}s", self.attr("head"))
            elif runner.cancelled:
                self.put(y, 2, f"■ Build cancelled   {el}s", self.attr("warn"))
            elif state["result"]:
                self.put(y, 2, f"✔ Build finished successfully   {el}s", self.attr("ok"))
            else:
                self.put(y, 2, f"✖ Build failed   {el}s", self.attr("bad"))
            y += 1
            if state["done"] and state["result"]:
                self.put(y, 2, "→ " + str(state["result"][0]), self.attr("ok"))
            y += 1
            self.put(y, 2, "─" * max(0, w - 5), self.attr("dim"))
            y += 1
            rows = max(1, h - y - 3)
            with lock:
                tail = lines[-rows:]
            for i, ln in enumerate(tail):
                self.put(y + i, 2, ln.replace("\t", "    "))
            foot = "C cancel build" if not state["done"] else "Enter back   O open output folder   L save full log"
            self.center(h - 2, foot, self.attr("dim"))
            scr.refresh()
            n += 1
            k = scr.getch()
            if not state["done"]:
                if k in (ord("c"), ord("C")):
                    runner.cancel()
            else:
                if k in (10, 13, c.KEY_ENTER, 27, ord("q")):
                    break
                if k in (ord("o"), ord("O")):
                    subprocess.Popen(["xdg-open", cfg["out"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if k in (ord("l"), ord("L")):
                    try:
                        Path(cfg["out"]).mkdir(parents=True, exist_ok=True)
                        (Path(cfg["out"]) / "build.log").write_text("\n".join(lines) + "\n")
                        log("log saved to " + str(Path(cfg["out"]) / "build.log"))
                    except OSError as e:
                        log(f"couldn't save log: {e}")
        scr.timeout(-1)
        self.note = "Last build: " + ("done" if state["result"] else ("cancelled" if runner.cancelled else "failed"))

    def loop(self):
        c, scr = self.c, self.scr
        scr.timeout(-1)
        sel_ok = self.selectable()
        self.sel = sel_ok[0]
        while True:
            self.draw_main()
            k = scr.getch()
            sel_ok = self.selectable()
            pos = sel_ok.index(self.sel)
            if k in (c.KEY_UP, ord("k")):
                self.sel = sel_ok[(pos - 1) % len(sel_ok)]
            elif k in (c.KEY_DOWN, ord("j"), 9):
                self.sel = sel_ok[(pos + 1) % len(sel_ok)]
            elif k == c.KEY_LEFT:
                self.change(-1) if self.items()[self.sel][2] == "choice" else None
            elif k == c.KEY_RIGHT:
                self.change(1) if self.items()[self.sel][2] == "choice" else None
            elif k in (10, 13, 32, c.KEY_ENTER):
                if not self.activate():
                    return
            elif k in (ord("b"), ord("B")):
                self.sel = [i for i, it in enumerate(self.items()) if it and it[2] == "build"][0]
                self.activate()
            elif k in (ord("q"), ord("Q")):
                return


def make_server(port=8765):
    for p in range(port, port + 20):
        try:
            return ThreadingHTTPServer(("127.0.0.1", p), Handler)
        except OSError:
            continue
    return None


def run_tui():
    import curses
    import locale
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("TweakForge's menu needs a real terminal. Try: tweakforge.py build --help")
        return 1
    locale.setlocale(locale.LC_ALL, "")
    p = problems()
    if p:
        print(BANNER_MID)
        print("Missing: " + ", ".join(p))
        ans = input("\nInstall everything now? (needs sudo once) [Y/n] ").strip().lower()
        if ans in ("", "y", "yes"):
            if not setup(Runner(print)):
                input("\nSetup hit an error. Press Enter to open the menu anyway...")
        else:
            time.sleep(0.3)
    os.environ.setdefault("ESCDELAY", "25")
    curses.wrapper(lambda scr: TUI(scr).loop())
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def cmd_start(no_browser=False):
    if problems():
        print("First run: setting things up (you'll be asked for your sudo password)...\n")
        if not setup(Runner(print)):
            print("\nSetup didn't finish. Fix the error above and run ./start.sh again.")
            return 1
    return serve(open_browser=not no_browser)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tweakforge", description="Build iOS jailbreak tweaks from a source .zip")
    ap.add_argument("--version", action="version", version=f"tweakforge {VERSION}")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("tui", help="open the terminal menu (default)")
    st = sub.add_parser("web", help="open the web UI instead")
    st.add_argument("--no-browser", action="store_true")

    b = sub.add_parser("build", help="build a tweak from a .zip")
    b.add_argument("zip")
    b.add_argument("-o", "--out", default=".", help="output folder for the .deb (default: current dir)")
    b.add_argument("-s", "--scheme", choices=SCHEMES, default="auto")
    b.add_argument("-a", "--archs", choices=list(ARCH_CHOICES), default="auto")
    b.add_argument("-t", "--target", default="auto", help="iOS deployment target, e.g. 15.0")
    b.add_argument("--debug", action="store_true", help="debug build (skip FINALPACKAGE=1)")
    b.add_argument("-j", "--jobs", type=int)
    b.add_argument("--keep", action="store_true", help="keep the temp work dir")
    b.add_argument("make_args", nargs="*", help="extra make args after --")

    sub.add_parser("setup", help="install deps, Theos, SDKs, ldid")
    sub.add_parser("doctor", help="check your setup")

    args = ap.parse_args(argv)
    if args.cmd in (None, "tui"):
        return run_tui()
    if args.cmd == "web":
        return cmd_start(getattr(args, "no_browser", False))
    if args.cmd == "doctor":
        return 0 if doctor() else 1
    if args.cmd == "setup":
        return 0 if setup(Runner(print)) else 1
    if args.cmd == "build":
        runner = Runner(print)
        try:
            res = build_zip(args.zip, args.out, args.scheme, args.archs, args.target, args.debug,
                            args.jobs, args.keep, args.make_args, runner=runner)
        except KeyboardInterrupt:
            runner.cancel()
            return 130
        return 0 if res else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
