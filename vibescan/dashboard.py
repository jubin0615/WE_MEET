"""Loopback dashboard for saved results and explicit local repository scans."""

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import webbrowser
from contextlib import asynccontextmanager, closing
from datetime import timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from scanner.ingest import git
from scanner.models import ScanResult
from . import hook
from .cli import STAGES, ScanInputError, scan
from .login import login
from .register import data_dir
from .session import logout, status

ASSETS = Path(__file__).with_name("web")
GITHUB = re.compile(r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?")


def run_git(*args, cwd=None):
    # No prompts: private repos rely on the PC's existing Git credentials (SSH key or credential helper).
    subprocess.run(["git", *args], cwd=cwd, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=300, env=os.environ | {"GIT_TERMINAL_PROMPT": "0"})


class RepoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=4096)


class ScanInput(RepoInput):
    offline: bool = Field(default=True, strict=True)


class HookInput(RepoInput):
    enabled: bool = Field(strict=True)


class SettingsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    background_llm: bool = Field(strict=True)


def dashboard_app(results: Path, address: str, ticket: str, directory: Path | None = None):
    root = results.expanduser().resolve()
    directory = (directory or data_dir()).expanduser().resolve()
    database = directory / "scan-history.sqlite3"
    clones = directory / "github"
    folders = directory / "folders"
    lock = threading.Lock()
    cloning = threading.Lock()
    job = {"state": "idle"}
    sign_in = {"state": "idle"}
    worker = None

    @asynccontextmanager
    async def lifespan(app):
        yield
        if worker is not None:
            await asyncio.to_thread(worker.join)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    def repository(raw):
        try:
            path = Path(raw).expanduser().resolve()
            exists = path.is_dir()
        except (ValueError, OSError):
            exists = False
        if not exists:
            raise HTTPException(422, "폴더를 찾을 수 없습니다. 경로가 맞는지 확인하세요.")
        try:
            top = Path(os.fsdecode(git(path, "rev-parse", "--show-toplevel").rstrip(b"\r\n"))).resolve()
            commit = git(path, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
            branch = git(path, "rev-parse", "--abbrev-ref", "HEAD").decode().strip()
        except (ValueError, OSError, subprocess.TimeoutExpired):
            raise HTTPException(422, "Git 저장소가 아니거나 커밋이 없습니다. git init 후 첫 커밋을 만드세요.") from None
        if path != top:
            raise HTTPException(422, f"저장소의 하위 폴더입니다. 저장소 루트를 지정하세요: {top}")
        if root.is_relative_to(path) or directory.is_relative_to(path):
            raise HTTPException(422, "결과·설정 폴더가 이 저장소 안에 있습니다. 저장소 밖의 폴더를 사용하세요.")
        return {"path": str(path), "name": path.name, "commit": commit,
                "branch": None if branch == "HEAD" else branch}

    def connected():
        return hook.connected(database)

    def hook_state(path):
        if Path(path).is_relative_to(clones) or Path(path).is_relative_to(folders):
            return None  # VibeScan's own clones and folder snapshots get no commits, so a hook would never fire
        try:
            return hook.installed(Path(path))
        except (ValueError, OSError, subprocess.TimeoutExpired):
            return False

    @app.get("/api/repos")
    def repos():
        try:
            return {"repos": [{"path": path, "name": Path(path).name, "hook": hook_state(path)} for path in connected()]}
        except (OSError, sqlite3.Error):
            raise HTTPException(503, "연결된 레포 목록을 읽을 수 없습니다.") from None

    @app.post("/api/hook")
    def set_hook(body: HookInput):
        repo = repository(body.path)
        try:
            if repo["path"] not in connected():
                raise HTTPException(404, "먼저 레포를 연결하세요.")
        except (OSError, sqlite3.Error):
            raise HTTPException(503, "레포 연결 정보를 읽을 수 없습니다.") from None
        if hook_state(repo["path"]) is None:
            raise HTTPException(422, "GitHub 주소로 연결한 레포는 이 PC에서 커밋하지 않으므로 자동 스캔을 설치하지 않습니다.")
        try:
            (hook.install if body.enabled else hook.uninstall)(Path(repo["path"]))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        except (OSError, subprocess.TimeoutExpired):
            raise HTTPException(503, "hook 파일을 쓸 수 없습니다. 저장소 폴더 권한을 확인하세요.") from None
        return {"path": repo["path"], "hook": hook_state(repo["path"])}

    @app.get("/api/latest")
    def latest():
        # Cheap poll: newest result folder by modification time, so the page can notice hook scans.
        try:
            folders = [f for f in root.iterdir() if (f / "scan_result.json").is_file()] if root.exists() else []
            newest = max(folders, key=lambda f: f.stat().st_mtime, default=None)
        except OSError:
            raise HTTPException(503, "결과 폴더에 접근할 수 없습니다.") from None
        return {"scan_id": newest.name if newest else None}

    def clone(url):
        match = GITHUB.fullmatch(url)
        if not match or match[2] in (".", ".."):
            raise HTTPException(422, "GitHub 주소는 https://github.com/소유자/저장소 형식이어야 합니다.")
        dest = clones / match[1] / match[2]
        if dest.exists():
            return dest  # only complete clones are moved here; rescans fetch the latest commit
        if not cloning.acquire(blocking=False):
            raise HTTPException(409, "다른 저장소를 복제하는 중입니다. 완료 후 다시 시도하세요.")
        # Clone beside the target (owners cannot start with "."), so an interrupted clone never looks finished.
        staging = clones / ".partial" / match[1] / match[2]
        try:
            if staging.exists():
                shutil.rmtree(staging)
            staging.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            run_git("clone", "--depth", "1", "--no-tags", "--", url, str(staging))
            try:
                run_git("rev-parse", "--verify", "--quiet", "HEAD^{commit}", cwd=staging)
            except subprocess.CalledProcessError:
                raise HTTPException(422, "커밋이 없는 빈 저장소입니다. 첫 커밋을 push한 뒤 다시 연결하세요.") from None
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            staging.rename(dest)
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "복제 시간(5분)이 초과되었습니다. 저장소 크기와 네트워크를 확인하세요.") from None
        except (subprocess.CalledProcessError, OSError):
            raise HTTPException(422, "GitHub 저장소를 복제하지 못했습니다. 주소와 네트워크를 확인하세요. "
                                     "비공개 저장소는 이 PC의 Git 인증(SSH 키·자격 증명)이 필요합니다.") from None
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            cloning.release()
        return dest

    def snapshot_folder(dest, source=None):
        """Record a scan marker. Plain folder contents never enter the managed Git index."""
        if source is None:
            # Git stores the path as UTF-8; reading it in the Windows locale breaks paths like "바탕 화면".
            source = git(dest, "config", "vibescan.source").decode("utf-8").strip()
        else:
            run_git("init", "-q", str(dest))
            run_git("config", "vibescan.source", str(source), cwd=dest)
        if not Path(source).is_dir():
            raise FileNotFoundError(source)
        # Older managed snapshots may have tracked raw files. Start every new tree empty.
        run_git("read-tree", "--empty", cwd=dest)
        run_git("-c", "user.name=VibeScan", "-c", "user.email=vibescan@localhost", "-c", "commit.gpgsign=false",
                "commit", "-q", "--allow-empty", "-m", "VibeScan folder scan", cwd=dest)
        return Path(source)

    def plain_folder(raw):
        """A folder outside any Git repository gets a VibeScan-managed snapshot; anything else is returned as is."""
        try:
            path = Path(raw).expanduser().resolve()
            if not path.is_dir():
                return raw
            git(path, "rev-parse", "--is-inside-work-tree")
            return raw
        except ValueError:  # not inside a Git work tree
            pass
        except OSError:
            return raw
        if root.is_relative_to(path) or directory.is_relative_to(path):
            raise HTTPException(422, "결과·설정 폴더가 이 폴더 안에 있습니다. 프로젝트 폴더만 지정하세요.")
        dest = folders / f"{path.name}-{hashlib.sha256(str(path).encode()).hexdigest()[:8]}"
        if (dest / ".git").is_dir():
            return dest  # already connected; rescans take a fresh snapshot
        try:
            folders.mkdir(mode=0o700, parents=True, exist_ok=True)
            snapshot_folder(dest, path)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            shutil.rmtree(dest, ignore_errors=True)
            raise HTTPException(422, "폴더의 파일을 읽어 스냅샷을 만들지 못했습니다. 폴더 접근 권한을 확인하세요.") from None
        return dest

    @app.post("/api/repos")
    def connect_repo(body: RepoInput):
        raw = body.path.strip()
        repo = repository(clone(raw) if raw.startswith(("https://", "http://", "git@")) else plain_folder(raw))
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("CREATE TABLE IF NOT EXISTS connected_repos(path TEXT PRIMARY KEY NOT NULL)")
                db.execute("INSERT OR IGNORE INTO connected_repos VALUES (?)", (repo["path"],))
        except (OSError, sqlite3.Error):
            raise HTTPException(503, "레포 연결을 저장할 수 없습니다.") from None
        return repo

    def run_scan(repo, offline):
        nonlocal job
        try:
            if Path(repo).is_relative_to(clones):
                # VibeScan owns these clones, so a hard reset to the remote HEAD discards nothing of the user's.
                # Keep commit ancestry available for branch-aware scan comparisons.
                run_git("fetch", "--no-tags", "origin", "HEAD", cwd=repo)
                run_git("reset", "--hard", "--quiet", "FETCH_HEAD", cwd=repo)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            with lock:
                job = {"state": "failed", "repo": repo, "message": "GitHub에서 최신 커밋을 가져오지 못했습니다. "
                       "네트워크와 저장소 접근 권한을 확인하세요. 기존 결과는 유지됩니다."}
            return
        options = {}
        try:
            if Path(repo).is_relative_to(folders):
                options["folder_source"] = snapshot_folder(Path(repo))
        except Exception:
            # Anything escaping here would kill the thread and leave the job "running" forever.
            with lock:
                job = {"state": "failed", "repo": repo, "message": "원본 폴더를 읽지 못했습니다. 폴더가 옮겨졌거나 "
                       "삭제되지 않았는지 확인하세요. 기존 결과는 유지됩니다."}
            return
        def report(stage, text):
            with lock:
                job.update(stage=stage, log=(job.get("log", []) + [text])[-30:])

        try:
            folder, note, issue = scan(Path(repo), root, directory, offline=offline, progress=report, **options)
            completed = {"state": "completed", "repo": repo, "scan_id": folder.name, "message": note, "issue": issue}
        except subprocess.TimeoutExpired:
            completed = {"state": "failed", "repo": repo, "message": "검사 시간이 초과되었습니다. 기존 결과는 유지됩니다."}
        except ScanInputError as exc:
            completed = {"state": "failed", "repo": repo, "message": f"{exc} 기존 결과는 유지됩니다."}
        except Exception:
            # Engine/provider exceptions must not expose source text or credentials through HTTP.
            completed = {"state": "failed", "repo": repo,
                         "message": "스캔에 실패했습니다. Git 저장소·Semgrep 설치·저장 경로를 확인하세요. 기존 결과는 유지됩니다."}
        with lock:
            job = completed | {"log": job.get("log", [])}

    @app.post("/api/scan", status_code=202)
    def start_scan(body: ScanInput):
        nonlocal job, worker
        # shortcut: one scan per dashboard process; use a DB lease if multiple servers are supported.
        with lock:
            if job["state"] == "running":
                raise HTTPException(409, "이미 스캔 중입니다. 완료 후 다시 실행하세요.")
            repo = repository(body.path)
            try:
                if repo["path"] not in connected():
                    raise HTTPException(404, "먼저 레포를 연결하세요.")
            except (OSError, sqlite3.Error):
                raise HTTPException(503, "레포 연결 정보를 읽을 수 없습니다.") from None
            job = {"state": "running", "repo": repo["path"], "offline": body.offline, "stage": 0, "log": []}
            worker = threading.Thread(target=run_scan, args=(repo["path"], body.offline))
            try:
                worker.start()
            except RuntimeError:
                worker = None
                job = {"state": "failed", "message": "스캔을 시작할 수 없습니다. 다시 시도하세요."}
                raise HTTPException(503, job["message"]) from None
            return dict(job)

    @app.get("/api/scan")
    def scan_status():
        with lock:
            state = dict(job)
        return state | {"stages": STAGES, "hook": live_hook()}

    def live_hook():
        """A commit hook's scan in progress, written by that background process."""
        try:
            data = json.loads((directory / "live.json").read_text(encoding="utf-8"))
            # A crashed hook leaves its file behind; ten quiet minutes means it is gone.
            if time.time() - data.get("updated", data["started"]) < 600 and data["repo"] in connected():
                return {key: data[key] for key in ("repo", "commit", "stage", "log")}
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
            pass
        return None

    @app.get("/api/settings")
    def get_settings():
        return hook.settings(directory)

    @app.post("/api/settings")
    def set_settings(body: SettingsInput):
        try:
            return hook.save_settings(directory, background_llm=body.background_llm)
        except OSError:
            raise HTTPException(503, "설정을 저장할 수 없습니다.") from None

    def run_login():
        nonlocal sign_in

        def in_dashboard_tab(url):
            # The dashboard tab navigates here itself, so no second browser tab is opened.
            with lock:
                sign_in["url"] = url
            return True

        try:
            done = {"state": "completed", "message": login(directory, in_dashboard_tab, f"http://{address}/")}
        except RuntimeError as exc:
            # login() and SessionError messages are written by VibeScan and hold no tokens.
            done = {"state": "failed", "message": str(exc)}
        except Exception:
            done = {"state": "failed", "message": "로그인에 실패했습니다. 다시 시도하세요."}
        with lock:
            sign_in = done

    @app.get("/api/auth")
    def auth():
        try:
            state = status(directory)
        except Exception:
            # Unreadable or undecryptable session files must not leak details over HTTP.
            state = {"state": "login", "message": "로그인 정보를 읽을 수 없습니다. 다시 로그인하세요."}
        with lock:
            return state | {"login": dict(sign_in)}

    @app.post("/api/logout")
    def sign_out():
        with lock:
            if sign_in["state"] == "running":
                raise HTTPException(409, "로그인 진행 중에는 로그아웃할 수 없습니다.")
        try:
            logout(directory)
        except Exception:
            raise HTTPException(503, "로그아웃하지 못했습니다. 다시 시도하세요.") from None
        return auth()

    @app.post("/api/login", status_code=202)
    def start_login():
        nonlocal sign_in
        with lock:
            if sign_in["state"] == "running":
                raise HTTPException(409, "이미 로그인 창이 열려 있습니다. 브라우저에서 승인을 마치세요.")
            sign_in = {"state": "running",
                       "message": "브라우저에서 ChatGPT 로그인과 구독 사용 승인을 진행하세요. 5분 안에 완료해야 합니다."}
            # Daemon: an abandoned login window must not keep the dashboard from exiting.
            threading.Thread(target=run_login, daemon=True).start()
            return dict(sign_in)

    @app.middleware("http")
    async def local_only(request, call_next):
        origin = request.headers.get("origin")
        if request.headers.get("host") != address:
            response = PlainTextResponse("Invalid host", 400)
        elif origin is not None and origin != f"http://{address}":
            response = PlainTextResponse("Invalid origin", 403)
        elif request.url.path.startswith("/api/") and not secrets.compare_digest(
            request.headers.get("x-vibescan-token", "").encode(), ticket.encode()
        ):
            response = PlainTextResponse("대시보드를 실행한 창에서 다시 접속하세요.", 403)
        else:
            response = await call_next(request)
        response.headers.update({
            "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
                                       "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        })
        return response

    def read_result(scan_id):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", scan_id):
            raise HTTPException(404, "결과를 찾을 수 없습니다.")
        path = root / scan_id / "scan_result.json"
        if path.resolve() != path or not path.is_file():
            raise HTTPException(404, "결과 파일이 없거나 허용된 폴더 밖에 있습니다.")
        try:
            # shortcut: the first listing per dashboard process parses every result; index summaries in SQLite if startup slows.
            with path.open("rb") as file:
                raw = file.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise ValueError("Result too large")
            result = ScanResult.from_json(raw.decode("utf-8"))
            if result.scan_id != scan_id:
                raise ValueError("Mismatched scan ID")
            data = result.to_dict()
            data["scanned_at"] = result.scanned_at.astimezone(timezone.utc).isoformat()
            return data
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            raise HTTPException(422, "결과 파일을 읽을 수 없습니다. JSON 형식과 파일 크기를 확인하세요.") from None

    @app.get("/")
    def index():
        return FileResponse(ASSETS / "index.html")

    @app.get("/assets/{name:path}")
    def asset(name: str):
        if name not in ("dashboard.css", "dashboard.js", "meet-vibescan.svg",
                        "fonts/PretendardVariable.woff2", "fonts/OFL.txt"):
            raise HTTPException(404)
        return FileResponse(ASSETS / name)

    summaries = {}  # folder name -> ((mtime, size) of its result file, list row or None when unreadable)

    @app.get("/api/scans")
    def scans():
        nonlocal summaries
        rows, unavailable, seen = [], 0, {}
        try:
            folders = list(root.iterdir()) if root.exists() else []
            for folder in folders:
                try:
                    stat = (folder / "scan_result.json").stat()
                except OSError:
                    continue  # not a result: a scan still being written, or an unrelated folder
                # Every commit adds a result, so parse each file once and reuse it until it changes.
                key = (stat.st_mtime_ns, stat.st_size)
                cached = summaries.get(folder.name)
                if not cached or cached[0] != key:
                    try:
                        data = read_result(folder.name)
                        cached = key, {k: data[k] for k in ("scan_id", "repo", "commit", "scanned_at",
                                                          "risk_score", "summary", "trigger")}
                    except HTTPException:
                        cached = key, None
                seen[folder.name] = cached
                if cached[1] is None:
                    unavailable += 1
                else:
                    rows.append(cached[1])
        except OSError:
            raise HTTPException(503, "결과 폴더에 접근할 수 없습니다.") from None
        summaries = seen
        rows.sort(key=lambda row: (row["scanned_at"], row["scan_id"]), reverse=True)
        return {"scans": rows, "unavailable": unavailable, "results_path": str(root)}

    @app.get("/api/scans/{scan_id}")
    def detail(scan_id: str):
        return read_result(scan_id)

    return app


def serve(results: Path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        address = f"127.0.0.1:{sock.getsockname()[1]}"
        ticket = secrets.token_urlsafe(32)
        app = dashboard_app(results, address, ticket)
        url = f"http://{address}/#{ticket}"

        def open_browser():
            print(f"meet vibescan 대시보드: {url}\n종료: Ctrl+C", flush=True)
            webbrowser.open(url)

        # The socket is already listening, so early browser requests can wait for startup.
        server = uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="warning", proxy_headers=False))
        timer = threading.Timer(0.5, open_browser)
        timer.start()
        try:
            server.run(sockets=[sock])
        finally:
            timer.cancel()

