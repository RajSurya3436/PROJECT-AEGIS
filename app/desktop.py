"""Desktop launcher: runs the copilot in its own window instead of a browser tab.

    .venv\\Scripts\\pythonw.exe app\\desktop.py      (no console window)
    .venv\\Scripts\\python.exe  app\\desktop.py      (shows the log in the console)

It starts the Streamlit server on 127.0.0.1 (reusing one that is already running), waits until
it answers, then opens a window:

1. pywebview, if installed (``pip install pywebview``): a native window using Edge WebView2.
2. Otherwise Microsoft Edge or Chrome in app mode (``--app``): its own window with no tabs or
   address bar, using a separate browser profile under ``data/desktop-profile``.

Closing the window stops the server this launcher started. Nothing listens beyond loopback.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"
PREFERRED_PORT = 8501
TITLE = "Aegis SOC Copilot"
LOG_DIR = ROOT / "data" / "logs"
PROFILE_DIR = ROOT / "data" / "desktop-profile"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

BROWSERS = (
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
)


def healthy(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}/_stcore/health", timeout=1) as r:
            return r.status == 200
    except OSError:
        return False


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((HOST, port)) != 0


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def start_server(port: int) -> subprocess.Popen:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log = open(LOG_DIR / "desktop-server.log", "ab")  # noqa: SIM115 - lives as long as the server
    python = Path(sys.executable)
    if python.name.lower() == "pythonw.exe":  # the server itself may use the console build
        python = python.with_name("python.exe")
    return subprocess.Popen(  # noqa: S603 - fixed arguments, no shell
        [
            str(python),
            "-m",
            "streamlit",
            "run",
            str(ROOT / "app" / "main.py"),
            "--server.address",
            HOST,
            "--server.port",
            str(port),
            "--server.headless",
            "true",
        ],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        creationflags=NO_WINDOW,
    )


def wait_until_up(port: int, server: subprocess.Popen | None, seconds: float = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if healthy(port):
            return
        if server is not None and server.poll() is not None:
            raise RuntimeError(
                f"The server stopped during start-up; see {LOG_DIR / 'desktop-server.log'}"
            )
        time.sleep(0.3)
    raise RuntimeError(f"The server did not answer within {seconds:.0f} s")


def open_with_webview(url: str) -> bool:
    try:
        import webview  # type: ignore[import-not-found]
    except ImportError:
        return False
    webview.create_window(TITLE, url, width=1500, height=950, min_size=(1024, 700))
    webview.start()
    return True


def find_browser() -> str | None:
    for candidate in BROWSERS:
        path = os.path.expandvars(candidate)
        if Path(path).is_file():
            return path
    return shutil.which("msedge") or shutil.which("chrome")


def open_with_browser_app_mode(url: str) -> bool:
    browser = find_browser()
    if browser is None:
        return False
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    # A dedicated profile makes this a separate browser process, so waiting on it waits for the
    # window to close (and the copilot never mixes with the user's normal browsing).
    window = subprocess.Popen(  # noqa: S603 - fixed arguments, no shell
        [
            browser,
            f"--app={url}",
            f"--user-data-dir={PROFILE_DIR}",
            "--window-size=1500,950",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-features=Translate",
        ]
    )
    window.wait()
    return True


def message(text: str) -> None:
    """Show a message even when started with pythonw (no console)."""
    if sys.stderr is not None and sys.executable.lower().endswith("python.exe"):
        print(text, file=sys.stderr)
        return
    with contextlib.suppress(Exception):
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, text, TITLE, 0x10)


def main() -> int:
    server = None
    if healthy(PREFERRED_PORT):
        port = PREFERRED_PORT  # already running (e.g. `make run`): just open a window on it
    else:
        port = PREFERRED_PORT if port_free(PREFERRED_PORT) else free_port()
        server = start_server(port)
    try:
        wait_until_up(port, server)
        url = f"http://{HOST}:{port}/"
        if not (open_with_webview(url) or open_with_browser_app_mode(url)):
            message("No window backend found: install pywebview, Microsoft Edge or Chrome.")
            return 1
        return 0
    except RuntimeError as exc:
        message(str(exc))
        return 1
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                server.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
