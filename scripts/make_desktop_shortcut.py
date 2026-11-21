"""Create an "Aegis SOC Copilot" shortcut on the Windows desktop (and in the Start menu).

    .venv\\Scripts\\python scripts\\make_desktop_shortcut.py

The shortcut runs ``app\\desktop.py`` with ``pythonw.exe`` (no console window). The icon is
drawn here with Pillow (a Streamlit dependency) and saved to ``app/ui/assets/aegis.ico``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ICON = ROOT / "app" / "ui" / "assets" / "aegis.ico"
NAME = "Aegis SOC Copilot"


def draw_icon(size: int = 256) -> Image.Image:
    """The sidebar mark: a blue gradient shield with a check."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    s = size / 40
    shield = [(20, 3), (34, 8), (34, 19), (31, 28), (20, 37), (9, 28), (6, 19), (6, 8)]
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).polygon([(x * s, y * s) for x, y in shield], fill=255)
    gradient = Image.new("RGBA", (size, size))
    top, bottom = (79, 140, 255), (34, 211, 238)
    for y in range(size):
        t = y / (size - 1)
        color = tuple(round(a + (b - a) * t) for a, b in zip(top, bottom, strict=True))
        ImageDraw.Draw(gradient).line([(0, y), (size, y)], fill=(*color, 255))
    img.paste(gradient, (0, 0), mask)
    ImageDraw.Draw(img).line(
        [(14 * s, 19.5 * s), (18.5 * s, 24 * s), (27 * s, 14.5 * s)],
        fill=(11, 16, 32, 255),
        width=max(2, round(3 * s)),
        joint="curve",
    )
    return img


def make_shortcut(folder: Path) -> Path:
    link = folder / f"{NAME}.lnk"
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    script = (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:AEGIS_LINK);"
        "$s.TargetPath = $env:AEGIS_TARGET;"
        "$s.Arguments = $env:AEGIS_ARGS;"
        "$s.WorkingDirectory = $env:AEGIS_DIR;"
        "$s.IconLocation = $env:AEGIS_ICON;"
        "$s.Description = 'Local agentic SOC copilot';"
        "$s.Save()"
    )
    env = {
        **os.environ,
        "AEGIS_LINK": str(link),
        "AEGIS_TARGET": str(pythonw),
        "AEGIS_ARGS": f'"{ROOT / "app" / "desktop.py"}"',
        "AEGIS_DIR": str(ROOT),
        "AEGIS_ICON": f"{ICON},0",
    }
    subprocess.run(  # noqa: S603 - fixed command; paths are passed via the environment
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],  # noqa: S607
        check=True,
        env=env,
    )
    return link


def main() -> int:
    draw_icon().save(ICON, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)])
    print(f"Icon: {ICON}")
    desktop = Path(os.environ["USERPROFILE"]) / "Desktop"
    onedrive = Path(os.environ.get("ONEDRIVE", "")) / "Desktop"
    if not desktop.is_dir() and onedrive.is_dir():
        desktop = onedrive
    start_menu = Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    for folder in (desktop, start_menu):
        print(f"Shortcut: {make_shortcut(folder)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
