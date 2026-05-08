"""Terminal banner helpers for SecureShield."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

BANNER_LINES = [
    "███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ",
    "██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗",
    "███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║",
    "╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║",
    "███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗███████║██║  ██║██║███████╗███████╗██████╔╝",
    "╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ",
]

SUBTITLE = "                    🛡️  SECURESHIELD  🛡️"

KITTY_TITLE = "\033[1;36mSecureShield\033[0m"
KITTY_SUBTITLE = "\033[38;5;117m                    🛡️  SECURESHIELD  🛡️\033[0m"


def _logo_path() -> Path:
    terminal_logo = Path(__file__).resolve().parent / "assets" / "logo_terminal.png"
    if terminal_logo.exists():
        return terminal_logo
    return Path(__file__).resolve().parent / "assets" / "logo.png"


def _is_interactive() -> bool:
    return sys.stdout.isatty() and not os.environ.get("SECURESHIELD_NO_BANNER")


def _banner_mode_preference() -> str:
    return os.environ.get("SECURESHIELD_BANNER_MODE", "text").strip().lower()


def _kitty_banner_height() -> int:
    raw_value = os.environ.get("SECURESHIELD_KITTY_HEIGHT", "18").strip()
    try:
        return max(10, min(28, int(raw_value)))
    except ValueError:
        return 18


def _supports_kitty() -> bool:
    return bool(os.environ.get("KITTY_WINDOW_ID")) and shutil.which("kitty") is not None


def _supports_iterm() -> bool:
    term_program = os.environ.get("TERM_PROGRAM", "").lower()
    return term_program == "iterm.app"


def _supports_chafa() -> bool:
    return shutil.which("chafa") is not None


def _supports_viu() -> bool:
    return shutil.which("viu") is not None


def _show_kitty_image(logo_path: Path) -> bool:
    height = _kitty_banner_height()
    try:
        completed = subprocess.run(
            [
                "kitty",
                "+kitten",
                "icat",
                "--align",
                "center",
                "--place",
                f"48x{height}@0x0",
                str(logo_path),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return False

    return completed.returncode == 0


def _print_kitty_text() -> None:
    print()
    print(KITTY_TITLE.center(48))
    print(KITTY_SUBTITLE.center(48))


def _prefer_ascii_only() -> bool:
    return _banner_mode_preference() == "ascii"


def _prefer_text_banner() -> bool:
    return _banner_mode_preference() in {"text", "color", "colour"}


def _prefer_kitty_only() -> bool:
    return _banner_mode_preference() == "kitty"


def _supports_color() -> bool:
    return bool(os.environ.get("COLORTERM") or "256color" in os.environ.get("TERM", ""))


def _print_color_banner() -> None:
    if not _supports_color():
        _print_ascii_banner()
        return

    palette = [51, 45, 39, 33, 27, 21]
    accent = 226
    for index, line in enumerate(BANNER_LINES):
        color = palette[min(index, len(palette) - 1)]
        print(f"\033[1;38;5;{color}m{line}\033[0m")
    print()
    print(f"\033[1;38;5;{accent}m{SUBTITLE}\033[0m")


def _print_ascii_banner() -> None:
    print("\n".join(BANNER_LINES))
    print()
    print(f" {SUBTITLE}")


def _show_iterm_image(logo_path: Path) -> bool:
    try:
        encoded = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    except OSError:
        return False

    filename = logo_path.name
    # Tanglish: iTerm2 inline image escape sequence use pannrom.
    sys.stdout.write(f"\033]1337;File=name={filename};inline=1:{encoded}\a\n")
    sys.stdout.flush()
    return True


def _show_chafa_image(logo_path: Path) -> bool:
    try:
        completed = subprocess.run(
            [
                "chafa",
                "--animate=off",
                "--clear",
                "--center=on",
                "--size=60x30",
                str(logo_path),
            ],
            check=False,
        )
    except OSError:
        return False

    return completed.returncode == 0


def _show_viu_image(logo_path: Path) -> bool:
    try:
        completed = subprocess.run(
            ["viu", "-w", "60", str(logo_path)],
            check=False,
        )
    except OSError:
        return False

    return completed.returncode == 0


def banner_environment() -> dict[str, Any]:
    logo_path = _logo_path()
    return {
        "interactive": sys.stdout.isatty(),
        "banner_disabled": bool(os.environ.get("SECURESHIELD_NO_BANNER")),
        "banner_mode": _banner_mode_preference(),
        "logo_path": str(logo_path),
        "logo_exists": logo_path.exists(),
        "term": os.environ.get("TERM", ""),
        "term_program": os.environ.get("TERM_PROGRAM", ""),
        "kitty_window_id": bool(os.environ.get("KITTY_WINDOW_ID")),
        "supports": {
            "kitty": _supports_kitty(),
            "iterm": _supports_iterm(),
            "chafa": _supports_chafa(),
            "viu": _supports_viu(),
        },
    }


def resolve_banner_mode() -> str:
    env = banner_environment()
    if not env["interactive"]:
        return "disabled-non-interactive"
    if env["banner_disabled"]:
        return "disabled-env"
    if env["banner_mode"] in {"text", "color", "colour"}:
        return "text-color"
    if env["banner_mode"] == "ascii":
        return "ascii-forced"
    if not env["logo_exists"]:
        return "ascii-no-logo"
    if env["supports"]["kitty"]:
        return "image-kitty"
    if env["banner_mode"] == "kitty":
        return "ascii-kitty-unavailable"
    if env["supports"]["iterm"]:
        return "image-iterm"
    if env["supports"]["chafa"]:
        return "image-chafa"
    if env["supports"]["viu"]:
        return "image-viu"
    return "ascii-fallback"


def show_banner() -> None:
    """Render an image banner when supported, otherwise show ASCII fallback."""
    if not _is_interactive():
        return

    if _prefer_text_banner():
        _print_color_banner()
        return

    if _prefer_ascii_only():
        _print_ascii_banner()
        return

    logo_path = _logo_path()
    if logo_path.exists():
        if _supports_kitty() and _show_kitty_image(logo_path):
            _print_kitty_text()
            return
        if _prefer_kitty_only():
            _print_ascii_banner()
            return
        if _supports_iterm() and _show_iterm_image(logo_path):
            print()
            return
        if _supports_kitty():
            _print_ascii_banner()
            return
        if _supports_chafa() and _show_chafa_image(logo_path):
            print()
            return
        if _supports_viu() and _show_viu_image(logo_path):
            print()
            return

    _print_ascii_banner()
