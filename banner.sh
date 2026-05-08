#!/usr/bin/env bash

set -u

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="$PROJECT_DIR/secureshield/assets/logo.png"
BANNER_MODE="${SECURESHIELD_BANNER_MODE:-text}"
KITTY_HEIGHT="${SECURESHIELD_KITTY_HEIGHT:-18}"
if [[ -f "$PROJECT_DIR/secureshield/assets/logo_terminal.png" ]]; then
  IMAGE="$PROJECT_DIR/secureshield/assets/logo_terminal.png"
fi

print_color() {
  printf '\033[1;38;5;51m███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ \033[0m\n'
  printf '\033[1;38;5;45m██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗\033[0m\n'
  printf '\033[1;38;5;39m███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║\033[0m\n'
  printf '\033[1;38;5;33m╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║\033[0m\n'
  printf '\033[1;38;5;27m███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗███████║██║  ██║██║███████╗███████╗██████╔╝\033[0m\n'
  printf '\033[1;38;5;21m╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ \033[0m\n'
  printf '\n'
  printf '\033[1;38;5;226m                    🛡️  SECURESHIELD  🛡️\033[0m\n'
}

print_ascii() {
  cat <<'EOF'
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗███████║██║  ██║██║███████╗███████╗██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 

                    🛡️  SECURESHIELD  🛡️
EOF
}

if [[ ! -f "$IMAGE" ]]; then
  print_color
  exit 0
fi

if [[ "$BANNER_MODE" == "text" || "$BANNER_MODE" == "color" || "$BANNER_MODE" == "colour" ]]; then
  print_color
  exit 0
fi

if [[ "$BANNER_MODE" == "ascii" ]]; then
  print_ascii
  exit 0
fi

if [[ -n "${KITTY_WINDOW_ID:-}" ]] && command -v kitty >/dev/null 2>&1; then
  kitty +kitten icat --align center --place "48x${KITTY_HEIGHT}@0x0" "$IMAGE" 2>/dev/null && {
    printf '\n'
    printf '\033[1;36m%24s\033[0m\n' "SecureShield"
    printf '\033[38;5;117m%48s\033[0m\n' "Container Security and AI Threat Detection"
    exit 0
  }
  print_ascii
  exit 0
fi

if [[ "$BANNER_MODE" == "kitty" ]]; then
  print_ascii
  exit 0
fi

if [[ "${TERM_PROGRAM:-}" == "iTerm.app" ]]; then
  IMAGE_B64="$(base64 -w 0 "$IMAGE" 2>/dev/null || base64 "$IMAGE" | tr -d '\n')"
  printf '\033]1337;File=name=%s;inline=1:%s\a\n' "$(basename "$IMAGE")" "$IMAGE_B64"
  exit 0
fi

if command -v chafa >/dev/null 2>&1; then
  chafa --animate=off --clear --center=on --size=60x30 "$IMAGE" && printf '\n' && exit 0
fi

if command -v viu >/dev/null 2>&1; then
  viu -w 60 "$IMAGE" && printf '\n' && exit 0
fi

print_ascii
