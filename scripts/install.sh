#!/usr/bin/env bash
# anytls installer: download, verify, install/upgrade/uninstall.
# Also installs anytls-manager, an interactive systemd service helper for anytls-server.
# Usage:
#   install.sh [install|upgrade|uninstall] [flags]
# Flags:
#   --version vX.Y.Z      (env ANYTLS_VERSION)     default: latest
#   --install-dir DIR     (env ANYTLS_INSTALL_DIR) default: /usr/local/bin
#   --repo OWNER/NAME     (env ANYTLS_REPO)        default: geekdada/anytls-go
#   --manager-skip        skip installing anytls-manager
#   -h|--help

set -euo pipefail

SERVER_BIN="anytls-server"
CLIENT_BIN="anytls-client"
MANAGER_NAME="anytls-manager"
SERVICE_NAME="anytls-server"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
UNIT_OVERRIDE_DIR="/etc/systemd/system/${SERVICE_NAME}.service.d"
CONFIG_FILE="/etc/anytls/server.yaml"
REPO="${ANYTLS_REPO:-geekdada/anytls-go}"
VERSION="${ANYTLS_VERSION:-latest}"
INSTALL_DIR="${ANYTLS_INSTALL_DIR:-/usr/local/bin}"
CMD="install"
SKIP_MANAGER=0

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
anytls installer: download, verify, install/upgrade/uninstall.
Also installs anytls-manager, an interactive systemd service helper for anytls-server.

Usage:
  install.sh [install|upgrade|uninstall] [flags]

Flags:
  --version vX.Y.Z      (env ANYTLS_VERSION)     default: latest
  --install-dir DIR     (env ANYTLS_INSTALL_DIR) default: /usr/local/bin
  --repo OWNER/NAME     (env ANYTLS_REPO)        default: geekdada/anytls-go
  --manager-skip        skip installing anytls-manager
  -h, --help            show this help
EOF
}

parse_args() {
  if [ $# -gt 0 ]; then
    case "$1" in
      install|upgrade|uninstall)
        CMD="$1"; shift ;;
      -h|--help)
        usage; exit 0 ;;
    esac
  fi

  while [ $# -gt 0 ]; do
    case "$1" in
      --version)       VERSION="${2:?--version requires a value}"; shift 2 ;;
      --version=*)     VERSION="${1#*=}"; shift ;;
      --install-dir)   INSTALL_DIR="${2:?--install-dir requires a value}"; shift 2 ;;
      --install-dir=*) INSTALL_DIR="${1#*=}"; shift ;;
      --repo)          REPO="${2:?--repo requires a value}"; shift 2 ;;
      --repo=*)        REPO="${1#*=}"; shift ;;
      --manager-skip)  SKIP_MANAGER=1; shift ;;
      -h|--help)       usage; exit 0 ;;
      *)               die "unknown argument: $1 (use --help)" ;;
    esac
  done
}

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Linux)
      case "$arch" in
        x86_64)        echo "linux_amd64" ;;
        aarch64|arm64) echo "linux_arm64" ;;
        *) die "unsupported Linux arch: $arch (supported: x86_64, aarch64)" ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64)        echo "darwin_amd64" ;;
        arm64|aarch64) echo "darwin_arm64" ;;
        *) die "unsupported macOS arch: $arch (supported: x86_64, arm64)" ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*)
      case "$arch" in
        x86_64)        echo "windows_amd64" ;;
        aarch64|arm64) echo "windows_arm64" ;;
        *) die "unsupported Windows arch: $arch (supported: x86_64, aarch64)" ;;
      esac
      ;;
    *) die "unsupported OS: $os (supported: Linux, Darwin, Windows)" ;;
  esac
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c -
  else
    die "need sha256sum or shasum to verify checksum"
  fi
}

resolve_tag() {
  if [ "$VERSION" != "latest" ]; then
    case "$VERSION" in
      v*) echo "$VERSION" ;;
      *)  echo "v${VERSION}" ;;
    esac
    return
  fi
  local api="https://api.github.com/repos/${REPO}/releases/latest"
  local body tag
  body="$(curl -fsSL "$api")"
  tag="$(printf '%s\n' "$body" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')"
  [ -n "$tag" ] || die "failed to resolve latest release tag from $api"
  echo "$tag"
}

maybe_sudo() {
  local dir="$1"
  if [ -d "$dir" ] && [ -w "$dir" ]; then
    echo ""
  elif [ ! -e "$dir" ] && [ -w "$(dirname "$dir")" ]; then
    echo ""
  else
    if command -v sudo >/dev/null 2>&1; then
      echo "sudo"
    else
      die "no write access to $dir and sudo not available"
    fi
  fi
}

install_file() {
  local src="$1" dest="$2"
  if command -v install >/dev/null 2>&1; then
    $3 install -m 0755 "$src" "$dest"
  else
    $3 cp "$src" "$dest"
    $3 chmod 0755 "$dest"
  fi
}

generate_manager_script() {
  local dest="$1"
  cat > "$dest" <<'MANAGER_SCRIPT'
#!/usr/bin/env bash
# anytls-manager: interactive systemd service helper for anytls-server.
# Installed by scripts/install.sh — do not edit manually.
set -euo pipefail

BIN_NAME="anytls-server"
SERVICE_NAME="anytls-server"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
UNIT_OVERRIDE_DIR="/etc/systemd/system/${SERVICE_NAME}.service.d"
CONFIG_DIR="/etc/anytls"
CONFIG_FILE="/etc/anytls/server.yaml"

MANAGER_REPO="__REPO__"
MANAGER_INSTALL_DIR="__INSTALL_DIR__"
DEFAULT_LISTEN="0.0.0.0:8443"

INSTALLER_URL="https://raw.githubusercontent.com/${MANAGER_REPO}/main/scripts/install.sh"

log()    { printf '==> %s\n' "$*"; }
warn()   { printf 'warning: %s\n' "$*" >&2; }
die()    { printf 'error: %s\n' "$*" >&2; exit 1; }

maybe_sudo() {
  if command -v sudo >/dev/null 2>&1; then
    echo "sudo"
  else
    echo ""
  fi
}

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl not found — systemd is required on this host"
  fi
}

has_service() {
  [ -f "$UNIT_FILE" ]
}

upgrade_binary() {
  log "upgrading anytls binaries..."
  local sudo_cmd
  sudo_cmd="$(maybe_sudo)"
  curl -fsSL "$INSTALLER_URL" | $sudo_cmd bash -s -- upgrade \
    --repo "$MANAGER_REPO" \
    --install-dir "$MANAGER_INSTALL_DIR" \
    --version latest
}

prompt_required() {
  local label="$1"
  local val=""
  while [ -z "$val" ]; do
    read -r -p "$label: " val
  done
  echo "$val"
}

prompt_optional() {
  local label="$1" default="$2"
  local val
  read -r -p "${label} [${default}]: " val
  echo "${val:-$default}"
}

prompt_optional_empty() {
  local label="$1"
  local val
  read -r -p "${label} (leave empty to skip): " val
  echo "$val"
}

yaml_quote() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '"%s"' "$s"
}

collect_config() {
  printf >&2 '\n=== anytls-server configuration ===\n'
  printf >&2 'Press Enter to accept defaults. Required fields (*).\n\n'

  local listen auth_type password padding_scheme
  local tls_cert tls_key auth_url auth_insecure auth_cache auth_neg_cache
  local stats_listen stats_secret

  listen="$(prompt_optional "  Listen address" "$DEFAULT_LISTEN")"
  auth_type="$(prompt_optional "  Auth type (password|http)" "password")"

  case "$auth_type" in
    http)
      auth_url="$(prompt_required "* HTTP auth URL")"
      auth_insecure="$(prompt_optional "  Skip TLS verify for auth backend (true|false)" "false")"
      auth_cache=""
      auth_neg_cache=""
      password=""
      ;;
    password|*)
      password="$(prompt_required "* Password")"
      auth_url=""
      auth_insecure=""
      auth_cache=""
      auth_neg_cache=""
      ;;
  esac

  padding_scheme=""
  tls_cert="$(prompt_optional_empty "  TLS certificate file")"
  if [ -n "$tls_cert" ]; then
    tls_key="$(prompt_required "* TLS key file")"
  else
    tls_key=""
  fi

  stats_listen="$(prompt_optional_empty "  Traffic stats listen (IP:port)")"
  if [ -n "$stats_listen" ]; then
    stats_secret="$(prompt_optional_empty "  Traffic stats secret")"
  else
    stats_secret=""
  fi

  printf >&2 '\n--- Summary ---\n'
  printf >&2 '  Listen:           %s\n' "$listen"
  if [ "$auth_type" = "http" ]; then
    printf >&2 '  Auth:             http (%s)\n' "$auth_url"
    [ -n "$auth_cache" ]     && printf >&2 '  Auth cache TTL:   %s\n' "$auth_cache"
    [ -n "$auth_neg_cache" ] && printf >&2 '  Auth neg cache:   %s\n' "$auth_neg_cache"
  else
    printf >&2 '  Auth:             password\n'
  fi
  [ -n "$padding_scheme" ] && printf >&2 '  Padding scheme:   %s\n' "$padding_scheme"
  [ -n "$tls_cert" ]       && printf >&2 '  TLS cert/key:     %s / %s\n' "$tls_cert" "$tls_key"
  [ -n "$stats_listen" ]   && printf >&2 '  Traffic stats:    %s\n' "$stats_listen"
  printf >&2 '\n'

  read -r -p "Proceed with this configuration? [Y/n] " confirm
  case "${confirm:-y}" in
    [Yy]|[Yy][Ee][Ss]) ;;
    *) die "aborted" ;;
  esac

  {
    printf 'listen: %s\n' "$(yaml_quote "$listen")"
    if [ -n "$password" ]; then
      printf 'password: %s\n' "$(yaml_quote "$password")"
    fi
    if [ -n "$padding_scheme" ]; then
      printf 'padding-scheme: %s\n' "$(yaml_quote "$padding_scheme")"
    fi
    if [ -n "$tls_cert" ]; then
      printf 'tls:\n  cert: %s\n  key: %s\n' \
        "$(yaml_quote "$tls_cert")" "$(yaml_quote "$tls_key")"
    fi
    if [ "$auth_type" = "http" ]; then
      printf 'auth:\n  type: http\n  http:\n    url: %s\n' "$(yaml_quote "$auth_url")"
      if [ "$auth_insecure" = "true" ]; then
        printf '    insecure: true\n'
      fi
      if [ -n "$auth_cache" ]; then
        printf '    cacheTTL: %s\n' "$auth_cache"
      fi
      if [ -n "$auth_neg_cache" ]; then
        printf '    negativeCacheTTL: %s\n' "$auth_neg_cache"
      fi
    fi
    if [ -n "$stats_listen" ]; then
      printf 'trafficStats:\n  listen: %s\n' "$(yaml_quote "$stats_listen")"
      if [ -n "$stats_secret" ]; then
        printf '  secret: %s\n' "$(yaml_quote "$stats_secret")"
      fi
    fi
  }
}

write_config() {
  local yaml_content="$1"
  local sudo_cmd
  sudo_cmd="$(maybe_sudo)"

  log "writing config to $CONFIG_FILE"
  $sudo_cmd mkdir -p "$CONFIG_DIR"
  printf '%s\n' "$yaml_content" | $sudo_cmd tee "$CONFIG_FILE" > /dev/null
  $sudo_cmd chmod 600 "$CONFIG_FILE"
}

install_config_from() {
  local source="$1"
  local sudo_cmd
  sudo_cmd="$(maybe_sudo)"

  [ -f "$source" ] || die "config file not found: $source"
  log "installing config from $source"
  $sudo_cmd mkdir -p "$CONFIG_DIR"
  $sudo_cmd cp "$source" "$CONFIG_FILE"
  $sudo_cmd chmod 600 "$CONFIG_FILE"
}

write_unit() {
  local sudo_cmd
  sudo_cmd="$(maybe_sudo)"

  log "writing systemd unit to $UNIT_FILE"
  $sudo_cmd tee "$UNIT_FILE" > /dev/null <<UNIT_EOF
[Unit]
Description=AnyTLS proxy server
Documentation=https://github.com/${MANAGER_REPO}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=${MANAGER_INSTALL_DIR}/${BIN_NAME} -c ${CONFIG_FILE}
Environment=LOG_LEVEL=info
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT_EOF

  $sudo_cmd systemctl daemon-reload
}

install_service() {
  require_systemd
  log "installing/updating ${SERVICE_NAME} service..."

  local config_source=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -c|--config)
        config_source="${2:?-c requires a path}"
        shift 2
        ;;
      *)
        die "unknown argument: $1 (use install-service [-c PATH])"
        ;;
    esac
  done

  if [ -n "$config_source" ]; then
    install_config_from "$config_source"
  else
    local yaml
    if ! yaml="$(collect_config)"; then
      warn "configuration aborted — nothing written"
      return 1
    fi
    write_config "$yaml"
  fi

  write_unit
  local sudo_cmd
  sudo_cmd="$(maybe_sudo)"
  $sudo_cmd systemctl enable "$SERVICE_NAME"
  $sudo_cmd systemctl restart "$SERVICE_NAME"
  log "service installed and started"
}

uninstall_service() {
  require_systemd
  local sudo_cmd
  sudo_cmd="$(maybe_sudo)"
  log "stopping $SERVICE_NAME"
  $sudo_cmd systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  log "disabling $SERVICE_NAME"
  $sudo_cmd systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  log "removing unit file"
  $sudo_cmd rm -f "$UNIT_FILE"
  $sudo_cmd rm -rf "$UNIT_OVERRIDE_DIR" 2>/dev/null || true
  $sudo_cmd systemctl daemon-reload
  log "service uninstalled"
}

start_service() {
  require_systemd
  log "starting $SERVICE_NAME"
  $(maybe_sudo) systemctl start "$SERVICE_NAME"
}

stop_service() {
  require_systemd
  log "stopping $SERVICE_NAME"
  $(maybe_sudo) systemctl stop "$SERVICE_NAME" || true
}

restart_service() {
  require_systemd
  log "restarting $SERVICE_NAME"
  $(maybe_sudo) systemctl restart "$SERVICE_NAME"
}

show_status() {
  require_systemd
  if has_service; then
    systemctl status "$SERVICE_NAME" --no-pager || true
  else
    warn "service $SERVICE_NAME is not installed"
  fi
}

show_logs() {
  require_systemd
  if has_service; then
    local lines="${1:-50}"
    journalctl -u "$SERVICE_NAME" --no-pager -n "$lines" 2>/dev/null || \
      die "journalctl failed — check that systemd-journald is running"
  else
    warn "service $SERVICE_NAME is not installed"
  fi
}

upgrade_and_restart() {
  require_systemd
  if has_service; then
    upgrade_binary
    restart_service
  else
    warn "service $SERVICE_NAME is not installed — use install-service first"
  fi
}

show_menu() {
  while true; do
    echo
    echo "===================="
    echo " anytls-manager"
    echo "===================="
    echo " 1) Install/update service"
    echo " 2) Upgrade binaries and restart"
    echo " 3) Start service"
    echo " 4) Stop service"
    echo " 5) Restart service"
    echo " 6) Show status"
    echo " 7) Show logs (last 50 lines)"
    echo " 8) Uninstall service"
    echo " 9) Exit"
    echo "--------------------"
    read -r -p " choice> " choice
    case "$choice" in
      1) install_service || true ;;
      2) upgrade_and_restart ;;
      3) start_service ;;
      4) stop_service ;;
      5) restart_service ;;
      6) show_status ;;
      7) show_logs 50 ;;
      8)
        read -r -p "Really uninstall systemd service? [y/N] " confirm
        case "${confirm:-n}" in [Yy]|[Yy][Ee][Ss]) uninstall_service ;; *) echo "cancelled" ;; esac
        ;;
      9) echo "bye."; exit 0 ;;
      *) echo "invalid choice" ;;
    esac
  done
}

if [ $# -eq 0 ]; then
  show_menu
else
  case "$1" in
    install-service)
      shift
      install_service "$@"
      ;;
    upgrade)
      upgrade_binary
      ;;
    start)
      start_service
      ;;
    stop)
      stop_service
      ;;
    restart)
      restart_service
      ;;
    status)
      show_status
      ;;
    logs)
      show_logs "${2:-50}"
      ;;
    uninstall-service)
      read -r -p "Really uninstall systemd service? [y/N] " confirm
      case "${confirm:-n}" in [Yy]|[Yy][Ee][Ss]) uninstall_service ;; *) die "cancelled" ;; esac
      ;;
    -h|--help)
      cat <<'HELP_EOF'
anytls-manager: interactive systemd service helper for anytls-server.

Usage:
  anytls-manager                                    interactive menu
  anytls-manager install-service [-c PATH]          install/update service
  anytls-manager upgrade                            upgrade binaries only
  anytls-manager start|stop|restart|status          service lifecycle
  anytls-manager logs [N]                           show last N lines (default 50)
  anytls-manager uninstall-service                  remove service
HELP_EOF
      ;;
    *)
      die "unknown command: $1 (use --help)"
      ;;
  esac
fi
MANAGER_SCRIPT

  sed -i '' \
    -e "s|__REPO__|${REPO}|g" \
    -e "s|__INSTALL_DIR__|${INSTALL_DIR}|g" \
    "$dest" 2>/dev/null || \
  sed -i \
    -e "s|__REPO__|${REPO}|g" \
    -e "s|__INSTALL_DIR__|${INSTALL_DIR}|g" \
    "$dest"
}

do_install() {
  require_cmd curl
  require_cmd unzip

  local target tag version archive checksums url_base tmp sudo_cmd
  target="$(detect_target)"
  tag="$(resolve_tag)"
  version="${tag#v}"
  archive="anytls_${version}_${target}.zip"
  checksums="anytls_${version}_checksums.txt"
  url_base="https://github.com/${REPO}/releases/download/${tag}"

  log "repo:        $REPO"
  log "version:     $tag"
  log "target:      $target"
  log "install dir: $INSTALL_DIR"

  tmp="$(mktemp -d)"
  trap "rm -rf -- '$tmp'" EXIT

  log "downloading $archive"
  curl -fsSL --retry 3 -o "$tmp/$archive" "$url_base/$archive"

  log "downloading $checksums"
  curl -fsSL --retry 3 -o "$tmp/$checksums" "$url_base/$checksums"

  log "verifying checksum"
  ( cd "$tmp" && grep -E "[[:space:]]${archive}$" "$checksums" | sha256_check ) \
    || die "checksum verification failed for $archive"

  log "extracting"
  unzip -q "$tmp/$archive" -d "$tmp"

  local server_bin client_bin
  server_bin="$(find "$tmp" -type f \( -name "$SERVER_BIN" -o -name "${SERVER_BIN}.exe" \) | head -n1)"
  client_bin="$(find "$tmp" -type f \( -name "$CLIENT_BIN" -o -name "${CLIENT_BIN}.exe" \) | head -n1)"
  [ -n "$server_bin" ] || die "binary '$SERVER_BIN' not found inside archive"
  [ -n "$client_bin" ] || die "binary '$CLIENT_BIN' not found inside archive"

  sudo_cmd="$(maybe_sudo "$INSTALL_DIR")"
  if [ ! -d "$INSTALL_DIR" ]; then
    log "creating $INSTALL_DIR"
    $sudo_cmd mkdir -p "$INSTALL_DIR"
  fi

  log "installing to $INSTALL_DIR/$SERVER_BIN"
  install_file "$server_bin" "$INSTALL_DIR/$SERVER_BIN" "$sudo_cmd"
  log "installing to $INSTALL_DIR/$CLIENT_BIN"
  install_file "$client_bin" "$INSTALL_DIR/$CLIENT_BIN" "$sudo_cmd"

  log "installed: $INSTALL_DIR/$SERVER_BIN, $INSTALL_DIR/$CLIENT_BIN"
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) warn "$INSTALL_DIR is not in your PATH — add it to use anytls binaries directly." ;;
  esac

  if [ "$SKIP_MANAGER" -eq 0 ]; then
    log "installing $MANAGER_NAME"
    local manager_tmp
    manager_tmp="$(mktemp)"
    generate_manager_script "$manager_tmp"
    install_file "$manager_tmp" "$INSTALL_DIR/$MANAGER_NAME" "$sudo_cmd"
    rm -f "$manager_tmp"
    log "manager installed: $INSTALL_DIR/$MANAGER_NAME"
  fi
}

remove_systemd_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  if [ ! -f "$UNIT_FILE" ]; then
    return 0
  fi

  local sudo_cmd
  sudo_cmd="$(maybe_sudo /etc/systemd/system)"

  log "stopping $SERVICE_NAME"
  $sudo_cmd systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  log "disabling $SERVICE_NAME"
  $sudo_cmd systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  log "removing unit file $UNIT_FILE"
  $sudo_cmd rm -f "$UNIT_FILE"
  if [ -d "$UNIT_OVERRIDE_DIR" ]; then
    log "removing unit override dir $UNIT_OVERRIDE_DIR"
    $sudo_cmd rm -rf "$UNIT_OVERRIDE_DIR"
  fi
  log "reloading systemd daemon"
  $sudo_cmd systemctl daemon-reload
}

do_uninstall() {
  local server_path="$INSTALL_DIR/$SERVER_BIN"
  local client_path="$INSTALL_DIR/$CLIENT_BIN"
  local manager_path="$INSTALL_DIR/$MANAGER_NAME"
  local sudo_cmd removed=0
  sudo_cmd="$(maybe_sudo "$INSTALL_DIR")"

  remove_systemd_service

  for path in "$server_path" "$client_path" "$manager_path"; do
    if [ -e "$path" ]; then
      log "removing $path"
      $sudo_cmd rm -f "$path"
      removed=1
    else
      log "$path not found — skipping"
    fi
  done

  if [ "$removed" -eq 0 ]; then
    log "nothing to uninstall"
  else
    log "uninstalled"
  fi

  if [ -f "$CONFIG_FILE" ]; then
    warn "config left in place: $CONFIG_FILE (remove manually if no longer needed)"
  fi
}

main() {
  parse_args "$@"
  case "$CMD" in
    install|upgrade) do_install ;;
    uninstall)       do_uninstall ;;
    *) die "unknown command: $CMD" ;;
  esac
}

main "$@"
