#!/usr/bin/env bash
#
# oxmon quick install script
#
# Usage:
#   Install server:
#     curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- server
#   Install agent:
#     curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- agent --server-endpoint http://10.0.1.100:9090
#
# Options:
#   server | agent                  Component to install (required)
#   --version <tag>                 Release version (default: latest)
#   --install-dir <path>            Binary install directory (default: /usr/local/bin)
#   --config-dir <path>             Config directory (default: /etc/oxmon)
#   --data-dir <path>               Data directory for server (default: /var/lib/oxmon)
#   --agent-id <id>                 Agent ID (default: hostname)
#   --server-endpoint <url>         gRPC server endpoint for agent (default: http://127.0.0.1:9090)
#   --setup-pm2                     Generate PM2 ecosystem config and start services
#   --pm2-only                      Only generate PM2 config (skip binary install)
#

set -euo pipefail

# --- Defaults ---
GITHUB_REPO="skingford/oxmon"
COMPONENT=""
VERSION="latest"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/oxmon"
DATA_DIR="/var/lib/oxmon"
AGENT_ID=""
SERVER_ENDPOINT="http://127.0.0.1:9090"
SETUP_PM2=false
PM2_ONLY=false

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

usage() {
    echo ""
    echo -e "Usage: ${CYAN}install.sh <server|agent> [OPTIONS]${NC}"
    echo ""
    echo "  The first argument specifies which component to install."
    echo "  Server and agent are typically deployed on separate machines."
    echo ""
    echo "Examples:"
    echo -e "  ${CYAN}# Central server${NC}"
    echo "  curl -fsSL .../install.sh | bash -s -- server"
    echo "  curl -fsSL .../install.sh | bash -s -- server --setup-pm2"
    echo ""
    echo -e "  ${CYAN}# Monitored host${NC}"
    echo "  curl -fsSL .../install.sh | bash -s -- agent --server-endpoint http://10.0.1.100:9090"
    echo "  curl -fsSL .../install.sh | bash -s -- agent --agent-id web-01 --setup-pm2"
    echo ""
    echo "Options:"
    echo "  --version <tag>           Release version (default: latest)"
    echo "  --install-dir <path>      Binary install path (default: /usr/local/bin)"
    echo "  --config-dir <path>       Config file path (default: /etc/oxmon)"
    echo "  --data-dir <path>         Server data dir (default: /var/lib/oxmon)"
    echo "  --agent-id <id>           Agent identifier (default: hostname)"
    echo "  --server-endpoint <url>   gRPC server address (default: http://127.0.0.1:9090)"
    echo "  --setup-pm2               Generate PM2 config and start service"
    echo "  --pm2-only                Only generate PM2 config (skip download)"
    echo ""
}

# --- Parse arguments ---
# First positional argument is the component
if [[ $# -gt 0 && "$1" != --* ]]; then
    case "$1" in
        server|agent) COMPONENT="$1"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            error "Unknown component: '$1'. Must be 'server' or 'agent'.\n$(usage)" ;;
    esac
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --version)         VERSION="$2";           shift 2 ;;
        --install-dir)     INSTALL_DIR="$2";       shift 2 ;;
        --config-dir)      CONFIG_DIR="$2";        shift 2 ;;
        --data-dir)        DATA_DIR="$2";          shift 2 ;;
        --agent-id)        AGENT_ID="$2";          shift 2 ;;
        --server-endpoint) SERVER_ENDPOINT="$2";   shift 2 ;;
        --setup-pm2)       SETUP_PM2=true;         shift ;;
        --pm2-only)        PM2_ONLY=true; SETUP_PM2=true; shift ;;
        --help|-h)         usage; exit 0 ;;
        *) error "Unknown option: $1" ;;
    esac
done

# Validate component
if [[ -z "$COMPONENT" ]]; then
    echo ""
    error "Missing required argument: component (server or agent).\n\n$(usage)"
fi

# --- Detect platform ---
detect_platform() {
    local os arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os="unknown-linux-gnu" ;;
        Darwin) os="apple-darwin" ;;
        *)      error "Unsupported OS: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64)   arch="x86_64" ;;
        aarch64|arm64)  arch="aarch64" ;;
        *)              error "Unsupported architecture: $arch" ;;
    esac

    echo "${arch}-${os}"
}

# --- Resolve version ---
resolve_version() {
    if [[ "$VERSION" == "latest" ]]; then
        info "Fetching latest release version..."
        VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
            | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ -z "$VERSION" ]]; then
            error "Failed to fetch latest version. Specify --version manually."
        fi
    fi
    info "Version: ${CYAN}${VERSION}${NC}"
}

# --- Download and install a binary ---
install_binary() {
    local bin_name="$1"
    local target="$2"
    local tmp_dir

    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" RETURN

    local tarball="${bin_name}-${VERSION}-${target}.tar.gz"
    local url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${tarball}"

    info "Downloading ${CYAN}${bin_name}${NC} for ${target}..."
    if ! curl -fSL --progress-bar -o "${tmp_dir}/${tarball}" "$url"; then
        error "Download failed: $url\nCheck that release ${VERSION} exists and has asset ${tarball}."
    fi

    info "Installing ${bin_name} to ${INSTALL_DIR}/"
    tar xzf "${tmp_dir}/${tarball}" -C "$tmp_dir"
    sudo install -m 755 "${tmp_dir}/${bin_name}" "${INSTALL_DIR}/${bin_name}"

    info "${GREEN}${bin_name}${NC} installed: $(${INSTALL_DIR}/${bin_name} --version 2>/dev/null || echo "${INSTALL_DIR}/${bin_name}")"
}

# --- Generate config files ---
generate_server_config() {
    if [[ -f "${CONFIG_DIR}/server.toml" ]]; then
        warn "Server config already exists: ${CONFIG_DIR}/server.toml (skipped)"
        return
    fi

    info "Generating server config: ${CONFIG_DIR}/server.toml"
    sudo mkdir -p "$CONFIG_DIR"
    sudo tee "${CONFIG_DIR}/server.toml" > /dev/null <<'TOML'
# oxmon Server Configuration

grpc_port = 9090
http_port = 8080
data_dir = "/var/lib/oxmon"
retention_days = 7
require_agent_auth = false

[auth]
# jwt_secret = "change-me-in-production"
token_expire_secs = 86400
default_username = "admin"
default_password = "changeme"

[[alert.rules]]
name = "high-cpu"
type = "threshold"
metric = "cpu.usage"
agent_pattern = "*"
operator = "greater_than"
value = 90.0
duration_secs = 300
severity = "critical"
silence_secs = 600

[[alert.rules]]
name = "memory-spike"
type = "rate_of_change"
metric = "memory.used_percent"
agent_pattern = "*"
rate_threshold = 20.0
window_secs = 300
severity = "warning"
silence_secs = 600

[[alert.rules]]
name = "disk-full-prediction"
type = "trend_prediction"
metric = "disk.used_percent"
agent_pattern = "*"
predict_threshold = 95.0
horizon_secs = 86400
min_data_points = 10
severity = "info"
silence_secs = 3600

[[notification.channels]]
type = "webhook"
min_severity = "info"
url = "https://hooks.slack.com/services/xxx/yyy/zzz"

aggregation_window_secs = 60

[cert_check]
enabled = true
default_interval_secs = 86400
tick_secs = 60
connect_timeout_secs = 10
max_concurrent = 10
TOML
}

generate_agent_config() {
    if [[ -f "${CONFIG_DIR}/agent.toml" ]]; then
        warn "Agent config already exists: ${CONFIG_DIR}/agent.toml (skipped)"
        return
    fi

    local agent_id="${AGENT_ID:-$(hostname)}"

    info "Generating agent config: ${CONFIG_DIR}/agent.toml"
    sudo mkdir -p "$CONFIG_DIR"
    sudo tee "${CONFIG_DIR}/agent.toml" > /dev/null <<TOML
# oxmon Agent Configuration

agent_id = "${agent_id}"
server_endpoint = "${SERVER_ENDPOINT}"
# auth_token = "your-token-here"
collection_interval_secs = 10
buffer_max_size = 1000
TOML
}

# --- PM2 setup ---
setup_pm2() {
    # Check if npm / pm2 is available
    if ! command -v pm2 &>/dev/null; then
        if command -v npm &>/dev/null; then
            info "Installing PM2 globally..."
            sudo npm install -g pm2
        else
            warn "npm not found. Install Node.js first, then run:"
            warn "  npm install -g pm2"
            warn "  pm2 start ${CONFIG_DIR}/ecosystem.config.js"
            warn "  pm2 save && pm2 startup"
            generate_pm2_config
            return
        fi
    fi

    generate_pm2_config

    info "Starting oxmon-${COMPONENT} with PM2..."
    pm2 start "${CONFIG_DIR}/ecosystem.config.js"
    pm2 save

    info "Setting up PM2 startup hook..."
    local startup_cmd
    startup_cmd=$(pm2 startup 2>&1 | grep 'sudo' | head -1)
    if [[ -n "$startup_cmd" ]]; then
        info "Run the following command to enable auto-start on boot:"
        echo -e "  ${CYAN}${startup_cmd}${NC}"
    fi
}

generate_pm2_config() {
    local bin_name="oxmon-${COMPONENT}"
    local config_file="${COMPONENT}.toml"
    local log_prefix="${COMPONENT}"

    info "Generating PM2 ecosystem config: ${CONFIG_DIR}/ecosystem.config.js"

    if [[ "$COMPONENT" == "server" ]]; then
        sudo tee "${CONFIG_DIR}/ecosystem.config.js" > /dev/null <<JS
module.exports = {
  apps: [
    {
      name: 'oxmon-server',
      script: '${INSTALL_DIR}/oxmon-server',
      args: '${CONFIG_DIR}/server.toml',
      cwd: '${DATA_DIR}',
      autorestart: true,
      max_restarts: 10,
      restart_delay: 5000,
      env: {
        RUST_LOG: 'oxmon=info',
      },
      error_file: '/var/log/oxmon/server-error.log',
      out_file: '/var/log/oxmon/server-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    },
  ],
};
JS
    else
        sudo tee "${CONFIG_DIR}/ecosystem.config.js" > /dev/null <<JS
module.exports = {
  apps: [
    {
      name: 'oxmon-agent',
      script: '${INSTALL_DIR}/oxmon-agent',
      args: '${CONFIG_DIR}/agent.toml',
      autorestart: true,
      max_restarts: 10,
      restart_delay: 5000,
      env: {
        RUST_LOG: 'oxmon=info',
      },
      error_file: '/var/log/oxmon/agent-error.log',
      out_file: '/var/log/oxmon/agent-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    },
  ],
};
JS
    fi
}

# --- Main ---
main() {
    echo ""
    echo -e "${CYAN}  ╔═══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║         oxmon quick installer          ║${NC}"
    echo -e "${CYAN}  ╚═══════════════════════════════════════╝${NC}"
    echo ""

    local target
    target=$(detect_platform)
    info "Platform:  ${CYAN}${target}${NC}"
    info "Component: ${CYAN}${COMPONENT}${NC}"

    if [[ "$PM2_ONLY" == true ]]; then
        info "PM2-only mode: skipping binary download"
        sudo mkdir -p /var/log/oxmon
        sudo chown "$(id -u):$(id -g)" /var/log/oxmon
        setup_pm2
        echo ""
        info "${GREEN}PM2 config generated. Done!${NC}"
        return
    fi

    resolve_version

    # Create directories
    sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" /var/log/oxmon
    sudo chown "$(id -u):$(id -g)" /var/log/oxmon
    if [[ "$COMPONENT" == "server" ]]; then
        sudo mkdir -p "$DATA_DIR"
        sudo chown "$(id -u):$(id -g)" "$DATA_DIR"
    fi

    # Download and install binary
    if [[ "$COMPONENT" == "server" ]]; then
        install_binary "oxmon-server" "$target"
        generate_server_config
    else
        install_binary "oxmon-agent" "$target"
        generate_agent_config
    fi

    # PM2 setup
    if [[ "$SETUP_PM2" == true ]]; then
        setup_pm2
    fi

    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Installation complete!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  Config:  ${CYAN}${CONFIG_DIR}/${COMPONENT}.toml${NC}"
    if [[ "$COMPONENT" == "server" ]]; then
        echo -e "  Data:    ${CYAN}${DATA_DIR}/${NC}"
        echo -e "  Logs:    ${CYAN}/var/log/oxmon/server-*.log${NC}"
    else
        echo -e "  Logs:    ${CYAN}/var/log/oxmon/agent-*.log${NC}"
    fi
    echo ""

    if [[ "$SETUP_PM2" == true ]]; then
        echo -e "  PM2 commands:"
        echo -e "    ${CYAN}pm2 status${NC}                    - View process status"
        echo -e "    ${CYAN}pm2 logs oxmon-${COMPONENT}${NC}        - View logs"
        echo -e "    ${CYAN}pm2 restart oxmon-${COMPONENT}${NC}     - Restart"
        echo -e "    ${CYAN}pm2 stop oxmon-${COMPONENT}${NC}        - Stop"
    else
        echo -e "  Start manually:"
        if [[ "$COMPONENT" == "server" ]]; then
            echo -e "    ${CYAN}oxmon-server ${CONFIG_DIR}/server.toml${NC}"
        else
            echo -e "    ${CYAN}oxmon-agent ${CONFIG_DIR}/agent.toml${NC}"
        fi
        echo ""
        echo -e "  Or start with PM2 directly:"
        if [[ "$COMPONENT" == "server" ]]; then
            echo -e "    ${CYAN}pm2 start ${INSTALL_DIR}/oxmon-server --name oxmon-server --log-date-format=\"YYYY-MM-DD HH:mm:ss Z\" -- ${CONFIG_DIR}/server.toml${NC}"
        else
            echo -e "    ${CYAN}pm2 start ${INSTALL_DIR}/oxmon-agent --name oxmon-agent --log-date-format=\"YYYY-MM-DD HH:mm:ss Z\" -- ${CONFIG_DIR}/agent.toml${NC}"
        fi
        echo -e "    ${CYAN}pm2 save && pm2 startup${NC}"
        echo ""
        echo -e "  Or generate PM2 ecosystem config:"
        echo -e "    ${CYAN}curl -fsSL https://raw.githubusercontent.com/${GITHUB_REPO}/main/scripts/install.sh | bash -s -- ${COMPONENT} --pm2-only${NC}"
    fi
    echo ""
}

main
