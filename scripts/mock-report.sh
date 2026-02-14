#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SERVER_ENDPOINT="127.0.0.1:9090"
HTTP_BASE_URL="http://127.0.0.1:8080"
HEALTH_URL="http://127.0.0.1:8080/v1/health"

AGENT_COUNT=5
AGENT_PREFIX="mock-agent"
DURATION_SECS=60
INTERVAL_SECS=2
BUFFER_MAX_SIZE=2000
BUILD_MODE="debug"

BOOTSTRAP_AUTH=0
API_USERNAME="admin"
API_PASSWORD="changeme"
AUTH_TOKEN_FILE=""

KEEP_TEMP=1
TMP_DIR=""
CFG_DIR=""
LOG_DIR=""
AGENT_BIN=""
JWT_TOKEN=""

HTTP_STATUS=""
HTTP_BODY=""

declare -a PIDS=()

usage() {
    cat <<'EOF'
模拟真实场景，批量启动多个本地 Agent 上报指标（通过 gRPC ReportMetrics）。

用法:
  scripts/mock-report.sh [options]

选项:
  --server-endpoint <host:port>   gRPC 地址 (默认: 127.0.0.1:9090)
  --http-base-url <url>           REST 基础地址 (默认: http://127.0.0.1:8080)
  --health-url <url>              健康检查地址 (默认: http://127.0.0.1:8080/v1/health)

  --agent-count <n>               Agent 数量 (默认: 5)
  --agent-prefix <prefix>         Agent ID 前缀 (默认: mock-agent)
  --duration-secs <n>             运行时长秒数 (默认: 60)
  --interval-secs <n>             采集间隔秒数 (默认: 2)
  --buffer-max-size <n>           Agent 缓冲区大小 (默认: 2000)

  --build-mode <debug|release|skip>
                                  启动前构建方式 (默认: debug)

  --bootstrap-auth                自动登录 REST 并为每个 Agent 创建/刷新白名单 token
  --api-username <name>           bootstrap-auth 登录用户名 (默认: admin)
  --api-password <password>       bootstrap-auth 登录密码 (默认: changeme)
  --auth-token-file <file>        从文件读取 token（格式: agent_id=token）

  --cleanup-temp                  结束后自动清理临时目录（默认保留，便于排查）
  -h, --help                      显示帮助

示例:
  # 默认：5 个 Agent，上报 60 秒
  scripts/mock-report.sh

  # 20 个 Agent，上报 3 分钟
  scripts/mock-report.sh --agent-count 20 --duration-secs 180

  # 开启服务端 require_agent_auth=true 时，自动创建白名单 token
  scripts/mock-report.sh --bootstrap-auth

  # 使用预先准备好的 token 文件
  scripts/mock-report.sh --auth-token-file ./tokens.env
EOF
}

log() {
    echo "[mock-report] $*"
}

warn() {
    echo "[mock-report][WARN] $*" >&2
}

die() {
    echo "[mock-report][ERROR] $*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

is_positive_int() {
    [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -gt 0 ]]
}

http_request() {
    local method="$1"
    local url="$2"
    local payload="${3:-}"
    local bearer="${4:-}"

    local body_file
    body_file="$(mktemp "${TMPDIR:-/tmp}/oxmon-http.XXXXXX")"

    local -a curl_args
    curl_args=(
        -sS
        -o "$body_file"
        -w "%{http_code}"
        -X "$method"
        -H "Accept: application/json"
    )

    if [[ -n "$payload" ]]; then
        curl_args+=( -H "Content-Type: application/json" -d "$payload" )
    fi

    if [[ -n "$bearer" ]]; then
        curl_args+=( -H "Authorization: Bearer ${bearer}" )
    fi

    if ! HTTP_STATUS="$(curl "${curl_args[@]}" "$url")"; then
        rm -f "$body_file"
        die "请求失败: ${method} ${url}"
    fi

    HTTP_BODY="$(cat "$body_file")"
    rm -f "$body_file"
}

json_get() {
    local json="$1"
    local path="$2"

    printf '%s' "$json" | python3 - "$path" <<'PY'
import json
import sys

path = sys.argv[1].split(".")
obj = json.load(sys.stdin)

for part in path:
    if isinstance(obj, dict):
        obj = obj.get(part)
    else:
        obj = None
    if obj is None:
        break

if obj is None:
    raise SystemExit(1)

if isinstance(obj, (dict, list)):
    print(json.dumps(obj, ensure_ascii=False))
else:
    print(obj)
PY
}

find_whitelist_id_by_agent() {
    local json="$1"
    local target_agent="$2"

    printf '%s' "$json" | python3 - "$target_agent" <<'PY'
import json
import sys

target = sys.argv[1]
obj = json.load(sys.stdin)

for item in obj.get("data") or []:
    if item.get("agent_id") == target:
        print(item.get("id", ""))
        raise SystemExit(0)

raise SystemExit(1)
PY
}

get_token_from_file() {
    local agent_id="$1"

    [[ -n "$AUTH_TOKEN_FILE" ]] || return 1
    [[ -f "$AUTH_TOKEN_FILE" ]] || die "token 文件不存在: $AUTH_TOKEN_FILE"

    awk -F '=' -v id="$agent_id" '
        {
            line = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line == "" || line ~ /^#/) {
                next
            }
            pos = index(line, "=")
            if (pos == 0) {
                next
            }
            key = substr(line, 1, pos - 1)
            val = substr(line, pos + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
            if (key == id) {
                print val
                found = 1
                exit 0
            }
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "$AUTH_TOKEN_FILE"
}

login_and_get_jwt() {
    local payload
    payload="$(printf '{"username":"%s","password":"%s"}' "$API_USERNAME" "$API_PASSWORD")"

    http_request "POST" "${HTTP_BASE_URL}/v1/auth/login" "$payload"
    [[ "$HTTP_STATUS" == "200" ]] || die "登录失败(${HTTP_STATUS})，请检查用户名密码"

    JWT_TOKEN="$(json_get "$HTTP_BODY" "data.token" || true)"
    [[ -n "$JWT_TOKEN" ]] || die "登录成功但未拿到 token"
}

create_or_refresh_agent_token() {
    local agent_id="$1"
    local token=""

    local payload
    payload="$(printf '{"agent_id":"%s","description":"generated-by-scripts/mock-report.sh"}' "$agent_id")"
    http_request "POST" "${HTTP_BASE_URL}/v1/agents/whitelist" "$payload" "$JWT_TOKEN"

    if [[ "$HTTP_STATUS" == "200" ]]; then
        token="$(json_get "$HTTP_BODY" "data.token" || true)"
        [[ -n "$token" ]] || die "创建白名单成功但未返回 token: ${agent_id}"
        printf '%s\n' "$token"
        return 0
    fi

    if [[ "$HTTP_STATUS" != "409" ]]; then
        die "创建白名单失败(${HTTP_STATUS}): ${agent_id}"
    fi

    http_request "GET" "${HTTP_BASE_URL}/v1/agents/whitelist?limit=1000&offset=0" "" "$JWT_TOKEN"
    [[ "$HTTP_STATUS" == "200" ]] || die "查询白名单失败(${HTTP_STATUS})"

    local whitelist_id
    whitelist_id="$(find_whitelist_id_by_agent "$HTTP_BODY" "$agent_id" || true)"
    [[ -n "$whitelist_id" ]] || die "白名单中未找到重复 Agent: ${agent_id}"

    http_request "POST" "${HTTP_BASE_URL}/v1/agents/whitelist/${whitelist_id}/token" "" "$JWT_TOKEN"
    [[ "$HTTP_STATUS" == "200" ]] || die "刷新 token 失败(${HTTP_STATUS}): ${agent_id}"

    token="$(json_get "$HTTP_BODY" "data.token" || true)"
    [[ -n "$token" ]] || die "刷新 token 成功但未返回 token: ${agent_id}"

    printf '%s\n' "$token"
}

write_agent_config() {
    local cfg_path="$1"
    local agent_id="$2"
    local auth_token="${3:-}"

    {
        echo "agent_id = \"${agent_id}\""
        echo "server_endpoint = \"${SERVER_ENDPOINT}\""
        echo "collection_interval_secs = ${INTERVAL_SECS}"
        echo "buffer_max_size = ${BUFFER_MAX_SIZE}"
        if [[ -n "$auth_token" ]]; then
            echo "auth_token = \"${auth_token}\""
        fi
    } >"$cfg_path"
}

build_agent_bin() {
    if [[ "$BUILD_MODE" == "skip" ]]; then
        if [[ -x "${ROOT_DIR}/target/debug/oxmon-agent" ]]; then
            AGENT_BIN="${ROOT_DIR}/target/debug/oxmon-agent"
            return 0
        fi
        if [[ -x "${ROOT_DIR}/target/release/oxmon-agent" ]]; then
            AGENT_BIN="${ROOT_DIR}/target/release/oxmon-agent"
            return 0
        fi
        die "build-mode=skip 但未找到现成二进制，请先构建"
    fi

    need_cmd cargo
    case "$BUILD_MODE" in
        debug)
            log "构建 oxmon-agent (debug)..."
            cargo build -p oxmon-agent
            AGENT_BIN="${ROOT_DIR}/target/debug/oxmon-agent"
            ;;
        release)
            log "构建 oxmon-agent (release)..."
            cargo build -p oxmon-agent --release
            AGENT_BIN="${ROOT_DIR}/target/release/oxmon-agent"
            ;;
        *)
            die "无效 build-mode: $BUILD_MODE"
            ;;
    esac
}

stop_agents() {
    local pid
    for pid in "${PIDS[@]:-}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
        fi
    done

    for pid in "${PIDS[@]:-}"; do
        if [[ -n "$pid" ]]; then
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done

    PIDS=()
}

cleanup() {
    stop_agents

    if [[ -n "$TMP_DIR" ]]; then
        if [[ "$KEEP_TEMP" -eq 1 ]]; then
            log "临时目录保留: $TMP_DIR"
        else
            rm -rf "$TMP_DIR"
        fi
    fi
}

trap cleanup EXIT INT TERM

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-endpoint)
            SERVER_ENDPOINT="$2"
            shift 2
            ;;
        --http-base-url)
            HTTP_BASE_URL="$2"
            shift 2
            ;;
        --health-url)
            HEALTH_URL="$2"
            shift 2
            ;;
        --agent-count)
            AGENT_COUNT="$2"
            shift 2
            ;;
        --agent-prefix)
            AGENT_PREFIX="$2"
            shift 2
            ;;
        --duration-secs)
            DURATION_SECS="$2"
            shift 2
            ;;
        --interval-secs)
            INTERVAL_SECS="$2"
            shift 2
            ;;
        --buffer-max-size)
            BUFFER_MAX_SIZE="$2"
            shift 2
            ;;
        --build-mode)
            BUILD_MODE="$2"
            shift 2
            ;;
        --bootstrap-auth)
            BOOTSTRAP_AUTH=1
            shift
            ;;
        --api-username)
            API_USERNAME="$2"
            shift 2
            ;;
        --api-password)
            API_PASSWORD="$2"
            shift 2
            ;;
        --auth-token-file)
            AUTH_TOKEN_FILE="$2"
            shift 2
            ;;
        --cleanup-temp)
            KEEP_TEMP=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "未知参数: $1 (使用 --help 查看帮助)"
            ;;
    esac
done

is_positive_int "$AGENT_COUNT" || die "--agent-count 必须是正整数"
is_positive_int "$DURATION_SECS" || die "--duration-secs 必须是正整数"
is_positive_int "$INTERVAL_SECS" || die "--interval-secs 必须是正整数"
is_positive_int "$BUFFER_MAX_SIZE" || die "--buffer-max-size 必须是正整数"

if [[ "$BOOTSTRAP_AUTH" -eq 1 && -n "$AUTH_TOKEN_FILE" ]]; then
    die "--bootstrap-auth 与 --auth-token-file 不能同时使用"
fi

need_cmd curl
if [[ "$BOOTSTRAP_AUTH" -eq 1 ]]; then
    need_cmd python3
fi
if [[ -n "$AUTH_TOKEN_FILE" ]]; then
    [[ -f "$AUTH_TOKEN_FILE" ]] || die "token 文件不存在: $AUTH_TOKEN_FILE"
fi

build_agent_bin

if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    log "服务健康检查通过: ${HEALTH_URL}"
else
    warn "健康检查失败: ${HEALTH_URL}（仍继续执行，若 gRPC 不通将只会本地缓冲）"
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/oxmon-mock-report.XXXXXX")"
CFG_DIR="${TMP_DIR}/configs"
LOG_DIR="${TMP_DIR}/logs"
mkdir -p "$CFG_DIR" "$LOG_DIR"

if [[ "$BOOTSTRAP_AUTH" -eq 1 ]]; then
    log "开始登录并自动准备白名单 token..."
    login_and_get_jwt
fi

width=${#AGENT_COUNT}
(( width < 2 )) && width=2

log "启动 ${AGENT_COUNT} 个 Agent (interval=${INTERVAL_SECS}s, duration=${DURATION_SECS}s)..."

for ((i = 1; i <= AGENT_COUNT; i++)); do
    printf -v seq "%0${width}d" "$i"
    agent_id="${AGENT_PREFIX}-${seq}"
    cfg_path="${CFG_DIR}/${agent_id}.toml"
    log_path="${LOG_DIR}/${agent_id}.log"

    auth_token=""
    if [[ "$BOOTSTRAP_AUTH" -eq 1 ]]; then
        auth_token="$(create_or_refresh_agent_token "$agent_id")"
    elif [[ -n "$AUTH_TOKEN_FILE" ]]; then
        auth_token="$(get_token_from_file "$agent_id" || true)"
        [[ -n "$auth_token" ]] || warn "未在 token 文件中找到 ${agent_id}，将按无 token 启动"
    fi

    write_agent_config "$cfg_path" "$agent_id" "$auth_token"

    "$AGENT_BIN" "$cfg_path" >"$log_path" 2>&1 &
    PIDS+=("$!")
done

log "开始上报，等待 ${DURATION_SECS}s..."
sleep "$DURATION_SECS"

stop_agents

reported_count="$( (grep -h "Metrics reported" "${LOG_DIR}"/*.log 2>/dev/null || true) | wc -l | tr -d '[:space:]')"
connected_count="$( (grep -h "Connected to server" "${LOG_DIR}"/*.log 2>/dev/null || true) | wc -l | tr -d '[:space:]')"

log "完成。连接日志条数: ${connected_count}，上报成功日志条数: ${reported_count}"
log "配置目录: ${CFG_DIR}"
log "日志目录: ${LOG_DIR}"

if [[ "$reported_count" == "0" ]]; then
    warn "未发现成功上报日志，请检查 gRPC 地址(${SERVER_ENDPOINT})和服务端是否启动"
fi
