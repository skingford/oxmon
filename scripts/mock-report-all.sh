#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

HTTP_BASE_URL="http://127.0.0.1:8080"
HEALTH_URL="http://127.0.0.1:8080/v1/health"
GRPC_ENDPOINT="127.0.0.1:9090"

SCENARIO="all"
AGENT_COUNT=5
AGENT_PREFIX="mock"
PAUSE_MS=120
BUILD_MODE="debug"

AUTO_AUTH=0
API_USERNAME="admin"
API_PASSWORD="changeme"

AUTH_TOKEN=""
AUTH_TOKEN_FILE=""

WAIT_ALERT_SECS=2
PRINT_PAYLOAD=0

TMP_DIR=""
KEEP_TEMP=1

HTTP_STATUS=""
HTTP_BODY=""
JWT_TOKEN=""

usage() {
    cat <<'EOF'
一键上报“所有场景”测试数据（正常 + 告警触发 + 可选鉴权），用于本地接口联调。

用法:
  scripts/mock-report-all.sh [options]

选项:
  --scenario <name>              all|baseline|threshold|rate|trend|cert (默认: all)
  --agent-count <n>              baseline Agent 数量 (默认: 5)
  --agent-prefix <prefix>        Agent 前缀 (默认: mock)
  --pause-ms <n>                 批次间隔毫秒 (默认: 120)

  --grpc-endpoint <host:port>    gRPC 地址 (默认: 127.0.0.1:9090)
  --http-base-url <url>          REST 基础地址 (默认: http://127.0.0.1:8080)
  --health-url <url>             健康检查 URL (默认: http://127.0.0.1:8080/v1/health)

  --build-mode <debug|release|skip>
                                 构建模式 (默认: debug)

  --auto-auth                    自动登录并创建/刷新白名单 token
  --api-username <name>          auto-auth 用户名 (默认: admin)
  --api-password <password>      auto-auth 密码 (默认: changeme)
  --auth-token <token>           所有 Agent 复用同一 token
  --auth-token-file <path>       token 文件（agent_id=token）

  --wait-alert-secs <n>          上报后等待告警入库秒数 (默认: 2)
  --print-payload                打印每个批次摘要

  --cleanup-temp                 自动删除临时目录
  -h, --help                     显示帮助

示例:
  # 全场景（无鉴权）
  scripts/mock-report-all.sh

  # 全场景（服务端开启 require_agent_auth=true）
  scripts/mock-report-all.sh --auto-auth

  # 只打 rate 场景并打印 payload
  scripts/mock-report-all.sh --scenario rate --print-payload
EOF
}

log() {
    echo "[mock-all] $*"
}

warn() {
    echo "[mock-all][WARN] $*" >&2
}

die() {
    echo "[mock-all][ERROR] $*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

is_positive_int() {
    [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -gt 0 ]]
}

is_non_negative_int() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

cleanup() {
    if [[ -n "$TMP_DIR" ]]; then
        if [[ "$KEEP_TEMP" -eq 1 ]]; then
            log "临时目录保留: $TMP_DIR"
        else
            rm -rf "$TMP_DIR"
        fi
    fi
}

trap cleanup EXIT INT TERM

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

agent_ids_for_scenario() {
    local scenario="$1"
    local prefix="$2"
    local count="$3"

    local width="${#count}"
    (( width < 2 )) && width=2

    case "$scenario" in
        baseline)
            for ((i = 1; i <= count; i++)); do
                printf '%s-normal-%0*d\n' "$prefix" "$width" "$i"
            done
            ;;
        threshold)
            printf '%s-threshold\n' "$prefix"
            ;;
        rate)
            printf '%s-rate\n' "$prefix"
            ;;
        trend)
            printf '%s-trend\n' "$prefix"
            ;;
        cert)
            printf 'cert-checker\n'
            ;;
        all)
            for ((i = 1; i <= count; i++)); do
                printf '%s-normal-%0*d\n' "$prefix" "$width" "$i"
            done
            printf '%s-threshold\n' "$prefix"
            printf '%s-rate\n' "$prefix"
            printf '%s-trend\n' "$prefix"
            printf 'cert-checker\n'
            ;;
        *)
            die "未知场景: $scenario"
            ;;
    esac
}

login_and_get_jwt() {
    local payload
    payload="$(printf '{"username":"%s","password":"%s"}' "$API_USERNAME" "$API_PASSWORD")"

    http_request "POST" "${HTTP_BASE_URL}/v1/auth/login" "$payload"
    [[ "$HTTP_STATUS" == "200" ]] || die "登录失败(${HTTP_STATUS})"

    JWT_TOKEN="$(json_get "$HTTP_BODY" "data.token" || true)"
    [[ -n "$JWT_TOKEN" ]] || die "登录成功但未拿到 token"
}

ensure_whitelist_token() {
    local agent_id="$1"
    local token=""

    local payload
    payload="$(printf '{"agent_id":"%s","description":"generated-by-scripts/mock-report-all.sh"}' "$agent_id")"
    http_request "POST" "${HTTP_BASE_URL}/v1/agents/whitelist" "$payload" "$JWT_TOKEN"

    if [[ "$HTTP_STATUS" == "200" ]]; then
        token="$(json_get "$HTTP_BODY" "data.token" || true)"
        [[ -n "$token" ]] || die "创建白名单成功但无 token: ${agent_id}"
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
    [[ -n "$whitelist_id" ]] || die "白名单中找不到 Agent: ${agent_id}"

    http_request "POST" "${HTTP_BASE_URL}/v1/agents/whitelist/${whitelist_id}/token" "" "$JWT_TOKEN"
    [[ "$HTTP_STATUS" == "200" ]] || die "刷新 token 失败(${HTTP_STATUS}): ${agent_id}"

    token="$(json_get "$HTTP_BODY" "data.token" || true)"
    [[ -n "$token" ]] || die "刷新 token 成功但无 token: ${agent_id}"
    printf '%s\n' "$token"
}

build_mock_binary() {
    need_cmd cargo
    case "$BUILD_MODE" in
        debug)
            log "构建 oxmon-mock-report (debug)..."
            cargo build -p oxmon-agent --bin oxmon-mock-report
            ;;
        release)
            log "构建 oxmon-mock-report (release)..."
            cargo build -p oxmon-agent --bin oxmon-mock-report --release
            ;;
        skip)
            ;;
        *)
            die "无效 build-mode: $BUILD_MODE"
            ;;
    esac
}

mock_binary_path() {
    if [[ "$BUILD_MODE" == "release" ]]; then
        printf '%s/target/release/oxmon-mock-report\n' "$ROOT_DIR"
    else
        printf '%s/target/debug/oxmon-mock-report\n' "$ROOT_DIR"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)
            SCENARIO="$2"
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
        --pause-ms)
            PAUSE_MS="$2"
            shift 2
            ;;
        --grpc-endpoint)
            GRPC_ENDPOINT="$2"
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
        --build-mode)
            BUILD_MODE="$2"
            shift 2
            ;;
        --auto-auth)
            AUTO_AUTH=1
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
        --auth-token)
            AUTH_TOKEN="$2"
            shift 2
            ;;
        --auth-token-file)
            AUTH_TOKEN_FILE="$2"
            shift 2
            ;;
        --wait-alert-secs)
            WAIT_ALERT_SECS="$2"
            shift 2
            ;;
        --print-payload)
            PRINT_PAYLOAD=1
            shift
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
            die "未知参数: $1"
            ;;
    esac
done

is_positive_int "$AGENT_COUNT" || die "--agent-count 必须是正整数"
is_non_negative_int "$PAUSE_MS" || die "--pause-ms 必须是非负整数"
is_positive_int "$WAIT_ALERT_SECS" || die "--wait-alert-secs 必须是正整数"

case "$SCENARIO" in
    all|baseline|threshold|rate|trend|cert) ;;
    *) die "--scenario 仅支持 all|baseline|threshold|rate|trend|cert" ;;
esac

if [[ "$AUTO_AUTH" -eq 1 ]]; then
    need_cmd python3
fi
need_cmd curl

if [[ -n "$AUTH_TOKEN" && -n "$AUTH_TOKEN_FILE" ]]; then
    die "--auth-token 与 --auth-token-file 不能同时使用"
fi

build_mock_binary
MOCK_BIN="$(mock_binary_path)"
[[ -x "$MOCK_BIN" ]] || die "找不到可执行文件: $MOCK_BIN"

if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    log "健康检查通过: ${HEALTH_URL}"
else
    warn "健康检查失败: ${HEALTH_URL}（继续执行）"
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/oxmon-mock-all.XXXXXX")"
TOKENS_FILE="${TMP_DIR}/tokens.env"

if [[ "$AUTO_AUTH" -eq 1 ]]; then
    log "auto-auth: 登录并准备白名单 token"
    login_and_get_jwt

    while IFS= read -r agent_id; do
        token="$(ensure_whitelist_token "$agent_id")"
        printf '%s=%s\n' "$agent_id" "$token" >>"$TOKENS_FILE"
    done < <(agent_ids_for_scenario "$SCENARIO" "$AGENT_PREFIX" "$AGENT_COUNT")

    AUTH_TOKEN_FILE="$TOKENS_FILE"
    log "token 文件生成: ${AUTH_TOKEN_FILE}"
fi

cmd=(
    "$MOCK_BIN"
    --server-endpoint "$GRPC_ENDPOINT"
    --scenario "$SCENARIO"
    --agent-count "$AGENT_COUNT"
    --agent-prefix "$AGENT_PREFIX"
    --pause-ms "$PAUSE_MS"
)

if [[ -n "$AUTH_TOKEN" ]]; then
    cmd+=( --auth-token "$AUTH_TOKEN" )
fi

if [[ -n "$AUTH_TOKEN_FILE" ]]; then
    cmd+=( --auth-token-file "$AUTH_TOKEN_FILE" )
fi

if [[ "$PRINT_PAYLOAD" -eq 1 ]]; then
    cmd+=( --print-payload )
fi

log "开始上报场景: ${SCENARIO}"
"${cmd[@]}"

log "等待 ${WAIT_ALERT_SECS}s，便于告警入库..."
sleep "$WAIT_ALERT_SECS"

if [[ "$AUTO_AUTH" -eq 1 ]]; then
    bearer="$JWT_TOKEN"
    http_request "GET" "${HTTP_BASE_URL}/v1/alerts/summary" "" "$bearer"
    if [[ "$HTTP_STATUS" == "200" ]]; then
        total_alerts="$(json_get "$HTTP_BODY" "data.total" || echo "?")"
        log "alerts summary total=${total_alerts}"
    else
        warn "查询 alerts summary 失败(${HTTP_STATUS})"
    fi

    http_request "GET" "${HTTP_BASE_URL}/v1/alerts/active?limit=20&offset=0" "" "$bearer"
    if [[ "$HTTP_STATUS" == "200" ]]; then
        active_count="$(printf '%s' "$HTTP_BODY" | python3 - <<'PY'
import json
import sys
obj = json.load(sys.stdin)
items = obj.get("data") or []
print(len(items))
PY
        )"
        log "active alerts count=${active_count}"
    else
        warn "查询 active alerts 失败(${HTTP_STATUS})"
    fi
else
    log "未启用 auto-auth，跳过 alerts API 查询"
fi

log "完成。你可以继续用以下接口验证："
log "  - GET ${HTTP_BASE_URL}/v1/metrics"
log "  - GET ${HTTP_BASE_URL}/v1/metrics/summary"
log "  - GET ${HTTP_BASE_URL}/v1/alerts/history"
log "  - GET ${HTTP_BASE_URL}/v1/dashboard/overview"
