#!/usr/bin/env bash
set -euo pipefail

HTTP_BASE_URL="http://127.0.0.1:8080"
API_USERNAME="admin"
API_PASSWORD="changeme"
JWT_TOKEN=""

AGENT_PREFIX="mock"
SUMMARY_AGENT=""
SUMMARY_METRIC="cpu.usage"
LIMIT=20

VERBOSE=0

HTTP_STATUS=""
HTTP_BODY=""

declare -a RESULT_ROWS=()
FAIL_COUNT=0

usage() {
    cat <<'EOF'
上报后接口校验脚本：自动检查 metrics / alerts / dashboard 核心接口。

用法:
  scripts/mock-query-check.sh [options]

选项:
  --http-base-url <url>          REST 基础地址 (默认: http://127.0.0.1:8080)
  --username <name>              登录用户名 (默认: admin)
  --password <password>          登录密码 (默认: changeme)
  --jwt-token <token>            直接使用已有 JWT（跳过登录）

  --agent-prefix <prefix>        mock agent 前缀 (默认: mock)
  --summary-agent <agent_id>     指标汇总查询 agent_id（默认: <prefix>-threshold）
  --summary-metric <metric>      指标汇总 metric_name (默认: cpu.usage)
  --limit <n>                    分页接口 limit (默认: 20)

  --verbose                      打印每个接口的原始响应体
  -h, --help                     显示帮助

示例:
  scripts/mock-query-check.sh
  scripts/mock-query-check.sh --agent-prefix mock --summary-metric memory.used_percent
  scripts/mock-query-check.sh --jwt-token "$TOKEN"
EOF
}

log() {
    echo "[mock-check] $*"
}

warn() {
    echo "[mock-check][WARN] $*" >&2
}

die() {
    echo "[mock-check][ERROR] $*" >&2
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

path = sys.argv[1].split('.')
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

json_data_len() {
    local json="$1"
    printf '%s' "$json" | python3 - <<'PY'
import json
import sys

obj = json.load(sys.stdin)
data = obj.get('data')
if isinstance(data, list):
    print(len(data))
elif isinstance(data, dict):
    print(len(data))
elif data is None:
    print(0)
else:
    print(1)
PY
}

json_first_array_item() {
    local json="$1"
    printf '%s' "$json" | python3 - <<'PY'
import json
import sys

obj = json.load(sys.stdin)
data = obj.get('data')
if isinstance(data, list) and data:
    first = data[0]
    if isinstance(first, str):
        print(first)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

row_add() {
    local name="$1"
    local status="$2"
    local note="$3"
    RESULT_ROWS+=("${name}|${status}|${note}")
    if [[ "$status" != "200" ]]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

print_rows() {
    printf '\n%-24s %-7s %s\n' "Endpoint" "HTTP" "Summary"
    printf '%-24s %-7s %s\n' "------------------------" "-------" "------------------------------"
    local row
    for row in "${RESULT_ROWS[@]}"; do
        IFS='|' read -r name status note <<<"$row"
        printf '%-24s %-7s %s\n' "$name" "$status" "$note"
    done
    printf '\n'
}

login_if_needed() {
    if [[ -n "$JWT_TOKEN" ]]; then
        return 0
    fi

    local payload
    payload="$(printf '{"username":"%s","password":"%s"}' "$API_USERNAME" "$API_PASSWORD")"
    http_request "POST" "${HTTP_BASE_URL}/v1/auth/login" "$payload"

    row_add "POST /v1/auth/login" "$HTTP_STATUS" "login"
    [[ "$HTTP_STATUS" == "200" ]] || die "登录失败(${HTTP_STATUS})"

    JWT_TOKEN="$(json_get "$HTTP_BODY" "data.token" || true)"
    [[ -n "$JWT_TOKEN" ]] || die "登录成功但未拿到 token"
}

check_endpoint() {
    local name="$1"
    local method="$2"
    local url="$3"
    local note_on_success="$4"

    http_request "$method" "$url" "" "$JWT_TOKEN"

    if [[ "$VERBOSE" -eq 1 ]]; then
        log "${name} response: ${HTTP_BODY}"
    fi

    if [[ "$HTTP_STATUS" == "200" ]]; then
        row_add "$name" "$HTTP_STATUS" "$note_on_success"
    else
        row_add "$name" "$HTTP_STATUS" "request failed"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --http-base-url)
            HTTP_BASE_URL="$2"
            shift 2
            ;;
        --username)
            API_USERNAME="$2"
            shift 2
            ;;
        --password)
            API_PASSWORD="$2"
            shift 2
            ;;
        --jwt-token)
            JWT_TOKEN="$2"
            shift 2
            ;;
        --agent-prefix)
            AGENT_PREFIX="$2"
            shift 2
            ;;
        --summary-agent)
            SUMMARY_AGENT="$2"
            shift 2
            ;;
        --summary-metric)
            SUMMARY_METRIC="$2"
            shift 2
            ;;
        --limit)
            LIMIT="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
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

need_cmd curl
need_cmd python3
is_positive_int "$LIMIT" || die "--limit 必须是正整数"

if [[ -z "$SUMMARY_AGENT" ]]; then
    SUMMARY_AGENT="${AGENT_PREFIX}-threshold"
fi

login_if_needed

check_endpoint "GET /v1/health" "GET" "${HTTP_BASE_URL}/v1/health" "service reachable"

http_request "GET" "${HTTP_BASE_URL}/v1/metrics/agents?limit=${LIMIT}&offset=0" "" "$JWT_TOKEN"
if [[ "$HTTP_STATUS" == "200" ]]; then
    agent_count="$(json_data_len "$HTTP_BODY")"
    row_add "GET /v1/metrics/agents" "$HTTP_STATUS" "agents=${agent_count}"
    fallback_agent="$(json_first_array_item "$HTTP_BODY" || true)"
    if [[ -z "$fallback_agent" ]]; then
        warn "metrics/agents 返回为空，metric summary 可能无数据"
    fi
else
    row_add "GET /v1/metrics/agents" "$HTTP_STATUS" "request failed"
fi

http_request "GET" "${HTTP_BASE_URL}/v1/metrics/names?limit=${LIMIT}&offset=0" "" "$JWT_TOKEN"
if [[ "$HTTP_STATUS" == "200" ]]; then
    metric_name_count="$(json_data_len "$HTTP_BODY")"
    row_add "GET /v1/metrics/names" "$HTTP_STATUS" "names=${metric_name_count}"
else
    row_add "GET /v1/metrics/names" "$HTTP_STATUS" "request failed"
fi

http_request "GET" "${HTTP_BASE_URL}/v1/metrics?limit=${LIMIT}&offset=0" "" "$JWT_TOKEN"
if [[ "$HTTP_STATUS" == "200" ]]; then
    metric_rows="$(json_data_len "$HTTP_BODY")"
    row_add "GET /v1/metrics" "$HTTP_STATUS" "rows=${metric_rows}"
else
    row_add "GET /v1/metrics" "$HTTP_STATUS" "request failed"
fi

summary_agent="$SUMMARY_AGENT"
if [[ -z "$summary_agent" && -n "${fallback_agent:-}" ]]; then
    summary_agent="$fallback_agent"
fi

http_request "GET" "${HTTP_BASE_URL}/v1/metrics/summary?agent_id=${summary_agent}&metric_name=${SUMMARY_METRIC}" "" "$JWT_TOKEN"
if [[ "$HTTP_STATUS" == "200" ]]; then
    summary_count="$(json_get "$HTTP_BODY" "data.count" || echo "0")"
    summary_avg="$(json_get "$HTTP_BODY" "data.avg" || echo "0")"
    row_add "GET /v1/metrics/summary" "$HTTP_STATUS" "agent=${summary_agent} count=${summary_count} avg=${summary_avg}"
else
    row_add "GET /v1/metrics/summary" "$HTTP_STATUS" "agent=${summary_agent}"
fi

http_request "GET" "${HTTP_BASE_URL}/v1/alerts/summary" "" "$JWT_TOKEN"
if [[ "$HTTP_STATUS" == "200" ]]; then
    alerts_total="$(json_get "$HTTP_BODY" "data.total" || echo "0")"
    row_add "GET /v1/alerts/summary" "$HTTP_STATUS" "total=${alerts_total}"
else
    row_add "GET /v1/alerts/summary" "$HTTP_STATUS" "request failed"
fi

http_request "GET" "${HTTP_BASE_URL}/v1/alerts/active?limit=${LIMIT}&offset=0" "" "$JWT_TOKEN"
if [[ "$HTTP_STATUS" == "200" ]]; then
    alerts_active="$(json_data_len "$HTTP_BODY")"
    row_add "GET /v1/alerts/active" "$HTTP_STATUS" "active=${alerts_active}"
else
    row_add "GET /v1/alerts/active" "$HTTP_STATUS" "request failed"
fi

http_request "GET" "${HTTP_BASE_URL}/v1/alerts/history?limit=${LIMIT}&offset=0" "" "$JWT_TOKEN"
if [[ "$HTTP_STATUS" == "200" ]]; then
    alerts_history="$(json_data_len "$HTTP_BODY")"
    row_add "GET /v1/alerts/history" "$HTTP_STATUS" "history=${alerts_history}"
else
    row_add "GET /v1/alerts/history" "$HTTP_STATUS" "request failed"
fi

http_request "GET" "${HTTP_BASE_URL}/v1/dashboard/overview" "" "$JWT_TOKEN"
if [[ "$HTTP_STATUS" == "200" ]]; then
    active_agents="$(json_get "$HTTP_BODY" "data.active_agents" || echo "0")"
    total_agents="$(json_get "$HTTP_BODY" "data.total_agents" || echo "0")"
    row_add "GET /v1/dashboard/overview" "$HTTP_STATUS" "active=${active_agents} total=${total_agents}"
else
    row_add "GET /v1/dashboard/overview" "$HTTP_STATUS" "request failed"
fi

print_rows

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    warn "校验完成：${FAIL_COUNT} 个接口非 200"
    exit 1
fi

log "校验完成：全部接口返回 200"

