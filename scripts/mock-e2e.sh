#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_SCRIPT="${ROOT_DIR}/scripts/mock-report-all.sh"
CHECK_SCRIPT="${ROOT_DIR}/scripts/mock-query-check.sh"

HTTP_BASE_URL="http://127.0.0.1:8080"
HEALTH_URL="http://127.0.0.1:8080/v1/health"
GRPC_ENDPOINT="127.0.0.1:9090"

SCENARIO="all"
AGENT_COUNT=5
AGENT_PREFIX="mock"
PAUSE_MS=120
BUILD_MODE="debug"
WAIT_ALERT_SECS=2

AUTO_AUTH=0
API_USERNAME="admin"
API_PASSWORD="changeme"
JWT_TOKEN=""

AUTH_TOKEN=""
AUTH_TOKEN_FILE=""

SUMMARY_AGENT=""
SUMMARY_METRIC="cpu.usage"
LIMIT=20

PRINT_PAYLOAD=0
VERBOSE_QUERY=0
CLEANUP_TEMP=0

usage() {
    cat <<'EOF'
一键执行：模拟上报 + 接口校验。

流程:
  1) 调用 scripts/mock-report-all.sh 上报测试数据
  2) 调用 scripts/mock-query-check.sh 校验核心接口

用法:
  scripts/mock-e2e.sh [options]

选项:
  --scenario <name>              all|baseline|threshold|rate|trend|cert (默认: all)
  --agent-count <n>              baseline Agent 数量 (默认: 5)
  --agent-prefix <prefix>        Agent 前缀 (默认: mock)
  --pause-ms <n>                 上报批次间隔毫秒 (默认: 120)
  --wait-alert-secs <n>          上报后等待告警入库秒数 (默认: 2)

  --grpc-endpoint <host:port>    gRPC 地址 (默认: 127.0.0.1:9090)
  --http-base-url <url>          REST 基础地址 (默认: http://127.0.0.1:8080)
  --health-url <url>             健康检查 URL (默认: http://127.0.0.1:8080/v1/health)
  --build-mode <debug|release|skip>
                                 上报器构建模式 (默认: debug)

  --auto-auth                    上报时自动登录并创建/刷新白名单 token
  --username <name>              REST 登录用户名 (默认: admin)
  --password <password>          REST 登录密码 (默认: changeme)
  --jwt-token <token>            校验阶段直接使用 JWT（跳过登录）
  --auth-token <token>           上报阶段：全部 Agent 使用一个 gRPC token
  --auth-token-file <path>       上报阶段：按 agent_id=token 映射 token

  --summary-agent <agent_id>     指标汇总查询 Agent (默认: <prefix>-threshold)
  --summary-metric <metric>      指标汇总 metric_name (默认: cpu.usage)
  --limit <n>                    校验分页接口 limit (默认: 20)

  --print-payload                上报阶段打印每个批次摘要
  --verbose-query                校验阶段打印接口原始响应
  --cleanup-temp                 清理中间临时目录

  -h, --help                     显示帮助

示例:
  scripts/mock-e2e.sh
  scripts/mock-e2e.sh --auto-auth --scenario all --agent-count 10
  scripts/mock-e2e.sh --scenario rate --summary-metric memory.used_percent
EOF
}

log() {
    echo "[mock-e2e] $*"
}

die() {
    echo "[mock-e2e][ERROR] $*" >&2
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
        --wait-alert-secs)
            WAIT_ALERT_SECS="$2"
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
        --auth-token)
            AUTH_TOKEN="$2"
            shift 2
            ;;
        --auth-token-file)
            AUTH_TOKEN_FILE="$2"
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
        --print-payload)
            PRINT_PAYLOAD=1
            shift
            ;;
        --verbose-query)
            VERBOSE_QUERY=1
            shift
            ;;
        --cleanup-temp)
            CLEANUP_TEMP=1
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

need_cmd bash
[[ -x "$REPORT_SCRIPT" ]] || die "脚本不可执行: $REPORT_SCRIPT"
[[ -x "$CHECK_SCRIPT" ]] || die "脚本不可执行: $CHECK_SCRIPT"

case "$SCENARIO" in
    all|baseline|threshold|rate|trend|cert) ;;
    *) die "--scenario 仅支持 all|baseline|threshold|rate|trend|cert" ;;
esac

case "$BUILD_MODE" in
    debug|release|skip) ;;
    *) die "--build-mode 仅支持 debug|release|skip" ;;
esac

is_positive_int "$AGENT_COUNT" || die "--agent-count 必须是正整数"
is_non_negative_int "$PAUSE_MS" || die "--pause-ms 必须是非负整数"
is_positive_int "$WAIT_ALERT_SECS" || die "--wait-alert-secs 必须是正整数"
is_positive_int "$LIMIT" || die "--limit 必须是正整数"

if [[ -n "$AUTH_TOKEN" && -n "$AUTH_TOKEN_FILE" ]]; then
    die "--auth-token 与 --auth-token-file 不能同时使用"
fi

report_cmd=(
    "$REPORT_SCRIPT"
    --scenario "$SCENARIO"
    --agent-count "$AGENT_COUNT"
    --agent-prefix "$AGENT_PREFIX"
    --pause-ms "$PAUSE_MS"
    --grpc-endpoint "$GRPC_ENDPOINT"
    --http-base-url "$HTTP_BASE_URL"
    --health-url "$HEALTH_URL"
    --build-mode "$BUILD_MODE"
    --wait-alert-secs "$WAIT_ALERT_SECS"
)

if [[ "$AUTO_AUTH" -eq 1 ]]; then
    report_cmd+=( --auto-auth --api-username "$API_USERNAME" --api-password "$API_PASSWORD" )
fi

if [[ -n "$AUTH_TOKEN" ]]; then
    report_cmd+=( --auth-token "$AUTH_TOKEN" )
fi

if [[ -n "$AUTH_TOKEN_FILE" ]]; then
    report_cmd+=( --auth-token-file "$AUTH_TOKEN_FILE" )
fi

if [[ "$PRINT_PAYLOAD" -eq 1 ]]; then
    report_cmd+=( --print-payload )
fi

if [[ "$CLEANUP_TEMP" -eq 1 ]]; then
    report_cmd+=( --cleanup-temp )
fi

check_cmd=(
    "$CHECK_SCRIPT"
    --http-base-url "$HTTP_BASE_URL"
    --agent-prefix "$AGENT_PREFIX"
    --summary-metric "$SUMMARY_METRIC"
    --limit "$LIMIT"
)

if [[ -n "$SUMMARY_AGENT" ]]; then
    check_cmd+=( --summary-agent "$SUMMARY_AGENT" )
fi

if [[ -n "$JWT_TOKEN" ]]; then
    check_cmd+=( --jwt-token "$JWT_TOKEN" )
else
    check_cmd+=( --username "$API_USERNAME" --password "$API_PASSWORD" )
fi

if [[ "$VERBOSE_QUERY" -eq 1 ]]; then
    check_cmd+=( --verbose )
fi

log "步骤 1/2：执行上报场景 ${SCENARIO}"
"${report_cmd[@]}"

log "步骤 2/2：执行接口校验"
"${check_cmd[@]}"

log "E2E 完成：上报与校验均通过"

