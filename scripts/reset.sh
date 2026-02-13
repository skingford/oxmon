#!/bin/bash

# oxmon 重置和初始化脚本
# 使用方法:
#   ./scripts/reset.sh config          # 只清理规则和渠道（保留监控数据）
#   ./scripts/reset.sh full            # 完全重置（删除所有数据）
#   ./scripts/reset.sh --help          # 显示帮助

set -e

# 配置
API_BASE="${API_BASE:-http://localhost:8080/v1}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-changeme}"
DATA_DIR="${DATA_DIR:-data}"
CONFIG_FILE="${CONFIG_FILE:-config/server.toml}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

show_help() {
    cat << EOF
oxmon 重置和初始化脚本

使用方法:
    ./scripts/reset.sh <mode> [options]

模式:
    config          只清理告警规则和通知渠道（保留监控数据）
    full            完全重置，删除所有数据（包括监控历史）
    --help, -h      显示此帮助信息

环境变量:
    API_BASE        API 基础地址 (默认: http://localhost:8080/v1)
    USERNAME        管理员用户名 (默认: admin)
    PASSWORD        管理员密码 (默认: changeme)
    DATA_DIR        数据目录 (默认: data)
    CONFIG_FILE     配置文件 (默认: config/server.toml)

示例:
    # 只清理配置，保留监控数据
    ./scripts/reset.sh config

    # 完全重置
    ./scripts/reset.sh full

    # 使用自定义配置
    CONFIG_FILE=config/prod.toml ./scripts/reset.sh config

EOF
}

check_dependencies() {
    if ! command -v jq &> /dev/null; then
        print_error "需要 jq 工具。请安装: brew install jq"
        exit 1
    fi
}

cleanup_config_via_api() {
    print_header "通过 REST API 清理配置"

    # 1. 登录获取 Token
    print_header "1. 登录获取 JWT Token"
    TOKEN=$(curl -s -X POST "${API_BASE}/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}" | jq -r '.data.token')

    if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
        print_error "登录失败，请检查服务器是否运行，用户名和密码是否正确"
        print_warning "服务器地址: ${API_BASE}"
        print_warning "用户名: ${USERNAME}"
        exit 1
    fi
    print_success "登录成功"

    # 2. 删除告警规则
    print_header "2. 删除现有告警规则"
    RULES=$(curl -s -X GET "${API_BASE}/alerts/rules" \
        -H "Authorization: Bearer ${TOKEN}")

    RULE_IDS=$(echo "$RULES" | jq -r '.data[]?.id // empty')

    if [ -z "$RULE_IDS" ]; then
        print_warning "没有找到现有的告警规则"
    else
        RULE_COUNT=$(echo "$RULE_IDS" | wc -l | tr -d ' ')
        echo "找到 ${RULE_COUNT} 条告警规则"
        for rule_id in $RULE_IDS; do
            rule_name=$(echo "$RULES" | jq -r ".data[] | select(.id==\"$rule_id\") | .name")
            echo "  删除: ${rule_name} (${rule_id})"
            curl -s -X DELETE "${API_BASE}/alerts/rules/${rule_id}" \
                -H "Authorization: Bearer ${TOKEN}" > /dev/null
        done
        print_success "已删除 ${RULE_COUNT} 条告警规则"
    fi

    # 3. 删除通知渠道
    print_header "3. 删除现有通知渠道"
    CHANNELS=$(curl -s -X GET "${API_BASE}/notifications/channels" \
        -H "Authorization: Bearer ${TOKEN}")

    CHANNEL_IDS=$(echo "$CHANNELS" | jq -r '.data[]?.id // empty')

    if [ -z "$CHANNEL_IDS" ]; then
        print_warning "没有找到现有的通知渠道"
    else
        CHANNEL_COUNT=$(echo "$CHANNEL_IDS" | wc -l | tr -d ' ')
        echo "找到 ${CHANNEL_COUNT} 个通知渠道"
        for channel_id in $CHANNEL_IDS; do
            channel_name=$(echo "$CHANNELS" | jq -r ".data[] | select(.id==\"$channel_id\") | .name")
            echo "  删除: ${channel_name} (${channel_id})"
            curl -s -X DELETE "${API_BASE}/notifications/channels/config/${channel_id}" \
                -H "Authorization: Bearer ${TOKEN}" > /dev/null
        done
        print_success "已删除 ${CHANNEL_COUNT} 个通知渠道"
    fi

    # 4. 删除静默窗口
    print_header "4. 删除静默窗口"
    WINDOWS=$(curl -s -X GET "${API_BASE}/notifications/silence-windows" \
        -H "Authorization: Bearer ${TOKEN}")

    WINDOW_IDS=$(echo "$WINDOWS" | jq -r '.data[]?.id // empty')

    if [ -z "$WINDOW_IDS" ]; then
        print_warning "没有找到现有的静默窗口"
    else
        WINDOW_COUNT=$(echo "$WINDOW_IDS" | wc -l | tr -d ' ')
        echo "找到 ${WINDOW_COUNT} 个静默窗口"
        for window_id in $WINDOW_IDS; do
            echo "  删除静默窗口: ${window_id}"
            curl -s -X DELETE "${API_BASE}/notifications/silence-windows/${window_id}" \
                -H "Authorization: Bearer ${TOKEN}" > /dev/null
        done
        print_success "已删除 ${WINDOW_COUNT} 个静默窗口"
    fi
}

reinit_from_cli() {
    print_header "5. 通过 CLI 重新初始化"

    # 检查二进制文件
    if [ ! -f "target/release/oxmon-server" ]; then
        print_warning "未找到 release 二进制文件，正在编译..."
        cargo build --release
    fi

    # 初始化告警规则
    if [ -f "config/rules.seed.example.json" ]; then
        echo "初始化告警规则..."
        ./target/release/oxmon-server init-rules "${CONFIG_FILE}" config/rules.seed.example.json
        print_success "告警规则已初始化"
    else
        print_warning "未找到规则种子文件: config/rules.seed.example.json"
    fi

    # 初始化通知渠道
    if [ -f "config/channels.seed.example.json" ]; then
        echo "初始化通知渠道..."
        ./target/release/oxmon-server init-channels "${CONFIG_FILE}" config/channels.seed.example.json
        print_success "通知渠道已初始化"
    else
        print_warning "未找到渠道种子文件: config/channels.seed.example.json"
    fi
}

mode_config() {
    echo ""
    print_header "配置清理模式（保留监控数据）"
    echo ""

    check_dependencies
    cleanup_config_via_api

    echo ""
    reinit_from_cli

    echo ""
    print_success "配置清理和重新初始化完成！"
    echo ""
    echo "重启服务器以使更改生效:"
    echo "  pkill -f oxmon-server"
    echo "  ./target/release/oxmon-server ${CONFIG_FILE}"
    echo ""
}

mode_full() {
    echo ""
    print_warning "完全重置模式（删除所有数据）"
    echo ""
    echo "这将删除:"
    echo "  - 所有告警规则"
    echo "  - 所有通知渠道"
    echo "  - 所有监控指标历史数据"
    echo "  - 所有证书信息"
    echo "  - 所有用户账号（将重置为默认 admin/changeme）"
    echo ""
    echo "数据目录: ${DATA_DIR}"
    echo ""

    read -p "确认删除? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        print_warning "已取消操作"
        exit 0
    fi

    echo ""
    print_header "1. 停止 oxmon-server 服务"
    if pkill -f oxmon-server; then
        print_success "服务已停止"
        sleep 2  # 等待进程完全退出
    else
        print_warning "服务未运行"
    fi

    print_header "2. 删除数据目录"
    if [ -d "$DATA_DIR" ]; then
        rm -rf "${DATA_DIR}"
        print_success "已删除: ${DATA_DIR}"
    else
        print_warning "数据目录不存在: ${DATA_DIR}"
    fi

    print_header "3. 重新创建数据目录"
    mkdir -p "${DATA_DIR}"
    print_success "已创建: ${DATA_DIR}"

    echo ""
    print_success "完全重置完成！"
    echo ""
    echo "现在启动服务器将自动初始化:"
    echo "  - 默认管理员账号 (admin/changeme)"
    echo "  - 9 条默认告警规则（已启用）"
    echo "  - 7 个默认通知渠道（已禁用）"
    echo ""
    echo "启动命令:"
    echo "  ./target/release/oxmon-server ${CONFIG_FILE}"
    echo ""
}

# 主程序
case "${1:-}" in
    config)
        mode_config
        ;;
    full)
        mode_full
        ;;
    --help|-h|help)
        show_help
        ;;
    "")
        print_error "缺少模式参数"
        echo ""
        show_help
        exit 1
        ;;
    *)
        print_error "未知模式: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
