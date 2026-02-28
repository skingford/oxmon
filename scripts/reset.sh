#!/bin/bash

# oxmon 重置和初始化脚本（直接操作数据库）
# 使用方法:
#   ./scripts/reset.sh config          # 只清理规则和渠道（保留监控数据）
#   ./scripts/reset.sh full            # 完全重置（删除所有数据）
#   ./scripts/reset.sh --help          # 显示帮助

set -e

# 配置
DATA_DIR="${DATA_DIR:-data}"
CONFIG_FILE="${CONFIG_FILE:-config/server.toml}"
CERT_DB="${DATA_DIR}/oxmon.db"

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
oxmon 重置和初始化脚本（直接操作 SQLite 数据库）

使用方法:
    ./scripts/reset.sh <mode> [options]

模式:
    config          只清理告警规则和通知渠道（保留监控数据）
    full            完全重置，删除所有数据（包括监控历史）
    --help, -h      显示此帮助信息

环境变量:
    DATA_DIR        数据目录 (默认: data)
    CONFIG_FILE     配置文件 (默认: config/server.toml)

示例:
    # 只清理配置，保留监控数据
    ./scripts/reset.sh config

    # 完全重置
    ./scripts/reset.sh full

    # 使用自定义数据目录
    DATA_DIR=/var/lib/oxmon ./scripts/reset.sh config

优势:
    ✓ 直接操作 SQLite 数据库，速度快
    ✓ 不需要服务器运行
    ✓ 不需要 API 认证
    ✓ 不依赖 jq 等外部工具

EOF
}

check_sqlite() {
    if ! command -v sqlite3 &> /dev/null; then
        print_error "需要 sqlite3 工具。请安装: brew install sqlite3"
        exit 1
    fi
}

check_db_exists() {
    if [ ! -f "$CERT_DB" ]; then
        print_warning "数据库不存在: ${CERT_DB}"
        return 1
    fi
    return 0
}

cleanup_config_db() {
    print_header "直接操作数据库清理配置"

    if ! check_db_exists; then
        print_warning "跳过清理，数据库文件不存在"
        return
    fi

    # 1. 删除告警规则
    print_header "1. 删除现有告警规则"
    RULE_COUNT=$(sqlite3 "$CERT_DB" "SELECT COUNT(*) FROM alert_rules;")
    if [ "$RULE_COUNT" -gt 0 ]; then
        echo "找到 ${RULE_COUNT} 条告警规则"
        sqlite3 "$CERT_DB" "SELECT id, name, rule_type FROM alert_rules;" | while IFS='|' read -r id name rule_type; do
            echo "  删除: ${name} (${rule_type})"
        done
        sqlite3 "$CERT_DB" "DELETE FROM alert_rules;"
        print_success "已删除 ${RULE_COUNT} 条告警规则"
    else
        print_warning "没有找到现有的告警规则"
    fi

    # 2. 删除通知渠道（级联删除会自动删除 recipients）
    print_header "2. 删除现有通知渠道"
    CHANNEL_COUNT=$(sqlite3 "$CERT_DB" "SELECT COUNT(*) FROM notification_channels;")
    if [ "$CHANNEL_COUNT" -gt 0 ]; then
        echo "找到 ${CHANNEL_COUNT} 个通知渠道"
        sqlite3 "$CERT_DB" "SELECT id, name, channel_type FROM notification_channels;" | while IFS='|' read -r id name channel_type; do
            echo "  删除: ${name} (${channel_type})"
        done
        # 先删除 recipients（如果有外键约束）
        sqlite3 "$CERT_DB" "DELETE FROM notification_recipients;"
        sqlite3 "$CERT_DB" "DELETE FROM notification_channels;"
        print_success "已删除 ${CHANNEL_COUNT} 个通知渠道"
    else
        print_warning "没有找到现有的通知渠道"
    fi

    # 3. 删除静默窗口
    print_header "3. 删除静默窗口"
    WINDOW_COUNT=$(sqlite3 "$CERT_DB" "SELECT COUNT(*) FROM notification_silence_windows;" 2>/dev/null || echo "0")
    if [ "$WINDOW_COUNT" -gt 0 ]; then
        echo "找到 ${WINDOW_COUNT} 个静默窗口"
        sqlite3 "$CERT_DB" "DELETE FROM notification_silence_windows;" 2>/dev/null || true
        print_success "已删除 ${WINDOW_COUNT} 个静默窗口"
    else
        print_warning "没有找到现有的静默窗口"
    fi

    # 4. 清理告警历史（可选）
    print_header "4. 清理告警历史记录"
    ALERT_COUNT=$(sqlite3 "$CERT_DB" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0")
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo "找到 ${ALERT_COUNT} 条告警历史记录"
        sqlite3 "$CERT_DB" "DELETE FROM alerts;" 2>/dev/null || true
        print_success "已清理告警历史"
    fi

    # 5. 清理通知日志（可选）
    NOTIF_COUNT=$(sqlite3 "$CERT_DB" "SELECT COUNT(*) FROM notification_logs;" 2>/dev/null || echo "0")
    if [ "$NOTIF_COUNT" -gt 0 ]; then
        echo "找到 ${NOTIF_COUNT} 条通知日志"
        sqlite3 "$CERT_DB" "DELETE FROM notification_logs;" 2>/dev/null || true
        print_success "已清理通知日志"
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

stop_server() {
    print_header "停止 oxmon-server 服务"
    if pkill -f oxmon-server; then
        print_success "服务已停止"
        sleep 2  # 等待进程完全退出和数据库连接关闭
    else
        print_warning "服务未运行"
    fi
}

mode_config() {
    echo ""
    print_header "配置清理模式（保留监控数据）"
    echo ""

    check_sqlite

    # 停止服务器以释放数据库锁
    stop_server

    echo ""
    cleanup_config_db

    echo ""
    reinit_from_cli

    echo ""
    print_success "配置清理和重新初始化完成！"
    echo ""
    echo "启动服务器:"
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
    stop_server

    print_header "删除数据目录"
    if [ -d "$DATA_DIR" ]; then
        rm -rf "${DATA_DIR}"
        print_success "已删除: ${DATA_DIR}"
    else
        print_warning "数据目录不存在: ${DATA_DIR}"
    fi

    print_header "重新创建数据目录"
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
