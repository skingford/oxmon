#!/bin/bash
# 从 .env 文件批量导入云账户配置
# 支持格式: 账号名:SecretId:SecretKey:region1,region2|账号名:SecretId:SecretKey:region1

set -e

# 默认配置
BASE_URL="${BASE_URL:-http://localhost:8080/v1}"
ENV_FILE="${ENV_FILE:-/Users/kingford/workspace/coding.net/motern.com/xiaoiron.com/monitor/.env}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-changeme}"
COLLECTION_INTERVAL="${COLLECTION_INTERVAL:-300}"
DRY_RUN="${DRY_RUN:-false}"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "=========================================="
echo "云账户配置批量导入"
echo "=========================================="
echo ""
echo "配置文件: $ENV_FILE"
echo "API 地址: $BASE_URL"
echo "采集间隔: ${COLLECTION_INTERVAL}秒"
if [ "$DRY_RUN" = "true" ]; then
    echo -e "${YELLOW}模式: 试运行（不实际创建）${NC}"
fi
echo ""

# JSON 解析函数
json_get() {
    local json="$1"
    local path="$2"
    echo "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    result = data
    for key in '$path'.split('.'):
        if key:
            result = result[key] if isinstance(result, dict) else result[int(key)]
    if isinstance(result, bool):
        print(str(result).lower())
    else:
        print(result if result is not None else '')
except:
    print('')
"
}

# 检查 .env 文件
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}错误: .env 文件不存在: $ENV_FILE${NC}"
    echo "使用方法: ENV_FILE=/path/to/.env $0"
    exit 1
fi

# 登录获取 token
echo -e "${YELLOW}1. 登录认证...${NC}"
PUBLIC_KEY=$(curl -s "$BASE_URL/auth/public-key" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data['data']['public_key'])
")

if [ -z "$PUBLIC_KEY" ]; then
    echo -e "${RED}错误: 无法获取公钥${NC}"
    exit 1
fi

ENCRYPTED=$(./scripts/encrypt_password_openssl.sh "$PUBLIC_KEY" "$ADMIN_PASS")
if [ $? -ne 0 ]; then
    echo -e "${RED}错误: 密码加密失败${NC}"
    exit 1
fi

LOGIN_RESPONSE=$(python3 -c "
import json
print(json.dumps({'username': '$ADMIN_USER', 'encrypted_password': '''$ENCRYPTED'''}))
" | curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d @-)

TOKEN=$(json_get "$LOGIN_RESPONSE" "data.access_token")
if [ -z "$TOKEN" ]; then
    echo -e "${RED}错误: 登录失败${NC}"
    echo "$LOGIN_RESPONSE"
    exit 1
fi
echo -e "${GREEN}✓ 登录成功${NC}"
echo ""

# 查询已存在的账户
echo -e "${YELLOW}2. 查询已存在的账户...${NC}"
EXISTING_ACCOUNTS=$(curl -s -X GET "$BASE_URL/cloud/accounts" \
    -H "Authorization: Bearer $TOKEN")

EXISTING_KEYS=$(echo "$EXISTING_ACCOUNTS" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    keys = [acc['config_key'] for acc in data.get('data', {}).get('items', [])]
    print('|'.join(keys))
except:
    print('')
")

EXISTING_COUNT=$(echo "$EXISTING_ACCOUNTS" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('data', {}).get('total', 0))
except:
    print(0)
")

echo -e "${BLUE}已存在 ${EXISTING_COUNT} 个账户${NC}"
echo ""

# 解析并导入腾讯云账户
echo -e "${YELLOW}3. 导入腾讯云账户...${NC}"
TENCENT_ACCOUNTS=$(grep "^TENCENT_ACCOUNTS=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || echo "")

if [ -z "$TENCENT_ACCOUNTS" ]; then
    echo -e "${CYAN}  未找到 TENCENT_ACCOUNTS 配置，跳过${NC}"
else
    TENCENT_COUNT=0
    TENCENT_CREATED=0
    TENCENT_SKIPPED=0

    # 按 | 分割多个账户
    IFS='|' read -ra ACCOUNTS <<< "$TENCENT_ACCOUNTS"

    for ACCOUNT in "${ACCOUNTS[@]}"; do
        # 解析单个账户: 账号名:SecretId:SecretKey:regions
        ACCOUNT_NAME=$(echo "$ACCOUNT" | cut -d':' -f1)
        SECRET_ID=$(echo "$ACCOUNT" | cut -d':' -f2)
        SECRET_KEY=$(echo "$ACCOUNT" | cut -d':' -f3)
        REGIONS=$(echo "$ACCOUNT" | cut -d':' -f4)

        ((TENCENT_COUNT++))

        # 生成 config_key
        CONFIG_KEY="cloud_tencent_${ACCOUNT_NAME}"

        # 检查是否已存在
        if echo "$EXISTING_KEYS" | grep -q "$CONFIG_KEY"; then
            echo -e "  ${YELLOW}⊘ 跳过已存在: $ACCOUNT_NAME${NC}"
            ((TENCENT_SKIPPED++))
            continue
        fi

        # 转换地域为 JSON 数组
        REGION_JSON=$(python3 -c "
import json
regions = '$REGIONS'.split(',')
print(json.dumps(regions))
")

        if [ "$DRY_RUN" = "true" ]; then
            echo -e "  ${CYAN}[试运行] 将创建: $ACCOUNT_NAME (地域: $REGIONS)${NC}"
            ((TENCENT_CREATED++))
            continue
        fi

        # 创建账户
        CREATE_RESPONSE=$(curl -s -X POST "$BASE_URL/cloud/accounts" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d @- <<EOF
{
  "config_key": "${CONFIG_KEY}",
  "provider": "tencent",
  "display_name": "腾讯云-${ACCOUNT_NAME}",
  "description": "从 .env 导入",
  "enabled": true,
  "config": {
    "secret_id": "${SECRET_ID}",
    "secret_key": "${SECRET_KEY}",
    "regions": ${REGION_JSON},
    "collection_interval_secs": ${COLLECTION_INTERVAL},
    "instance_filter": {
      "status_whitelist": ["RUNNING"],
      "required_tags": {},
      "excluded_tags": {}
    }
  }
}
EOF
)

        ACCOUNT_ID=$(json_get "$CREATE_RESPONSE" "data.id")
        if [ -n "$ACCOUNT_ID" ]; then
            echo -e "  ${GREEN}✓ 创建成功: $ACCOUNT_NAME (ID: $ACCOUNT_ID)${NC}"
            ((TENCENT_CREATED++))
        else
            ERR_MSG=$(json_get "$CREATE_RESPONSE" "err_msg")
            echo -e "  ${RED}✗ 创建失败: $ACCOUNT_NAME - $ERR_MSG${NC}"
        fi
    done

    echo -e "${BLUE}  腾讯云: 扫描 $TENCENT_COUNT 个, 创建 $TENCENT_CREATED 个, 跳过 $TENCENT_SKIPPED 个${NC}"
fi
echo ""

# 解析并导入阿里云账户
echo -e "${YELLOW}4. 导入阿里云账户...${NC}"
ALIBABA_ACCOUNTS=$(grep "^ALIBABA_ACCOUNTS=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || echo "")

if [ -z "$ALIBABA_ACCOUNTS" ]; then
    echo -e "${CYAN}  未找到 ALIBABA_ACCOUNTS 配置，跳过${NC}"
else
    ALIBABA_COUNT=0
    ALIBABA_CREATED=0
    ALIBABA_SKIPPED=0

    # 按 | 分割多个账户
    IFS='|' read -ra ACCOUNTS <<< "$ALIBABA_ACCOUNTS"

    for ACCOUNT in "${ACCOUNTS[@]}"; do
        # 解析单个账户
        ACCOUNT_NAME=$(echo "$ACCOUNT" | cut -d':' -f1)
        ACCESS_KEY_ID=$(echo "$ACCOUNT" | cut -d':' -f2)
        ACCESS_KEY_SECRET=$(echo "$ACCOUNT" | cut -d':' -f3)
        REGIONS=$(echo "$ACCOUNT" | cut -d':' -f4)

        ((ALIBABA_COUNT++))

        # 生成唯一的 config_key（如果有重复名称，加上数字后缀）
        BASE_CONFIG_KEY="cloud_alibaba_${ACCOUNT_NAME}"
        CONFIG_KEY="$BASE_CONFIG_KEY"
        SUFFIX=1

        while echo "$EXISTING_KEYS" | grep -q "^${CONFIG_KEY}$"; do
            CONFIG_KEY="${BASE_CONFIG_KEY}_${SUFFIX}"
            ((SUFFIX++))
        done

        # 检查是否已存在
        if [ "$CONFIG_KEY" != "$BASE_CONFIG_KEY" ]; then
            echo -e "  ${YELLOW}⚠ 账户名重复，使用: $CONFIG_KEY${NC}"
        elif echo "$EXISTING_KEYS" | grep -q "$BASE_CONFIG_KEY"; then
            echo -e "  ${YELLOW}⊘ 跳过已存在: $ACCOUNT_NAME${NC}"
            ((ALIBABA_SKIPPED++))
            continue
        fi

        # 转换地域为 JSON 数组
        REGION_JSON=$(python3 -c "
import json
regions = '$REGIONS'.split(',')
print(json.dumps(regions))
")

        if [ "$DRY_RUN" = "true" ]; then
            echo -e "  ${CYAN}[试运行] 将创建: $ACCOUNT_NAME (地域: $REGIONS)${NC}"
            ((ALIBABA_CREATED++))
            continue
        fi

        # 创建账户
        CREATE_RESPONSE=$(curl -s -X POST "$BASE_URL/cloud/accounts" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d @- <<EOF
{
  "config_key": "${CONFIG_KEY}",
  "provider": "alibaba",
  "display_name": "阿里云-${ACCOUNT_NAME}",
  "description": "从 .env 导入",
  "enabled": true,
  "config": {
    "secret_id": "${ACCESS_KEY_ID}",
    "secret_key": "${ACCESS_KEY_SECRET}",
    "regions": ${REGION_JSON},
    "collection_interval_secs": ${COLLECTION_INTERVAL},
    "instance_filter": {
      "status_whitelist": ["Running"],
      "required_tags": {},
      "excluded_tags": {}
    }
  }
}
EOF
)

        ACCOUNT_ID=$(json_get "$CREATE_RESPONSE" "data.id")
        if [ -n "$ACCOUNT_ID" ]; then
            echo -e "  ${GREEN}✓ 创建成功: $ACCOUNT_NAME (ID: $ACCOUNT_ID)${NC}"
            ((ALIBABA_CREATED++))
            # 更新已存在列表
            EXISTING_KEYS="${EXISTING_KEYS}|${CONFIG_KEY}"
        else
            ERR_MSG=$(json_get "$CREATE_RESPONSE" "err_msg")
            echo -e "  ${RED}✗ 创建失败: $ACCOUNT_NAME - $ERR_MSG${NC}"
        fi
    done

    echo -e "${BLUE}  阿里云: 扫描 $ALIBABA_COUNT 个, 创建 $ALIBABA_CREATED 个, 跳过 $ALIBABA_SKIPPED 个${NC}"
fi
echo ""

# 总结
echo "=========================================="
echo -e "${GREEN}导入完成！${NC}"
echo "=========================================="
TOTAL_CREATED=$((TENCENT_CREATED + ALIBABA_CREATED))
TOTAL_SKIPPED=$((TENCENT_SKIPPED + ALIBABA_SKIPPED))
echo "  成功创建: $TOTAL_CREATED 个账户"
echo "  跳过已存在: $TOTAL_SKIPPED 个账户"
echo ""
echo "查看所有账户:"
echo "  curl -H \"Authorization: Bearer \$TOKEN\" $BASE_URL/cloud/accounts"
echo ""
echo "API 文档: http://localhost:8080/docs"
echo ""
