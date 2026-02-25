#!/bin/bash
# 手动触发所有云账户的指标采集
set -e

BASE_URL="${BASE_URL:-http://localhost:8080/v1}"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "手动触发云指标采集"
echo "=========================================="
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

ENCRYPTED=$(./scripts/encrypt_password_openssl.sh "$PUBLIC_KEY" "changeme")
if [ $? -ne 0 ]; then
    echo -e "${RED}错误: 密码加密失败${NC}"
    exit 1
fi

LOGIN_RESPONSE=$(python3 -c "
import json
print(json.dumps({'username': 'admin', 'encrypted_password': '''$ENCRYPTED'''}))" | curl -s -X POST "$BASE_URL/auth/login" \
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

# 查询所有云账户
echo -e "${YELLOW}2. 查询云账户...${NC}"
ACCOUNTS_RESPONSE=$(curl -s -X GET "$BASE_URL/cloud/accounts" \
    -H "Authorization: Bearer $TOKEN")

ACCOUNT_IDS=$(echo "$ACCOUNTS_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('data', {}).get('items', [])
    for acc in items:
        if acc.get('enabled'):
            print(acc['id'])
except:
    pass
")

ACCOUNT_COUNT=$(echo "$ACCOUNT_IDS" | wc -l | xargs)
echo -e "${BLUE}找到 ${ACCOUNT_COUNT} 个启用的云账户${NC}"
echo ""

# 触发每个账户的采集
echo -e "${YELLOW}3. 触发采集...${NC}"
TOTAL_METRICS=0
SUCCESS_COUNT=0
FAIL_COUNT=0

for ACCOUNT_ID in $ACCOUNT_IDS; do
    if [ -z "$ACCOUNT_ID" ]; then
        continue
    fi

    # 获取账户名称
    ACCOUNT_NAME=$(echo "$ACCOUNTS_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('data', {}).get('items', [])
    for acc in items:
        if str(acc['id']) == '$ACCOUNT_ID':
            print(acc['display_name'])
            break
except:
    print('未知账户')
")

    echo -e "  触发账户: ${BLUE}$ACCOUNT_NAME${NC} (ID: $ACCOUNT_ID)"

    COLLECT_RESPONSE=$(curl -s -X POST "$BASE_URL/cloud/accounts/$ACCOUNT_ID/collect" \
        -H "Authorization: Bearer $TOKEN")

    COLLECT_SUCCESS=$(json_get "$COLLECT_RESPONSE" "data.success")
    if [ "$COLLECT_SUCCESS" = "true" ]; then
        METRICS_COUNT=$(json_get "$COLLECT_RESPONSE" "data.metrics_collected")
        TOTAL_METRICS=$((TOTAL_METRICS + METRICS_COUNT))
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo -e "    ${GREEN}✓ 采集成功, 收集 ${METRICS_COUNT} 个指标${NC}"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        ERR_MSG=$(json_get "$COLLECT_RESPONSE" "err_msg")
        echo -e "    ${RED}✗ 采集失败: ${ERR_MSG}${NC}"
    fi
done

echo ""
echo "=========================================="
echo -e "${GREEN}采集完成！${NC}"
echo "=========================================="
echo "  成功: $SUCCESS_COUNT 个账户"
echo "  失败: $FAIL_COUNT 个账户"
echo "  总计: $TOTAL_METRICS 个指标"
echo ""
echo "等待 10 秒后查询实例..."
sleep 10
echo ""

# 查询实例
INSTANCES_RESPONSE=$(curl -s -X GET "$BASE_URL/cloud/instances?limit=100" \
    -H "Authorization: Bearer $TOKEN")

INSTANCE_COUNT=$(echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('data', {}).get('items', [])
    print(len(items))
except:
    print(0)
")

echo -e "${BLUE}发现 ${INSTANCE_COUNT} 个云实例${NC}"

if [ "$INSTANCE_COUNT" -gt 0 ]; then
    echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('data', {}).get('items', [])

    # 按 provider 分组
    by_provider = {}
    for inst in items:
        provider = inst.get('provider', 'unknown')
        if provider not in by_provider:
            by_provider[provider] = []
        by_provider[provider].append(inst)

    for provider, insts in by_provider.items():
        print(f'\n  {provider.upper()}: {len(insts)} 个实例')
        for inst in insts[:5]:  # 只显示前5个
            print(f'    • {inst.get(\"instance_name\")} ({inst.get(\"region\")})')
        if len(insts) > 5:
            print(f'    ... 还有 {len(insts) - 5} 个实例')
except Exception as e:
    print(f'解析错误: {e}')
"
fi

echo ""
echo "查看详细信息: ./scripts/check-cloud-instances.sh"
echo ""
