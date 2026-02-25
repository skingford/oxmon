#!/bin/bash
# 查询云实例采集情况
set -e

BASE_URL="${BASE_URL:-http://localhost:8080/v1}"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "=========================================="
echo "云实例采集情况查询"
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

# 查询云账户
echo -e "${YELLOW}2. 查询云账户配置...${NC}"
ACCOUNTS_RESPONSE=$(curl -s -X GET "$BASE_URL/cloud/accounts" \
    -H "Authorization: Bearer $TOKEN")

ACCOUNT_COUNT=$(echo "$ACCOUNTS_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('data', {}).get('total', 0))
except:
    print(0)
")

echo -e "${BLUE}共 ${ACCOUNT_COUNT} 个云账户${NC}"

# 显示账户详情
echo "$ACCOUNTS_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('data', {}).get('items', [])
    for i, acc in enumerate(items, 1):
        provider = acc['provider'].upper()
        name = acc['display_name']
        enabled = '✅' if acc['enabled'] else '❌'
        last = acc.get('last_collection_at', '未采集')
        print(f'  {i}. {name} ({provider}) {enabled}')
        print(f'     最后采集: {last}')
except:
    pass
"
echo ""

# 查询云实例
echo -e "${YELLOW}3. 查询云实例列表...${NC}"
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

if [ "$INSTANCE_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠ 未找到云实例${NC}"
    echo ""
    echo "可能原因："
    echo "  1. 采集还未开始（等待 5 分钟后重试）"
    echo "  2. 云账户凭证无效"
    echo "  3. 指定的地域没有运行中的实例"
    echo ""
    echo "建议："
    echo "  • 手动触发采集: ./scripts/trigger-cloud-collection.sh"
    echo "  • 查看服务器日志: 检查采集错误信息"
else
    echo -e "${GREEN}✓ 找到 ${INSTANCE_COUNT} 个实例${NC}"
    echo ""
    echo -e "${BLUE}实例列表:${NC}"
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
        print(f'\n  {provider.upper()} ({len(insts)} 个):')
        for inst in insts:
            print(f'    • {inst.get(\"instance_name\")} ({inst.get(\"instance_id\")})')
            print(f'      状态: {inst.get(\"status\")}, 地域: {inst.get(\"region\")}')
            if inst.get('private_ip'):
                print(f'      内网IP: {inst.get(\"private_ip\")}')
            if inst.get('public_ip'):
                print(f'      公网IP: {inst.get(\"public_ip\")}')
except Exception as e:
    print(f'解析错误: {e}')
"
fi
echo ""

# 查询指标数据
if [ "$INSTANCE_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}4. 查询指标数据...${NC}"

    FIRST_INSTANCE=$(echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('data', {}).get('items', [])
    if items:
        inst = items[0]
        agent_id = f\"cloud:{inst['provider']}:{inst['instance_id']}\"
        print(agent_id)
except:
    pass
")

    if [ -n "$FIRST_INSTANCE" ]; then
        echo -e "  查询第一个实例: ${CYAN}$FIRST_INSTANCE${NC}"
        echo ""

        for METRIC in "cloud.cpu.usage:CPU使用率" "cloud.memory.usage:内存使用率" "cloud.network.in_bytes:网络入流量"; do
            METRIC_NAME=$(echo "$METRIC" | cut -d':' -f1)
            METRIC_LABEL=$(echo "$METRIC" | cut -d':' -f2)

            RESPONSE=$(curl -s -X GET "$BASE_URL/metrics?agent_id__eq=${FIRST_INSTANCE}&metric_name__eq=${METRIC_NAME}&limit=3" \
                -H "Authorization: Bearer $TOKEN")

            COUNT=$(echo "$RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len(data.get('data', {}).get('items', [])))")

            if [ "$COUNT" -gt 0 ]; then
                echo -e "  ${GREEN}✓ ${METRIC_LABEL}: ${COUNT} 条数据${NC}"
                echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('data', {}).get('items', [])
if items:
    item = items[0]
    value = item.get('value')
    ts = item.get('timestamp')
    metric = '$METRIC_NAME'
    if 'bytes' in metric:
        print(f'    最新值: {value / 1024 / 1024:.2f} MB/s @ {ts}')
    else:
        print(f'    最新值: {value} @ {ts}')
"
            else
                echo -e "  ${YELLOW}⚠ ${METRIC_LABEL}: 无数据${NC}"
            fi
        done
    fi
fi

echo ""
echo "=========================================="
echo -e "${GREEN}查询完成！${NC}"
echo "=========================================="
echo ""
echo "提示:"
echo "  • API 文档: http://localhost:8080/docs"
echo "  • 手动触发采集: ./scripts/trigger-cloud-collection.sh"
echo ""
