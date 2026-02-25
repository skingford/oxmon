#!/bin/bash
# 自动化云监控测试脚本 - 从 .env 文件读取配置
set -e

# 默认配置
BASE_URL="${BASE_URL:-http://localhost:8080/v1}"
ENV_FILE="${ENV_FILE:-/Users/kingford/workspace/coding.net/motern.com/xiaoiron.com/monitor/.env}"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "云监控自动化测试"
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
    # Convert Python bool to lowercase string for bash comparison
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
    exit 1
fi

# 解析 .env 中的腾讯云账号
echo -e "${YELLOW}1. 解析 .env 配置...${NC}"
TENCENT_ACCOUNTS=$(grep "^TENCENT_ACCOUNTS=" "$ENV_FILE" | cut -d'=' -f2-)

if [ -z "$TENCENT_ACCOUNTS" ]; then
    echo -e "${RED}错误: .env 中未找到 TENCENT_ACCOUNTS 配置${NC}"
    exit 1
fi

# 提取第一个账号信息
FIRST_ACCOUNT=$(echo "$TENCENT_ACCOUNTS" | cut -d'|' -f1)
ACCOUNT_NAME=$(echo "$FIRST_ACCOUNT" | cut -d':' -f1)
SECRET_ID=$(echo "$FIRST_ACCOUNT" | cut -d':' -f2)
SECRET_KEY=$(echo "$FIRST_ACCOUNT" | cut -d':' -f3)
REGIONS=$(echo "$FIRST_ACCOUNT" | cut -d':' -f4)

echo -e "${GREEN}✓ 使用账号: $ACCOUNT_NAME${NC}"
echo "  地域: $REGIONS"
echo ""

# 获取公钥并登录
echo -e "${YELLOW}2. 登录获取 token...${NC}"
PUBLIC_KEY=$(curl -s "$BASE_URL/auth/public-key" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data['data']['public_key'])
")

if [ -z "$PUBLIC_KEY" ]; then
    echo -e "${RED}错误: 无法获取公钥${NC}"
    exit 1
fi

# 加密密码
ENCRYPTED=$(./scripts/encrypt_password_openssl.sh "$PUBLIC_KEY" "changeme")
if [ $? -ne 0 ]; then
    echo -e "${RED}错误: 密码加密失败${NC}"
    exit 1
fi

# 登录
LOGIN_RESPONSE=$(python3 -c "
import json
print(json.dumps({'username': 'admin', 'encrypted_password': '''$ENCRYPTED'''}))
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

# 转换地域为 JSON 数组
REGION_JSON=$(python3 -c "
import json
regions = '$REGIONS'.split(',')
print(json.dumps(regions))
")

# 创建或查找云账户
echo -e "${YELLOW}3. 创建/查找云账户配置...${NC}"
CONFIG_KEY="cloud_tencent_${ACCOUNT_NAME}"

# 先查询是否已存在
LIST_RESPONSE=$(curl -s -X GET "$BASE_URL/cloud/accounts" \
    -H "Authorization: Bearer $TOKEN")

ACCOUNT_ID=$(echo "$LIST_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for account in data.get('data', []):
        if account.get('config_key') == '$CONFIG_KEY':
            print(account.get('id', ''))
            break
except:
    pass
")

if [ -n "$ACCOUNT_ID" ]; then
    echo -e "${YELLOW}  使用已存在的账户 (ID: $ACCOUNT_ID)${NC}"
else
    # 创建新账户
    CREATE_RESPONSE=$(curl -s -X POST "$BASE_URL/cloud/accounts" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d @- <<EOF
{
  "config_key": "${CONFIG_KEY}",
  "provider": "tencent",
  "display_name": "腾讯云-${ACCOUNT_NAME}",
  "description": "从 .env 自动导入",
  "enabled": true,
  "config": {
    "secret_id": "${SECRET_ID}",
    "secret_key": "${SECRET_KEY}",
    "regions": ${REGION_JSON},
    "collection_interval_secs": 300,
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
    if [ -z "$ACCOUNT_ID" ]; then
        echo -e "${RED}错误: 创建云账户失败${NC}"
        echo "$CREATE_RESPONSE" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))"
        exit 1
    fi
    echo -e "${GREEN}✓ 云账户创建成功 (ID: $ACCOUNT_ID)${NC}"
fi
echo ""

# 测试连接
echo -e "${YELLOW}4. 测试云 API 连接...${NC}"
TEST_RESPONSE=$(curl -s -X POST "$BASE_URL/cloud/accounts/$ACCOUNT_ID/test" \
    -H "Authorization: Bearer $TOKEN")

TEST_SUCCESS=$(json_get "$TEST_RESPONSE" "data.success")
if [ "$TEST_SUCCESS" != "true" ]; then
    echo -e "${RED}错误: 连接测试失败${NC}"
    echo "$TEST_RESPONSE" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))"
    exit 1
fi

INSTANCE_COUNT=$(json_get "$TEST_RESPONSE" "data.instance_count")
echo -e "${GREEN}✓ 连接成功, 发现 ${INSTANCE_COUNT} 个实例${NC}"
echo ""

# 触发手动采集
echo -e "${YELLOW}5. 触发手动采集...${NC}"
COLLECT_RESPONSE=$(curl -s -X POST "$BASE_URL/cloud/accounts/$ACCOUNT_ID/collect" \
    -H "Authorization: Bearer $TOKEN")

COLLECT_SUCCESS=$(json_get "$COLLECT_RESPONSE" "data.success")
if [ "$COLLECT_SUCCESS" = "true" ]; then
    METRICS_COUNT=$(json_get "$COLLECT_RESPONSE" "data.metrics_collected")
    echo -e "${GREEN}✓ 采集成功, 收集 ${METRICS_COUNT} 个指标数据点${NC}"
else
    echo -e "${YELLOW}⚠ 采集触发失败或无数据${NC}"
    echo "$COLLECT_RESPONSE" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin), indent=2))"
fi
echo ""

# 等待数据写入
echo -e "${YELLOW}6. 等待数据写入 (10秒)...${NC}"
sleep 10
echo ""

# 查询云实例
echo -e "${YELLOW}7. 查询云实例列表...${NC}"
INSTANCES_RESPONSE=$(curl -s -X GET "$BASE_URL/cloud/instances?limit=10" \
    -H "Authorization: Bearer $TOKEN")

INSTANCE_COUNT=$(echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(len(data.get('data', [])))
except:
    print(0)
")

if [ "$INSTANCE_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠ 未找到云实例${NC}"
else
    echo -e "${GREEN}✓ 找到 ${INSTANCE_COUNT} 个实例${NC}"
    echo ""
    echo -e "${BLUE}实例列表:${NC}"
    echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for inst in data.get('data', []):
        print(f\"  - {inst.get('instance_name')} ({inst.get('instance_id')})\")
        print(f\"    状态: {inst.get('status')}, 地域: {inst.get('region')}\")
        if inst.get('private_ip'):
            print(f\"    内网IP: {inst.get('private_ip')}\")
        if inst.get('public_ip'):
            print(f\"    公网IP: {inst.get('public_ip')}\")
except Exception as e:
    print(f'解析错误: {e}')
"

    # 查询第一个实例的指标
    FIRST_INSTANCE_ID=$(echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['data'][0]['instance_id'] if data.get('data') else '')
except:
    print('')
")

    if [ -n "$FIRST_INSTANCE_ID" ]; then
        AGENT_ID="cloud:tencent:${FIRST_INSTANCE_ID}"
        echo ""
        echo -e "${YELLOW}8. 查询指标数据 (Agent: $AGENT_ID)...${NC}"

        # 查询各类指标
        for METRIC in "cloud.cpu.usage:CPU使用率" "cloud.memory.usage:内存使用率" "cloud.network.in_bytes:网络入流量" "cloud.disk.iops_read:磁盘读IOPS" "cloud.connections:TCP连接数"; do
            METRIC_NAME=$(echo "$METRIC" | cut -d':' -f1)
            METRIC_LABEL=$(echo "$METRIC" | cut -d':' -f2)

            RESPONSE=$(curl -s -X GET "$BASE_URL/metrics?agent_id__eq=${AGENT_ID}&metric_name__eq=${METRIC_NAME}&limit=3" \
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
        print(f\"    最新值: {value / 1024 / 1024:.2f} MB/s @ {ts}\")
    else:
        print(f\"    最新值: {value} @ {ts}\")
"
            else
                echo -e "  ${YELLOW}⚠ ${METRIC_LABEL}: 无数据${NC}"
            fi
        done
    fi
fi

echo ""
echo "=========================================="
echo -e "${GREEN}测试完成！${NC}"
echo "=========================================="
echo ""
echo "测试结果总结:"
echo "  - 云账户ID: $ACCOUNT_ID"
echo "  - 发现实例数: $INSTANCE_COUNT"
echo "  - API 文档: http://localhost:8080/docs"
echo ""
