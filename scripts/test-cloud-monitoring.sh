#!/bin/bash
# 云监控功能测试脚本

set -e

BASE_URL="http://localhost:8080/v1"
CONFIG_FILE="config/server.test.toml"

echo "=========================================="
echo "云监控功能测试"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# JSON 解析函数 - 使用 Python
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
    print(result if result is not None else '')
except:
    print('')
"
}

json_array_to_bash() {
    local regions="$1"
    python3 -c "
import json
regions = '$regions'.split(',')
print(json.dumps(regions))
"
}

# 检查服务器是否运行
echo -e "${YELLOW}1. 检查服务器状态...${NC}"
if ! curl -s -f "${BASE_URL}/health" > /dev/null 2>&1; then
    echo -e "${RED}错误: 服务器未运行${NC}"
    echo "请先在另一个终端运行: cargo run --release --bin oxmon-server -- ${CONFIG_FILE}"
    exit 1
fi
echo -e "${GREEN}✓ 服务器正在运行${NC}"
echo ""

# 获取 JWT token
echo -e "${YELLOW}2. 获取认证 token...${NC}"

# 先获取公钥
PUBKEY_RESPONSE=$(curl -s -X GET "${BASE_URL}/auth/public-key")
PUBLIC_KEY=$(json_get "$PUBKEY_RESPONSE" "data.public_key")

if [ -z "$PUBLIC_KEY" ]; then
    echo -e "${RED}错误: 无法获取公钥${NC}"
    echo "$PUBKEY_RESPONSE"
    exit 1
fi

# 使用公钥加密密码
ENCRYPTED_PASSWORD=$(./scripts/encrypt_password_openssl.sh "$PUBLIC_KEY" "changeme")
if [ $? -ne 0 ]; then
    echo -e "${RED}错误: 密码加密失败${NC}"
    echo "请确保系统已安装 openssl 命令行工具"
    exit 1
fi

# 登录
LOGIN_RESPONSE=$(curl -s -X POST "${BASE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"encrypted_password\":\"${ENCRYPTED_PASSWORD}\"}")

TOKEN=$(json_get "$LOGIN_RESPONSE" "data.access_token")

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo -e "${RED}错误: 登录失败${NC}"
    echo "$LOGIN_RESPONSE"
    exit 1
fi
echo -e "${GREEN}✓ 认证成功${NC}"
echo ""

# 提示用户输入云账户信息
echo -e "${YELLOW}3. 配置云账户${NC}"
echo "请选择云厂商:"
echo "  1) 腾讯云 (Tencent Cloud)"
echo "  2) 阿里云 (Alibaba Cloud)"
read -p "请输入 (1/2): " PROVIDER_CHOICE

if [ "$PROVIDER_CHOICE" = "1" ]; then
    PROVIDER="tencent"
    echo ""
    echo "请输入腾讯云凭证:"
    read -p "SecretId: " SECRET_ID
    read -p "SecretKey: " SECRET_KEY
    read -p "地域 (例如: ap-guangzhou,ap-shanghai): " REGIONS
elif [ "$PROVIDER_CHOICE" = "2" ]; then
    PROVIDER="alibaba"
    echo ""
    echo "请输入阿里云凭证:"
    read -p "AccessKeyId: " SECRET_ID
    read -p "AccessKeySecret: " SECRET_KEY
    read -p "地域 (例如: cn-hangzhou,cn-beijing): " REGIONS
else
    echo -e "${RED}无效选择${NC}"
    exit 1
fi

# 转换地域列表为 JSON 数组
REGION_JSON=$(json_array_to_bash "$REGIONS")

# 创建云账户
echo ""
echo -e "${YELLOW}4. 创建云账户配置...${NC}"
CREATE_RESPONSE=$(curl -s -X POST "${BASE_URL}/cloud/accounts" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @- <<EOF
{
  "config_key": "cloud_${PROVIDER}_test",
  "provider": "${PROVIDER}",
  "display_name": "${PROVIDER}云测试账户",
  "description": "测试云监控功能",
  "enabled": true,
  "config": {
    "secret_id": "${SECRET_ID}",
    "secret_key": "${SECRET_KEY}",
    "regions": ${REGION_JSON},
    "collection_interval_secs": 60,
    "instance_filter": {
      "status_whitelist": ["Running", "RUNNING"],
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
    echo "$CREATE_RESPONSE"
    exit 1
fi
echo -e "${GREEN}✓ 云账户创建成功 (ID: ${ACCOUNT_ID})${NC}"
echo ""

# 测试连接
echo -e "${YELLOW}5. 测试云API连接...${NC}"
TEST_RESPONSE=$(curl -s -X POST "${BASE_URL}/cloud/accounts/${ACCOUNT_ID}/test" \
    -H "Authorization: Bearer ${TOKEN}")

TEST_STATUS=$(json_get "$TEST_RESPONSE" "data.success")
if [ "$TEST_STATUS" != "true" ]; then
    echo -e "${RED}错误: 连接测试失败${NC}"
    ERROR_MSG=$(json_get "$TEST_RESPONSE" "data.error")
    echo "  错误信息: ${ERROR_MSG}"
    exit 1
fi
echo -e "${GREEN}✓ 云API连接成功${NC}"
INSTANCE_COUNT=$(json_get "$TEST_RESPONSE" "data.instance_count")
echo "  发现实例数: ${INSTANCE_COUNT}"
echo ""

# 触发手动采集
echo -e "${YELLOW}6. 触发手动采集...${NC}"
COLLECT_RESPONSE=$(curl -s -X POST "${BASE_URL}/cloud/accounts/${ACCOUNT_ID}/collect" \
    -H "Authorization: Bearer ${TOKEN}")

COLLECT_SUCCESS=$(json_get "$COLLECT_RESPONSE" "data.success")
if [ "$COLLECT_SUCCESS" != "true" ]; then
    echo -e "${RED}警告: 采集触发失败${NC}"
    echo "$COLLECT_RESPONSE"
else
    echo -e "${GREEN}✓ 采集已触发${NC}"
    METRICS_COLLECTED=$(json_get "$COLLECT_RESPONSE" "data.metrics_collected")
    echo "  采集指标数: ${METRICS_COLLECTED}"
fi
echo ""

# 等待数据写入
echo -e "${YELLOW}7. 等待数据写入 (10秒)...${NC}"
sleep 10
echo ""

# 查询云实例列表
echo -e "${YELLOW}8. 查询发现的云实例...${NC}"
INSTANCES_RESPONSE=$(curl -s -X GET "${BASE_URL}/cloud/instances?limit=10" \
    -H "Authorization: Bearer ${TOKEN}")

# 获取实例数量
INSTANCE_COUNT=$(echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(len(data.get('data', [])))
except:
    print(0)
")

echo -e "${GREEN}✓ 发现 ${INSTANCE_COUNT} 个云实例${NC}"

if [ "$INSTANCE_COUNT" -gt 0 ]; then
    echo ""
    echo "实例列表:"
    echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for inst in data.get('data', []):
        print(f\"  - ID: {inst.get('instance_id')}, 名称: {inst.get('instance_name')}, 状态: {inst.get('status')}, 地域: {inst.get('region')}\")
except Exception as e:
    print(f'解析错误: {e}')
"

    # 获取第一个实例的instance_id
    INSTANCE_ID=$(echo "$INSTANCES_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['data'][0]['instance_id'] if data.get('data') else '')
except:
    print('')
")

    AGENT_ID="cloud:${PROVIDER}:${INSTANCE_ID}"

    echo ""
    echo -e "${YELLOW}9. 查询实例指标数据...${NC}"

    # 查询 CPU 指标
    echo "  查询 CPU 使用率..."
    CPU_RESPONSE=$(curl -s -X GET "${BASE_URL}/metrics?agent_id__eq=${AGENT_ID}&metric_name__eq=cloud.cpu.usage&limit=5" \
        -H "Authorization: Bearer ${TOKEN}")
    CPU_COUNT=$(echo "$CPU_RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len(data.get('data', {}).get('items', [])))")
    echo -e "    ${GREEN}✓ 找到 ${CPU_COUNT} 条 CPU 数据${NC}"
    if [ "$CPU_COUNT" -gt 0 ]; then
        echo "$CPU_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
item = data.get('data', {}).get('items', [])[0]
print(f\"      最新值: {item.get('value')}% @ {item.get('timestamp')}\")
"
    fi

    # 查询内存指标
    echo "  查询内存使用率..."
    MEM_RESPONSE=$(curl -s -X GET "${BASE_URL}/metrics?agent_id__eq=${AGENT_ID}&metric_name__eq=cloud.memory.usage&limit=5" \
        -H "Authorization: Bearer ${TOKEN}")
    MEM_COUNT=$(echo "$MEM_RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len(data.get('data', {}).get('items', [])))")
    echo -e "    ${GREEN}✓ 找到 ${MEM_COUNT} 条内存数据${NC}"
    if [ "$MEM_COUNT" -gt 0 ]; then
        echo "$MEM_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
item = data.get('data', {}).get('items', [])[0]
print(f\"      最新值: {item.get('value')}% @ {item.get('timestamp')}\")
"
    fi

    # 查询网络指标
    echo "  查询网络流量..."
    NET_RESPONSE=$(curl -s -X GET "${BASE_URL}/metrics?agent_id__eq=${AGENT_ID}&metric_name__eq=cloud.network.in_bytes&limit=5" \
        -H "Authorization: Bearer ${TOKEN}")
    NET_COUNT=$(echo "$NET_RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len(data.get('data', {}).get('items', [])))")
    echo -e "    ${GREEN}✓ 找到 ${NET_COUNT} 条网络流量数据${NC}"
    if [ "$NET_COUNT" -gt 0 ]; then
        echo "$NET_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
item = data.get('data', {}).get('items', [])[0]
value = float(item.get('value', 0))
print(f\"      最新值: {value / 1024 / 1024:.2f} MB/s\")
"
    fi

    # 查询磁盘 IOPS
    echo "  查询磁盘 IOPS..."
    IOPS_RESPONSE=$(curl -s -X GET "${BASE_URL}/metrics?agent_id__eq=${AGENT_ID}&metric_name__eq=cloud.disk.iops_read&limit=5" \
        -H "Authorization: Bearer ${TOKEN}")
    IOPS_COUNT=$(echo "$IOPS_RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len(data.get('data', {}).get('items', [])))")
    echo -e "    ${GREEN}✓ 找到 ${IOPS_COUNT} 条磁盘 IOPS 数据${NC}"
    if [ "$IOPS_COUNT" -gt 0 ]; then
        echo "$IOPS_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
item = data.get('data', {}).get('items', [])[0]
print(f\"      最新值: {item.get('value')} ops/s @ {item.get('timestamp')}\")
"
    fi

    # 查询连接数
    echo "  查询 TCP 连接数..."
    CONN_RESPONSE=$(curl -s -X GET "${BASE_URL}/metrics?agent_id__eq=${AGENT_ID}&metric_name__eq=cloud.connections&limit=5" \
        -H "Authorization: Bearer ${TOKEN}")
    CONN_COUNT=$(echo "$CONN_RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len(data.get('data', {}).get('items', [])))")
    echo -e "    ${GREEN}✓ 找到 ${CONN_COUNT} 条连接数据${NC}"
    if [ "$CONN_COUNT" -gt 0 ]; then
        echo "$CONN_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
item = data.get('data', {}).get('items', [])[0]
print(f\"      最新值: {item.get('value')} 连接 @ {item.get('timestamp')}\")
"
    fi
fi

echo ""
echo "=========================================="
echo -e "${GREEN}测试完成！${NC}"
echo "=========================================="
echo ""
echo "您可以:"
echo "  - 访问 http://localhost:8080/docs 查看 API 文档"
echo "  - 查看日志了解调度器运行情况"
echo "  - 等待 30 秒后自动采集会继续进行"
echo ""
