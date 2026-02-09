use snowflake::SnowflakeIdBucket;
use std::sync::Mutex;

static ID_GENERATOR: Mutex<Option<SnowflakeIdBucket>> = Mutex::new(None);

/// 初始化 Snowflake ID 生成器
///
/// `machine_id`: 机器标识 (0-31)
/// `node_id`: 节点标识 (0-31)
pub fn init(machine_id: i32, node_id: i32) {
    let mut gen = ID_GENERATOR.lock().unwrap();
    *gen = Some(SnowflakeIdBucket::new(machine_id, node_id));
}

/// 生成一个 Snowflake ID（字符串形式）
pub fn next_id() -> String {
    let mut gen = ID_GENERATOR.lock().unwrap();
    let bucket = gen.get_or_insert_with(|| SnowflakeIdBucket::new(1, 1));
    bucket.get_id().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_next_id_returns_unique_ids() {
        init(1, 1);
        let mut ids = HashSet::new();
        for _ in 0..1000 {
            let id = next_id();
            assert!(!id.is_empty());
            assert!(ids.insert(id), "Duplicate ID generated");
        }
    }

    #[test]
    fn test_next_id_is_numeric() {
        init(1, 1);
        let id = next_id();
        assert!(
            id.parse::<i64>().is_ok(),
            "ID should be a valid i64: {}",
            id
        );
    }
}
