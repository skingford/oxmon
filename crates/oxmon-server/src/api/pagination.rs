use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::IntoParams;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct PaginationParams {
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub offset: Option<u64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum U64Input {
    Number(u64),
    Text(String),
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<U64Input>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(U64Input::Number(number)) => Ok(Some(number)),
        Some(U64Input::Text(text)) => text
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(DeError::custom),
    }
}

const MAX_PAGE_LIMIT: u64 = 1000;

impl PaginationParams {
    pub fn limit(&self) -> usize {
        self.limit.unwrap_or(20).min(MAX_PAGE_LIMIT) as usize
    }

    pub fn offset(&self) -> usize {
        self.offset.unwrap_or(0) as usize
    }
}
