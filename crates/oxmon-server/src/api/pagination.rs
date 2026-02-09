use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa::IntoParams;

#[derive(Debug, Clone, Serialize, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct PaginationParams {
    /// 每页条数（默认 20）
    #[param(required = false)]
    pub limit: Option<u64>,
    /// 分页偏移量（默认 0）
    #[param(required = false)]
    pub offset: Option<u64>,
}

impl PaginationParams {
    pub fn limit(&self) -> usize {
        self.limit.unwrap_or(20) as usize
    }

    pub fn offset(&self) -> usize {
        self.offset.unwrap_or(0) as usize
    }
}
