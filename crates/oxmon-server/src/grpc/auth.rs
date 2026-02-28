use oxmon_storage::CertStore;
use std::sync::Arc;

/// gRPC 认证配置
#[derive(Clone)]
pub struct AuthInterceptor {
    #[allow(dead_code)]
    pub cert_store: Arc<CertStore>,
    pub require_auth: bool,
}

impl AuthInterceptor {
    pub fn new(cert_store: Arc<CertStore>, require_auth: bool) -> Self {
        Self {
            cert_store,
            require_auth,
        }
    }
}
