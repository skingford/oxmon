use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "certificate_details")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub domain: String,
    pub not_before: DateTimeWithTimeZone,
    pub not_after: DateTimeWithTimeZone,
    pub ip_addresses: String,
    pub issuer_cn: Option<String>,
    pub issuer_o: Option<String>,
    pub issuer_ou: Option<String>,
    pub issuer_c: Option<String>,
    pub subject_alt_names: Option<String>,
    pub chain_valid: bool,
    pub chain_error: Option<String>,
    pub last_checked: DateTimeWithTimeZone,
    pub serial_number: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub version: Option<i32>,
    pub signature_algorithm: Option<String>,
    pub public_key_algorithm: Option<String>,
    pub public_key_bits: Option<i32>,
    pub subject_cn: Option<String>,
    pub subject_o: Option<String>,
    pub key_usage: Option<String>,
    pub extended_key_usage: Option<String>,
    pub is_ca: Option<bool>,
    pub is_wildcard: Option<bool>,
    pub ocsp_urls: Option<String>,
    pub crl_urls: Option<String>,
    pub ca_issuer_urls: Option<String>,
    pub sct_count: Option<i32>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub chain_depth: Option<i32>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
