pub mod i18n;
pub mod id;
pub mod types;

pub mod proto {
    #![allow(clippy::pedantic)]
    #![allow(clippy::missing_errors_doc)]
    #![allow(clippy::doc_markdown)]
    #![allow(clippy::default_trait_access)]
    tonic::include_proto!("oxmon");
}
