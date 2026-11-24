#![doc = include_str!("../README.md")]

mod certificate;
mod downloader;
mod error;
mod url;

pub use certificate::{CertificateFields, CertificateProperties, Extension, SslCertificate};
pub use downloader::{Downloader, SocketOptions};
pub use error::Error;
pub use url::Url;

#[cfg(doctest)]
mod guide {
    include!(concat!(env!("OUT_DIR"), "/documentation.rs"));
}
