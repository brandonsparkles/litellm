use litellm_redis_types::TlsOptions;

use super::{Expected, Kwargs, RedisError, bool_value, parsed, text_value};

pub(super) fn tls_options(
    merged: &Kwargs,
    gcp_ca_certs: Option<String>,
) -> Result<TlsOptions, RedisError> {
    let verify_certificate =
        parsed(
            merged,
            "ssl_cert_reqs",
            Expected::CertRequirement,
            |text| match text {
                "required" | "optional" => Some(true),
                "none" => Some(false),
                _ => None,
            },
        )?
        .unwrap_or(true);
    Ok(TlsOptions {
        ca_certs: gcp_ca_certs
            .or_else(|| text_value(merged, "ssl_ca_certs"))
            .map(Into::into),
        certfile: text_value(merged, "ssl_certfile").map(Into::into),
        keyfile: text_value(merged, "ssl_keyfile").map(Into::into),
        verify_certificate,
        check_hostname: bool_value(merged, "ssl_check_hostname"),
    })
}
