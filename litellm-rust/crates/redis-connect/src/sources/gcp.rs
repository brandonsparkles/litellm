use std::time::SystemTime;

use litellm_auth_gcp::{CredentialSource as GcpCredentialSource, GcpAuth};
use serde::Deserialize;

use crate::Error;
use crate::error::CredentialStage;
use litellm_secret_value::SecretValue;

use crate::{CredentialSource, Expiring, SharedEnvironment, SourceFuture};

const IAM_CREDENTIALS: &str = "https://iamcredentials.googleapis.com/v1";
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

pub(crate) struct GcpIam {
    http: litellm_http::Client,
    identity: GcpAuth,
    service_account: String,
    lookup: SharedEnvironment,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessToken {
    access_token: String,
    expire_time: String,
}

impl GcpIam {
    pub(crate) fn new(
        http: litellm_http::Client,
        service_account: String,
        lookup: SharedEnvironment,
    ) -> Self {
        Self {
            http,
            identity: GcpAuth::default(),
            service_account,
            lookup,
        }
    }
}

impl CredentialSource for GcpIam {
    fn fetch(&self) -> SourceFuture<'_> {
        Box::pin(async move {
            let lookup = |name: &str| self.lookup.get(name);
            let caller = self
                .identity
                .access_token(GcpCredentialSource::application_default(&lookup))
                .await
                .map_err(Error::credential(CredentialStage::Identity))?;
            let response = self
                .http
                .post(format!(
                    "{IAM_CREDENTIALS}/{}:generateAccessToken",
                    self.service_account
                ))
                .bearer_auth(caller.expose())
                .json(&serde_json::json!({ "scope": [CLOUD_PLATFORM_SCOPE] }))
                .send()
                .await
                .map_err(Error::credential(CredentialStage::Exchange))?;
            let status = response.status().as_u16();
            let reply: AccessToken = response
                .error_for_status()
                .map_err(litellm_http::Error::from)
                .map_err(Error::credential_response(
                    CredentialStage::Exchange,
                    status,
                ))?
                .json()
                .await
                .map_err(litellm_http::Error::from)
                .map_err(Error::credential(CredentialStage::Response))?;
            let expires_at = time::OffsetDateTime::parse(
                &reply.expire_time,
                &time::format_description::well_known::Rfc3339,
            )
            .map(SystemTime::from)
            .map_err(Error::credential(CredentialStage::Response))?;
            Ok(Expiring {
                username: None,
                password: SecretValue::new(reply.access_token),
                expires_at: Some(expires_at),
            })
        })
    }
}
