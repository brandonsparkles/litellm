use std::time::{Duration, SystemTime};

use litellm_auth_aws::{AwsAuthConfig, AwsAuthService, SigningScope, presign_url};
use litellm_config::AwsIamAuth;

use crate::Error;
use crate::error::CredentialStage;
use litellm_secret_value::SecretValue;

use crate::{CredentialSource, Expiring, SharedEnvironment, SourceFuture};

const SERVICE: &str = "elasticache";
const TOKEN_LIFETIME: Duration = Duration::from_secs(900);
const SDK_ENVIRONMENT: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
];

pub(crate) struct ElastiCacheIam {
    service: AwsAuthService,
    auth: AwsIamAuth,
    lookup: SharedEnvironment,
}

impl ElastiCacheIam {
    pub(crate) fn new(auth: AwsIamAuth, lookup: SharedEnvironment) -> Self {
        Self {
            service: AwsAuthService::default(),
            auth,
            lookup: super::sdk_environment(lookup, SDK_ENVIRONMENT),
        }
    }
}

pub(crate) fn connect_url(auth: &AwsIamAuth) -> String {
    let query = [
        Some(("Action", "connect")),
        Some(("User", auth.user_name.as_str())),
        auth.serverless
            .then_some(("ResourceType", "ServerlessCache")),
    ];
    let mut url = String::from("https://");
    url.push_str(&auth.cache_name.to_lowercase());
    url.push_str("/?");
    url.push_str(
        &url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query.into_iter().flatten())
            .finish(),
    );
    url
}

impl CredentialSource for ElastiCacheIam {
    fn fetch(&self) -> SourceFuture<'_> {
        Box::pin(async move {
            let lookup = |name: &str| self.lookup.get(name);
            let credentials = self
                .service
                .resolve_credentials(
                    AwsAuthConfig {
                        region_name: Some(self.auth.region.clone()),
                        ..Default::default()
                    },
                    &lookup,
                )
                .await
                .map_err(Error::credential(CredentialStage::Identity))?;
            let now = SystemTime::now();
            let signed = presign_url(
                &connect_url(&self.auth),
                TOKEN_LIFETIME,
                SigningScope {
                    region: &self.auth.region,
                    service: SERVICE,
                    credentials: &credentials,
                    time: now,
                },
            )
            .map_err(Error::credential(CredentialStage::Signing))?;
            let token_expiry = now + TOKEN_LIFETIME;
            Ok(Expiring {
                username: Some(self.auth.user_name.clone()),
                password: SecretValue::new(signed.trim_start_matches("https://")),
                expires_at: Some(
                    credentials
                        .expiry()
                        .map_or(token_expiry, |expiry| expiry.min(token_expiry)),
                ),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use litellm_config::AwsIamAuth;
    use rstest::rstest;

    use super::{ElastiCacheIam, connect_url};
    use crate::CredentialSource;

    #[rstest]
    #[case::provisioned(false, "https://cache-1/?Action=connect&User=iam+user%2F1")]
    #[case::serverless(
        true,
        "https://cache-1/?Action=connect&User=iam+user%2F1&ResourceType=ServerlessCache"
    )]
    fn the_connect_url_matches_python_urlencode(#[case] serverless: bool, #[case] expected: &str) {
        let auth = AwsIamAuth {
            user_name: "iam user/1".to_owned(),
            cache_name: "Cache-1".to_owned(),
            region: "us-east-1".to_owned(),
            serverless,
        };

        assert_eq!(connect_url(&auth), expected);
    }

    #[rstest]
    #[tokio::test]
    async fn litellm_provider_settings_do_not_change_the_redis_identity() {
        let environment = |name: &str| {
            match name {
                "AWS_ACCESS_KEY_ID" => Some("AKIDREDIS"),
                "AWS_SECRET_ACCESS_KEY" => Some("redis-secret"),
                "AWS_ROLE_NAME" => Some("arn:aws:iam::123456789012:role/bedrock"),
                "AWS_PROFILE_NAME" => Some("bedrock"),
                "AWS_STS_ENDPOINT" => Some("http://127.0.0.1:1"),
                _ => None,
            }
            .map(str::to_owned)
        };
        let source = ElastiCacheIam::new(
            AwsIamAuth {
                user_name: "redis-user".to_owned(),
                cache_name: "cache-1".to_owned(),
                region: "us-east-1".to_owned(),
                serverless: false,
            },
            std::sync::Arc::new(environment),
        );

        let token = source.fetch().await.unwrap();

        assert!(
            token
                .password
                .expose()
                .contains("X-Amz-Credential=AKIDREDIS%2F")
        );
    }
}
