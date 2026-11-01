use std::sync::Arc;

use litellm_auth_types::{CredentialPlacement, Error, http::apply_credential};

use crate::{
    config::{VertexConfig, credential_source, get_vertex_ai_project, non_empty_env},
    constants::{VERTEX_AI_API_KEY_ENV, VERTEXAI_API_KEY_ENV},
    identity::{GcpAuth, GcpProviderLoader, GcpTokenSource},
};

pub struct VertexEnvironment {
    pub headers: Vec<(String, String)>,
    pub project_id: String,
}

#[derive(Clone, Default)]
pub struct VertexAuth {
    identity: GcpAuth,
}

impl VertexAuth {
    pub fn new(loader: Arc<dyn GcpProviderLoader>) -> Self {
        Self {
            identity: GcpAuth::new(loader),
        }
    }

    pub async fn access_token(
        &self,
        config: &VertexConfig,
        env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
    ) -> Result<String, Error> {
        self.identity
            .access_token(credential_source(config, env_lookup))
            .await
            .map(|token| token.expose().to_owned())
    }

    pub async fn validate_environment(
        &self,
        headers: Vec<(String, String)>,
        api_key: Option<&str>,
        config: &VertexConfig,
        env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
    ) -> Result<VertexEnvironment, Error> {
        let has_authorization = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Authorization"));
        let static_token = api_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| non_empty_env(env_lookup, VERTEX_AI_API_KEY_ENV))
            .or_else(|| non_empty_env(env_lookup, VERTEXAI_API_KEY_ENV));
        let project_id = get_vertex_ai_project(config, env_lookup);

        let static_token = match (has_authorization, static_token) {
            (true, _) => None,
            (false, Some(token)) => Some(token),
            (false, None) => {
                let provider = self.load_provider(config, env_lookup).await?;
                let (token, project_id) = match project_id {
                    Some(project_id) => (provider.token().await?, project_id),
                    None => tokio::try_join!(provider.token(), provider.project_id())?,
                };
                return Ok(VertexEnvironment {
                    headers: apply_credential(
                        headers,
                        token.expose(),
                        CredentialPlacement::Bearer,
                    )?,
                    project_id,
                });
            }
        };

        let project_id = match project_id {
            Some(project_id) => project_id,
            None => {
                self.load_provider(config, env_lookup)
                    .await?
                    .project_id()
                    .await?
            }
        };
        let headers = match static_token {
            Some(token) => apply_credential(headers, &token, CredentialPlacement::Bearer)?,
            None => headers,
        };
        Ok(VertexEnvironment {
            headers,
            project_id,
        })
    }

    async fn load_provider(
        &self,
        config: &VertexConfig,
        env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
    ) -> Result<Arc<dyn GcpTokenSource>, Error> {
        self.identity
            .load_provider(credential_source(config, env_lookup))
            .await
    }
}
