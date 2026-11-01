use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use litellm_auth_gcp::{
    CredentialSource, VertexAuth, VertexAuthFuture, VertexConfig, VertexProviderLoader,
    VertexTokenSource, get_vertex_ai_location, secret_names,
};
use litellm_secret_value::SecretValue;
use rstest::rstest;
use serde_json::{Value, json};

struct FakeProvider {
    project: Option<&'static str>,
    calls: Arc<AtomicUsize>,
}

impl VertexTokenSource for FakeProvider {
    fn project_id(&self) -> VertexAuthFuture<'_, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.project
                .map(str::to_owned)
                .ok_or(litellm_auth_types::Error::CredentialAcquisition(
                    litellm_auth_types::ErrorDetail::Unresolved {
                        subject: "credential project",
                    },
                ))
        })
    }

    fn token(&self) -> VertexAuthFuture<'_, SecretValue> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(SecretValue::new("adc-token")) })
    }
}

struct FakeLoader {
    loads: Arc<AtomicUsize>,
    provider: Arc<dyn VertexTokenSource>,
}

impl VertexProviderLoader for FakeLoader {
    fn load(&self, _source: CredentialSource) -> VertexAuthFuture<'_, Arc<dyn VertexTokenSource>> {
        let loads = self.loads.clone();
        let provider = self.provider.clone();
        Box::pin(async move {
            loads.fetch_add(1, Ordering::SeqCst);
            Ok(provider)
        })
    }
}

fn config(value: Value) -> VertexConfig {
    VertexConfig::from_sourced_optional_params(value.as_object().unwrap(), &BTreeMap::new())
        .unwrap()
}

fn auth(calls: Arc<AtomicUsize>, loads: Arc<AtomicUsize>) -> VertexAuth {
    let provider: Arc<dyn VertexTokenSource> = Arc::new(FakeProvider {
        calls,
        project: Some("adc-project"),
    });
    VertexAuth::new(Arc::new(FakeLoader { loads, provider }))
}

#[rstest]
#[tokio::test]
async fn secret_names_cover_environment_reads() {
    let seen = Arc::new(std::sync::Mutex::new(BTreeSet::<String>::new()));
    let recorded = seen.clone();
    let env = |name: &str| {
        recorded.lock().unwrap().insert(name.to_string());
        None
    };
    let auth = auth(Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    auth.validate_environment(Vec::new(), None, &VertexConfig::default(), &env)
        .await
        .unwrap();
    get_vertex_ai_location(&VertexConfig::default(), &env);
    let allowed = secret_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    assert!(seen.lock().unwrap().is_subset(&allowed));
}

#[rstest]
#[tokio::test]
async fn explicit_token_and_header_do_not_acquire_adc() {
    let loads = Arc::new(AtomicUsize::new(0));
    let auth = auth(Arc::new(AtomicUsize::new(0)), loads.clone());
    let configured = config(json!({"vertex_project":"project-1"}));
    let explicit = auth
        .validate_environment(Vec::new(), Some("access-token"), &configured, &|_| None)
        .await
        .unwrap();
    assert_eq!(explicit.headers[0].1, "Bearer access-token");
    let existing = auth
        .validate_environment(
            vec![("authorization".into(), "Bearer existing".into())],
            None,
            &configured,
            &|_| None,
        )
        .await
        .unwrap();
    assert_eq!(existing.headers[0].1, "Bearer existing");
    assert_eq!(loads.load(Ordering::SeqCst), 0);
}

#[rstest]
#[tokio::test]
async fn provider_is_reused_across_authentication_calls() {
    let calls = Arc::new(AtomicUsize::new(0));
    let loads = Arc::new(AtomicUsize::new(0));
    let auth = auth(calls.clone(), loads.clone());
    let config = VertexConfig::default();
    let environment = |_: &str| None;
    let (first, second) = tokio::try_join!(
        auth.validate_environment(Vec::new(), None, &config, &environment),
        auth.validate_environment(Vec::new(), None, &config, &environment),
    )
    .unwrap();
    assert_eq!(first.project_id, "adc-project");
    assert_eq!(first.headers[0].1, "Bearer adc-token");
    assert_eq!(first.project_id, second.project_id);
    assert_eq!(first.headers, second.headers);
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[rstest]
#[tokio::test]
async fn an_explicit_project_does_not_require_project_metadata_in_the_credentials() {
    let auth = VertexAuth::new(Arc::new(FakeLoader {
        loads: Arc::new(AtomicUsize::new(0)),
        provider: Arc::new(FakeProvider {
            calls: Arc::new(AtomicUsize::new(0)),
            project: None,
        }),
    }));
    let configured = VertexConfig::new(None, Some("configured-project".into()), None);
    let environment = auth
        .validate_environment(Vec::new(), None, &configured, &|_| None)
        .await
        .unwrap();
    assert_eq!(environment.project_id, "configured-project");
    assert_eq!(environment.headers[0].1, "Bearer adc-token");
}
