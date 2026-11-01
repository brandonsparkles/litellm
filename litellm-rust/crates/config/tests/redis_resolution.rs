//! What `RedisSettings::resolve` makes of each input, written next to the input. The same cases
//! with the same expected values sit in `tests/unit/test_redis.py`, asserted against
//! `litellm/_redis.py`, so a resolution rule change lands in both files or fails one of them.

use std::collections::HashMap;

use litellm_config::{RedisAuth, RedisError, RedisSettings, ResolvedRedis, SecretSnapshot};
use litellm_redis_types::{ClusterNode, Endpoint, TlsOptions};
use rstest::rstest;

fn resolve(kwargs: &str, environment: &[(&str, &str)]) -> Result<ResolvedRedis, RedisError> {
    let settings: RedisSettings = serde_json::from_str(kwargs).unwrap();
    let environment: HashMap<String, String> = environment
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    let lookup = |name: &str| environment.get(name).cloned();
    settings.resolve(
        &SecretSnapshot::read(settings.secret_names(), &lookup),
        &lookup,
    )
}

fn tls_view(tls: Option<&TlsOptions>) -> serde_json::Value {
    tls.map_or(serde_json::Value::Null, |tls| {
        serde_json::json!({
            "ca_certs": tls.ca_certs,
            "ca_data": tls.ca_data,
            "ca_path": tls.ca_path,
            "certfile": tls.certfile,
            "keyfile": tls.keyfile,
            "verify_certificate": tls.verify_certificate,
            "check_hostname": tls.check_hostname,
        })
    })
}

fn nodes_view(nodes: &[ClusterNode]) -> Vec<String> {
    nodes
        .iter()
        .map(|node| format!("{}:{}", node.host, node.port))
        .collect()
}

fn expose(value: Option<&litellm_secret_value::SecretValue>) -> Option<&str> {
    value.map(litellm_secret_value::SecretValue::expose)
}

fn view(resolved: &ResolvedRedis) -> serde_json::Value {
    let target = match &resolved.endpoint {
        Endpoint::Host(host) => match &host.unix_socket_path {
            Some(path) => serde_json::json!({"mode": "unix", "path": path}),
            None => serde_json::json!({
                "mode": "host",
                "host": host.host,
                "port": host.port,
                "db": host.db,
                "tls": tls_view(host.tls.as_ref()),
            }),
        },
        Endpoint::Url { url, tls } => serde_json::json!({
            "mode": "url",
            "url": url.expose(),
            "tls": tls_view(url.expose().starts_with("rediss://").then_some(tls)),
        }),
        Endpoint::Cluster(cluster) => serde_json::json!({
            "mode": "cluster",
            "nodes": nodes_view(&cluster.nodes),
            "tls": tls_view(cluster.tls.as_ref()),
        }),
        Endpoint::Sentinel(sentinel) => serde_json::json!({
            "mode": "sentinel",
            "nodes": nodes_view(&sentinel.sentinels),
            "service_name": sentinel.service_name,
            "sentinel_password": expose(sentinel.sentinel_password.as_ref()),
            "db": sentinel.db,
            "tls": tls_view(sentinel.tls.as_ref()),
        }),
    };
    let auth = match &resolved.auth {
        RedisAuth::Static { username, password } => serde_json::json!({
            "kind": "static",
            "username": expose(username.as_ref()),
            "password": expose(password.as_ref()),
        }),
        RedisAuth::Host => serde_json::json!({"kind": "host"}),
        RedisAuth::GcpIam { service_account } => {
            serde_json::json!({"kind": "gcp_iam", "service_account": service_account})
        }
        RedisAuth::AzureAd(azure) => {
            serde_json::json!({"kind": "azure_ad", "username": azure.username})
        }
        RedisAuth::AwsIam(aws) => serde_json::json!({
            "kind": "aws_iam",
            "user_name": aws.user_name,
            "cache_name": aws.cache_name,
            "region": aws.region,
            "serverless": aws.serverless,
        }),
    };
    let serde_json::Value::Object(target) = target else {
        unreachable!("every target view is an object")
    };
    let rest = serde_json::json!({
        "auth": auth,
        "socket_timeout": resolved.timeout.map_or(5.0, |timeout| timeout.as_secs_f64()),
        "socket_connect_timeout": resolved.connect_timeout.map(|timeout| timeout.as_secs_f64()),
        "health_check_interval": resolved.health_check_interval.map(|interval| interval.as_secs_f64()),
    });
    let serde_json::Value::Object(rest) = rest else {
        unreachable!("the view is an object")
    };
    serde_json::Value::Object(target.into_iter().chain(rest).collect())
}

#[rstest]
#[case::host_defaults(
    r#"{"host": "redis"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::host_with_every_basic_setting(
    r#"{"db": 2, "host": "redis", "password": "pass", "port": 6380, "socket_timeout": 1.5, "ssl": true, "username": "user"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": "pass",
                "username": "user"
            },
            "db": 2,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6380,
            "socket_connect_timeout": null,
            "socket_timeout": 1.5,
            "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
        })
)]
#[case::environment_host_port_and_password(
    r#"{}"#,
    &[("REDIS_HOST", "environment"), ("REDIS_PASSWORD", "environment-secret"), ("REDIS_PORT", "6390"), ("REDIS_SSL", "True")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": "environment-secret",
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "environment",
            "mode": "host",
            "port": 6390,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
        })
)]
#[case::string_numbers_are_coerced(
    r#"{"db": "3", "host": "redis", "port": "6380", "socket_timeout": "2.5"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 3,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6380,
            "socket_connect_timeout": null,
            "socket_timeout": 2.5,
            "tls": null
        })
)]
#[case::socket_timeout_from_the_environment(
    r#"{"host": "redis"}"#,
    &[("REDIS_SOCKET_TIMEOUT", "0.75")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 0.75,
            "tls": null
        })
)]
#[case::environment_url(
    r#"{}"#,
    &[("REDIS_URL", "redis://environment:6379/1")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "health_check_interval": null,
            "mode": "url",
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null,
            "url": "redis://environment:6379/1"
        })
)]
#[case::environment_url_beats_the_environment_host(
    r#"{}"#,
    &[("REDIS_HOST", "ignored"), ("REDIS_URL", "redis://from-url:6379")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "health_check_interval": null,
            "mode": "url",
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null,
            "url": "redis://from-url:6379"
        })
)]
#[case::an_explicit_host_drops_the_environment_url(
    r#"{"host": "configured"}"#,
    &[("REDIS_URL", "redis://environment:6379")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "configured",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::a_url_drops_host_db_and_password_and_keeps_the_username(
    r#"{"db": 4, "host": "dropped", "password": "dropped", "url": "rediss://cache:6380", "username": "user"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": "user"
            },
            "health_check_interval": null,
            "mode": "url",
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            },
            "url": "rediss://cache:6380"
        })
)]
#[case::a_url_ignores_tls_settings_outside_the_url(
    r#"{"ssl_ca_certs": "/ca.pem", "ssl_cert_reqs": "none", "ssl_check_hostname": true, "url": "rediss://cache:6380"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "health_check_interval": null,
            "mode": "url",
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            },
            "url": "rediss://cache:6380"
        })
)]
#[case::startup_nodes_beat_a_url(
    r#"{"password": "cluster-secret", "startup_nodes": [{"host": "node-a", "port": 7000}], "url": "redis://single:6379"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": "cluster-secret",
                "username": null
            },
            "health_check_interval": null,
            "mode": "cluster",
            "nodes": [
                "node-a:7000"
            ],
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::environment_cluster_nodes(
    r#"{}"#,
    &[("REDIS_CLUSTER_NODES", "[{\"host\": \"node-a\", \"port\": \"7000\"}, {\"host\": \"node-b\", \"port\": 7001}]")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "health_check_interval": null,
            "mode": "cluster",
            "nodes": [
                "node-a:7000",
                "node-b:7001"
            ],
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::cluster_tls_options(
    r#"{"ssl": "true", "ssl_ca_certs": "/ca.pem", "ssl_check_hostname": true, "startup_nodes": [{"host": "node-a", "port": 7000}]}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "health_check_interval": null,
            "mode": "cluster",
            "nodes": [
                "node-a:7000"
            ],
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": "/ca.pem",
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": true,
                "verify_certificate": true
            }
        })
)]
#[case::sentinel_from_settings(
    r#"{"password": "data-secret", "sentinel_nodes": [["sentinel-a", 26379], ["sentinel-b", 26380]], "sentinel_password": "sentinel-secret", "service_name": "primary"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": "data-secret",
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "mode": "sentinel",
            "nodes": [
                "sentinel-a:26379",
                "sentinel-b:26380"
            ],
            "sentinel_password": "sentinel-secret",
            "service_name": "primary",
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::sentinel_from_the_environment(
    r#"{}"#,
    &[("REDIS_SENTINEL_NODES", "[[\"sentinel-a\", 26379]]"), ("REDIS_SENTINEL_PASSWORD", "sentinel-secret"), ("REDIS_SERVICE_NAME", "primary")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "mode": "sentinel",
            "nodes": [
                "sentinel-a:26379"
            ],
            "sentinel_password": "sentinel-secret",
            "service_name": "primary",
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::a_url_beats_sentinels(
    r#"{"sentinel_nodes": [["sentinel-a", 26379]], "service_name": "primary", "url": "redis://single:6379"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "health_check_interval": null,
            "mode": "url",
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null,
            "url": "redis://single:6379"
        })
)]
#[case::an_explicit_credential_provider_beats_cloud_auth(
    r#"{"aws_iam_auth": true, "credential_provider": true, "gcp_service_account": "account", "host": "redis", "password": "dropped"}"#,
    &[("REDIS_AZURE_AD_TOKEN", "true")],
    serde_json::json!({
            "auth": {
                "kind": "host"
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::gcp_beats_azure_and_aws(
    r#"{"aws_iam_auth": true, "azure_redis_ad_token": "True", "host": "redis", "password": "dropped"}"#,
    &[("REDIS_GCP_SERVICE_ACCOUNT", "projects/-/serviceAccounts/sa@project.iam.gserviceaccount.com")],
    serde_json::json!({
            "auth": {
                "kind": "gcp_iam",
                "service_account": "projects/-/serviceAccounts/sa@project.iam.gserviceaccount.com"
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::gcp_ca_certs_replace_the_configured_ones_under_ssl(
    r#"{"gcp_service_account": "account", "gcp_ssl_ca_certs": "/gcp-ca.pem", "host": "redis", "ssl": true, "ssl_ca_certs": "/configured-ca.pem"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "gcp_iam",
                "service_account": "account"
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": "/gcp-ca.pem",
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
        })
)]
#[case::azure_beats_aws_and_takes_the_environment_username(
    r#"{"aws_iam_auth": true, "azure_client_id": "client", "azure_client_secret": "secret", "azure_redis_ad_token": true, "azure_tenant_id": "tenant", "host": "redis", "username": "dropped"}"#,
    &[("REDIS_USERNAME", "environment-user")],
    serde_json::json!({
            "auth": {
                "kind": "azure_ad",
                "username": "environment-user"
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::azure_without_a_username_sends_only_the_token(
    r#"{"azure_client_id": "client", "azure_client_secret": "secret", "azure_redis_ad_token": true, "azure_tenant_id": "tenant", "host": "redis"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "azure_ad",
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::azure_needs_the_literal_true(
    r#"{"azure_client_id": "client", "azure_client_secret": "secret", "azure_redis_ad_token": "1", "azure_tenant_id": "tenant", "host": "redis"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::aws_iam_over_tls_with_the_default_region(
    r#"{"aws_iam_auth": "yes", "aws_iam_cache_name": "cache-1", "aws_iam_user_name": "iam-user", "host": "cache-1", "password": "dropped", "ssl": true}"#,
    &[("AWS_DEFAULT_REGION", "us-east-1")],
    serde_json::json!({
            "auth": {
                "cache_name": "cache-1",
                "kind": "aws_iam",
                "region": "us-east-1",
                "serverless": false,
                "user_name": "iam-user"
            },
            "db": 0,
            "health_check_interval": null,
            "host": "cache-1",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
        })
)]
#[case::aws_region_beats_the_default_region(
    r#"{"aws_iam_auth": true, "aws_iam_cache_name": "cache-1", "aws_iam_user_name": "iam-user", "host": "cache-1", "ssl": true}"#,
    &[("AWS_DEFAULT_REGION", "us-east-1"), ("AWS_REGION", "eu-central-1")],
    serde_json::json!({
            "auth": {
                "cache_name": "cache-1",
                "kind": "aws_iam",
                "region": "eu-central-1",
                "serverless": false,
                "user_name": "iam-user"
            },
            "db": 0,
            "health_check_interval": null,
            "host": "cache-1",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
        })
)]
#[case::aws_iam_serverless_over_a_rediss_url_drops_its_userinfo(
    r#"{"aws_iam_auth": true, "aws_iam_cache_name": "cache-1", "aws_iam_region": "eu-west-1", "aws_iam_serverless": true, "aws_iam_user_name": "iam-user", "url": "rediss://user:pass@cache-1:6379"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "cache_name": "cache-1",
                "kind": "aws_iam",
                "region": "eu-west-1",
                "serverless": true,
                "user_name": "iam-user"
            },
            "health_check_interval": null,
            "mode": "url",
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            },
            "url": "rediss://cache-1:6379"
        })
)]
#[case::tls_options_from_settings(
    r#"{"host": "redis", "ssl": true, "ssl_ca_certs": "/ca.pem", "ssl_cert_reqs": "none", "ssl_check_hostname": true}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": "/ca.pem",
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": true,
                "verify_certificate": false
            }
        })
)]
#[case::tls_options_from_the_environment(
    r#"{"host": "redis"}"#,
    &[("REDIS_SSL", "true"), ("REDIS_SSL_CA_CERTS", "/env-ca.pem"), ("REDIS_SSL_CERT_REQS", "optional")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": "/env-ca.pem",
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
        })
)]
#[case::connect_timeout_is_separate_from_the_socket_timeout(
    r#"{"host": "redis", "socket_connect_timeout": 0.25, "socket_timeout": 2.5}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": 0.25,
            "socket_timeout": 2.5,
            "tls": null
        })
)]
#[case::environment_references_resolve(
    r#"{"host": "os.environ/COORD_HOST", "password": "os.environ/COORD_PASSWORD"}"#,
    &[("COORD_HOST", "referenced"), ("COORD_PASSWORD", "referenced-secret")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": "referenced-secret",
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "referenced",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::ssl_ciphers(
    r#"{"host": "redis", "ssl": true, "ssl_ciphers": "HIGH"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
        })
)]
#[case::retry_on_timeout(
    r#"{"host": "redis", "retry_on_timeout": true}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::malformed_port(
    r#"{"host": "redis", "port": "abc"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::malformed_db(
    r#"{"db": "first", "host": "redis"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::socket_timeout_not_a_number(
    r#"{"host": "redis", "socket_timeout": "slow"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::malformed_port_from_the_environment(
    r#"{}"#,
    &[("REDIS_HOST", "redis"), ("REDIS_PORT", "abc")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::protocol_3(
    r#"{"host": "redis", "protocol": 3}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::retry_on_error_from_the_environment(
    r#"{"host": "redis"}"#,
    &[("REDIS_RETRY_ON_ERROR", "true")],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null
        })
)]
#[case::unix_socket_path(
    r#"{"host": "redis", "unix_socket_path": "/tmp/redis.sock"}"#,
    &[],
    serde_json::json!({
    "auth": {
        "kind": "static",
        "password": null,
        "username": null
    },
    "mode": "unix",
    "path": "/tmp/redis.sock",
    "health_check_interval": null,
    "socket_connect_timeout": null,
    "socket_timeout": 5.0
})
)]
#[case::unix_socket_path_keeps_tls_settings_out_of_the_target(
    r#"{"host": "redis", "ssl": true, "ssl_ca_certs": "/ca.pem", "unix_socket_path": "/tmp/redis.sock"}"#,
    &[],
    serde_json::json!({
    "auth": {
        "kind": "static",
        "password": null,
        "username": null
    },
    "mode": "unix",
    "path": "/tmp/redis.sock",
    "health_check_interval": null,
    "socket_connect_timeout": null,
    "socket_timeout": 5.0
})
)]
#[case::client_certificates(
    r#"{"host": "redis", "ssl": true, "ssl_certfile": "/client.pem", "ssl_keyfile": "/client.key"}"#,
    &[],
    serde_json::json!({
    "auth": {
        "kind": "static",
        "password": null,
        "username": null
    },
    "db": 0,
    "host": "redis",
    "mode": "host",
    "port": 6379,
    "health_check_interval": null,
    "socket_connect_timeout": null,
    "socket_timeout": 5.0,
    "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": "/client.pem",
                "keyfile": "/client.key",
                "check_hostname": false,
                "verify_certificate": true
            }
})
)]
#[case::ssl_ca_data(
    r#"{"host": "redis", "ssl": true, "ssl_ca_data": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}"#,
    &[],
    serde_json::json!({
    "auth": {
        "kind": "static",
        "password": null,
        "username": null
    },
    "db": 0,
    "host": "redis",
    "mode": "host",
    "port": 6379,
    "health_check_interval": null,
    "socket_connect_timeout": null,
    "socket_timeout": 5.0,
    "tls": {
                "ca_certs": null,
                "ca_data": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
})
)]
#[case::ssl_ca_path_from_the_environment(
    r#"{"host": "redis"}"#,
    &[("REDIS_SSL", "true"), ("REDIS_SSL_CA_PATH", "/etc/ssl/private-cas")],
    serde_json::json!({
    "auth": {
        "kind": "static",
        "password": null,
        "username": null
    },
    "db": 0,
    "host": "redis",
    "mode": "host",
    "port": 6379,
    "health_check_interval": null,
    "socket_connect_timeout": null,
    "socket_timeout": 5.0,
    "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": "/etc/ssl/private-cas",
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            }
})
)]
#[case::a_rediss_url_takes_tls_options_from_its_query(
    r#"{"url": "rediss://cache:6380/0?ssl_cert_reqs=none&ssl_ca_certs=/ca.pem&ssl_check_hostname=yes"}"#,
    &[],
    serde_json::json!({
    "auth": {
        "kind": "static",
        "password": null,
        "username": null
    },
    "mode": "url",
    "health_check_interval": null,
    "socket_connect_timeout": null,
    "socket_timeout": 5.0,
    "tls": {
                "ca_certs": "/ca.pem",
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": true,
                "verify_certificate": false
            },
    "url": "rediss://cache:6380/0?ssl_cert_reqs=none&ssl_ca_certs=/ca.pem&ssl_check_hostname=yes"
})
)]
#[case::tls_settings_outside_a_url_never_fail_it(
    r#"{"url": "rediss://cache:6380", "ssl_cert_reqs": "strict", "db": "99999999999999999999"}"#,
    &[],
    serde_json::json!({
    "auth": {
        "kind": "static",
        "password": null,
        "username": null
    },
    "mode": "url",
    "health_check_interval": null,
    "socket_connect_timeout": null,
    "socket_timeout": 5.0,
    "tls": {
                "ca_certs": null,
                "ca_data": null,
                "ca_path": null,
                "certfile": null,
                "keyfile": null,
                "check_hostname": false,
                "verify_certificate": true
            },
    "url": "rediss://cache:6380"
})
)]
#[case::health_check_interval_is_whole_seconds(
    r#"{"health_check_interval": "7", "host": "redis"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": 7.0,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null,
            "unix_socket_path": null
        })
)]
#[case::health_check_interval_zero_is_off(
    r#"{"health_check_interval": 0, "host": "redis"}"#,
    &[],
    serde_json::json!({
            "auth": {
                "kind": "static",
                "password": null,
                "username": null
            },
            "db": 0,
            "health_check_interval": null,
            "host": "redis",
            "mode": "host",
            "port": 6379,
            "socket_connect_timeout": null,
            "socket_timeout": 5.0,
            "tls": null,
            "unix_socket_path": null
        })
)]
fn resolves_like_litellm_redis_py(
    #[case] kwargs: &str,
    #[case] environment: &[(&str, &str)],
    #[case] expected: serde_json::Value,
) {
    let resolved = resolve(kwargs, environment).unwrap();

    assert_eq!(view(&resolved), expected);
}

#[rstest]
#[case::aws_iam_without_tls_fails(r#"{"aws_iam_auth": true, "aws_iam_cache_name": "cache-1", "aws_iam_region": "us-east-1", "aws_iam_user_name": "iam-user", "host": "cache-1"}"#, &[])]
#[case::aws_iam_without_a_region_fails(r#"{"aws_iam_auth": true, "aws_iam_cache_name": "cache-1", "aws_iam_user_name": "iam-user", "host": "cache-1", "ssl": true}"#, &[])]
#[case::no_target_fails(r#"{"port": 6379}"#, &[])]
#[case::a_host_breaks_sentinel(r#"{"host": "ignored", "sentinel_nodes": [["sentinel-a", 26379]], "service_name": "primary"}"#, &[])]
#[case::a_cluster_rejects_a_nonzero_db(r#"{"startup_nodes": [{"host": "node-a", "port": 7000}], "db": 3}"#, &[])]
#[case::unix_socket_path_without_a_host_fails_like_python(r#"{"unix_socket_path": "/tmp/redis.sock"}"#, &[])]
fn fails_like_litellm_redis_py(#[case] kwargs: &str, #[case] environment: &[(&str, &str)]) {
    assert!(resolve(kwargs, environment).is_err());
}
