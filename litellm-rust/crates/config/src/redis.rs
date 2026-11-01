use std::{collections::BTreeMap, time::Duration};

use litellm_core_utils::settings::Lookup;
use litellm_redis_types::{
    ClusterEndpoint, ClusterNode as RedisNode, Endpoint, HostEndpoint, SentinelEndpoint,
};
use litellm_router_types::Spelled;
use litellm_secret_value::SecretValue;
use serde::{Deserialize, Deserializer, de::Error as _};
use veil::Redact;

use crate::{AdditionalFields, Object, Value};

mod auth;
mod error;
mod keys;
mod secrets;
mod sentinel;
mod tls;

use keys::Handling;

pub use auth::{AwsIamAuth, AzureAdAuth, RedisAuth};
pub use error::{Expected, RedisError};
pub use secrets::SecretSnapshot;

const SUPPORTED: &[&str] = &[
    "url",
    "host",
    "port",
    "username",
    "password",
    "ssl",
    "db",
    "socket_timeout",
    "startup_nodes",
    "namespace",
];

const CACHE_ONLY: &[&str] = &[
    "type",
    "mode",
    "ttl",
    "default_in_memory_ttl",
    "default_in_redis_ttl",
    "supported_call_types",
    "similarity_threshold",
    "max_messages",
    "_backend",
];

#[derive(Clone, Default, Redact)]
pub struct RedisSettings {
    pub url: Option<SecretValue>,
    pub host: Option<Spelled<String>>,
    pub port: Option<Spelled<u16>>,
    pub username: Option<SecretValue>,
    pub password: Option<SecretValue>,
    pub ssl: Option<Spelled<bool>>,
    pub db: Option<Spelled<i64>>,
    pub socket_timeout: Option<Spelled<f64>>,
    pub startup_nodes: Option<Value>,
    pub namespace: Option<Spelled<String>>,
    #[redact(with = "[REDACTED]")]
    pub additional_fields: AdditionalFields,
    #[redact(with = "[REDACTED]")]
    unparsed: DeferredInputs,
}

impl<'de> Deserialize<'de> for RedisSettings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields = BTreeMap::<String, Value>::deserialize(deserializer)?;
        let scalar = |key: &str| fields.get(key).and_then(as_text);
        Ok(Self {
            url: scalar("url").map(SecretValue::new),
            host: scalar("host").map(Spelled::Value),
            port: spelled(scalar("port")),
            username: scalar("username").map(SecretValue::new),
            password: scalar("password").map(SecretValue::new),
            ssl: spelled(scalar("ssl")),
            db: spelled(scalar("db")),
            socket_timeout: spelled(scalar("socket_timeout")),
            startup_nodes: fields
                .get("startup_nodes")
                .filter(|value| !value.is_null())
                .cloned(),
            namespace: scalar("namespace").map(Spelled::Value),
            additional_fields: cloned(&fields, |key, _| !SUPPORTED.contains(&key)),
            unparsed: deferred_inputs(&fields),
        })
    }
}

#[derive(Clone, Debug)]
pub enum CacheSettings {
    Redis(Box<RedisSettings>),
    Other(Object),
}

impl<'de> Deserialize<'de> for CacheSettings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields = BTreeMap::<String, Value>::deserialize(deserializer)?;
        let is_redis = matches!(fields.get("type"), Some(Value::String(kind)) if kind == "redis");
        if !is_redis {
            return Ok(Self::Other(Object::from_fields(fields)));
        }
        let mapping = fields
            .into_iter()
            .map(|(key, value)| (Value::String(key), value))
            .collect();
        serde_yaml_ng::from_value(Value::Mapping(mapping))
            .map(|settings| Self::Redis(Box::new(settings)))
            .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedRedis {
    pub endpoint: Endpoint,
    pub auth: RedisAuth,
    pub namespace: Option<String>,
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    /// redis-py's `health_check_interval`, which `_coerce_redis_kwargs_types` reads as an `int`
    pub health_check_interval: Option<Duration>,
}

#[derive(Clone)]
struct Entry {
    value: Value,
    source: String,
}

type Kwargs = BTreeMap<String, Entry>;

impl RedisSettings {
    pub fn resolve(
        &self,
        secrets: &SecretSnapshot,
        environment: &dyn Lookup,
    ) -> Result<ResolvedRedis, RedisError> {
        self.resolve_with(secrets, environment, false)
    }

    pub fn resolve_cache(
        &self,
        secrets: &SecretSnapshot,
        environment: &dyn Lookup,
    ) -> Result<ResolvedRedis, RedisError> {
        self.resolve_with(secrets, environment, true)
    }

    fn resolve_with(
        &self,
        secrets: &SecretSnapshot,
        environment: &dyn Lookup,
        cache: bool,
    ) -> Result<ResolvedRedis, RedisError> {
        let lookup: &dyn Lookup = secrets;
        let block = self.kwargs(cache);
        let block: Kwargs = block
            .into_iter()
            .filter_map(|(key, entry)| {
                let value = environment_reference(&entry.value, lookup);
                (!value.is_null() || keeps_explicit_none(cache, &key))
                    .then(|| (key, Entry { value, ..entry }))
            })
            .collect();
        let environment_kwargs = environment_kwargs(lookup);
        let names_a_target = ["host", "startup_nodes", "sentinel_nodes"]
            .iter()
            .any(|key| is_set(&block, key));
        let drop_environment_url = names_a_target && !is_set(&block, "url");
        let merged: Kwargs = environment_kwargs
            .into_iter()
            .filter(|(key, _)| !(key == "url" && drop_environment_url))
            .chain(block)
            .collect();
        warn_ignored(&merged);

        let startup_nodes = match configured(&merged, "startup_nodes") {
            Some(entry) => Some(
                cluster_nodes(&entry.value)
                    .ok_or_else(|| invalid(&entry.source, Expected::StartupNodes))?,
            ),
            None => keys::fallback("startup_nodes", lookup)
                .map(|(source, nodes)| {
                    cluster_nodes(&Value::String(nodes))
                        .ok_or_else(|| invalid(source, Expected::StartupNodes))
                })
                .transpose()?,
        }
        .filter(|nodes| !nodes.is_empty());
        let url = text_value(&merged, "url");
        let ssl = bool_value(&merged, "ssl");
        let uses_tls = match (&startup_nodes, &url) {
            (Some(_), _) | (None, None) => ssl,
            (None, Some(url)) => url
                .split_once("://")
                .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("rediss")),
        };
        let auth = auth::redis_auth(&merged, lookup, environment, uses_tls)?;
        let gcp_ca_certs = match &auth {
            RedisAuth::GcpIam { .. } if ssl => {
                text_or_fallback(&merged, "gcp_ssl_ca_certs", lookup)
                    .filter(|path| !path.is_empty())
            }
            _ => None,
        };
        let tls = || {
            ssl.then(|| tls::tls_options(&merged, gcp_ca_certs.clone()))
                .transpose()
        };
        let db = || integer(&merged, "db").map(|db| db.unwrap_or(0));
        let endpoint = match (startup_nodes, url) {
            (Some(nodes), _) => {
                reject_cluster_db(&merged)?;
                Endpoint::Cluster(ClusterEndpoint { nodes, tls: tls()? })
            }
            (None, Some(url)) => Endpoint::Url {
                tls: tls::url_tls(&url)?,
                url: SecretValue::new(match &auth {
                    RedisAuth::Static { .. } => url,
                    _ => without_userinfo(&url),
                }),
            },
            (None, None) => match sentinel::sentinel_target(&merged, lookup)? {
                Some(target) => {
                    reject_sentinel_host(&merged)?;
                    Endpoint::Sentinel(SentinelEndpoint {
                        sentinels: target.sentinels,
                        service_name: target.service_name,
                        sentinel_password: target.sentinel_password,
                        tls: tls()?,
                        db: db()?,
                    })
                }
                None => Endpoint::Host(HostEndpoint {
                    host: text_value(&merged, "host").ok_or(RedisError::NoTarget)?,
                    port: integer(&merged, "port")?.unwrap_or(6379),
                    tls: tls()?,
                    db: db()?,
                    unix_socket_path: text_value(&merged, "unix_socket_path").map(Into::into),
                }),
            },
        };
        let auth = match (&endpoint, auth) {
            (Endpoint::Url { .. }, RedisAuth::Static { username, .. }) => RedisAuth::Static {
                username,
                password: None,
            },
            (_, auth) => auth,
        };
        Ok(ResolvedRedis {
            endpoint,
            auth,
            namespace: text_value(&merged, "namespace"),
            timeout: seconds(&merged, "socket_timeout")?,
            connect_timeout: seconds(&merged, "socket_connect_timeout")?,
            health_check_interval: integer::<i64>(&merged, "health_check_interval")?
                .filter(|seconds| *seconds > 0)
                .map(|seconds| Duration::from_secs(seconds.unsigned_abs())),
        })
    }

    // The proxy validates general_settings.coordination_redis through the CoordinationRedisParams pydantic model
    // before redis-py coerces anything, so a malformed port or ssl there fails boot instead of falling back
    pub fn validate_coordination(&self) -> Result<(), RedisError> {
        let pydantic_bool = |text: &str| {
            matches!(
                text.to_ascii_lowercase().as_str(),
                "0" | "off" | "f" | "false" | "n" | "no" | "1" | "on" | "t" | "true" | "y" | "yes"
            )
        };
        match (&self.port, &self.ssl) {
            (Some(Spelled::Text(_)), _) => Err(invalid("port", Expected::Integer)),
            (_, Some(Spelled::Text(text))) if !pydantic_bool(text) => {
                Err(invalid("ssl", Expected::Boolean))
            }
            _ => Ok(()),
        }
    }

    fn kwargs(&self, cache: bool) -> Kwargs {
        let known = [
            (
                "url",
                self.url.as_ref().map(|value| value.expose().to_owned()),
            ),
            ("host", spelled_text(self.host.as_ref())),
            ("port", spelled_text(self.port.as_ref())),
            (
                "username",
                self.username
                    .as_ref()
                    .map(|value| value.expose().to_owned()),
            ),
            (
                "password",
                self.password
                    .as_ref()
                    .map(|value| value.expose().to_owned()),
            ),
            ("ssl", spelled_text(self.ssl.as_ref())),
            ("db", spelled_text(self.db.as_ref())),
            ("socket_timeout", spelled_text(self.socket_timeout.as_ref())),
            ("namespace", spelled_text(self.namespace.as_ref())),
        ];
        let known = known.into_iter().filter_map(|(key, value)| {
            value.map(|value| {
                (
                    key.to_owned(),
                    Entry {
                        value: Value::String(value),
                        source: key.to_owned(),
                    },
                )
            })
        });
        let startup_nodes = self.startup_nodes.clone().map(|value| {
            (
                "startup_nodes".to_owned(),
                Entry {
                    value,
                    source: "startup_nodes".to_owned(),
                },
            )
        });
        let extras = self.additional_fields.iter().filter_map(|(key, value)| {
            if cache && CACHE_ONLY.contains(&key.as_str()) {
                return None;
            }
            let key = match (cache, key.as_str()) {
                (true, "redis_startup_nodes") => "startup_nodes".to_owned(),
                _ => key.clone(),
            };
            Some((
                key.clone(),
                Entry {
                    value: value.clone(),
                    source: key,
                },
            ))
        });
        let unparsed = self.unparsed.iter().map(|(key, value)| {
            (
                key.clone(),
                Entry {
                    value: value.0.clone(),
                    source: key.clone(),
                },
            )
        });
        extras
            .chain(unparsed)
            .chain(known)
            .chain(startup_nodes)
            .collect()
    }
}

// _get_redis_url_kwargs keeps only plain Connection kwargs, so redis-py drops every ssl_* setting for a url
// and a credential provider replaces the url's userinfo, which _url_without_userinfo strips
fn without_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{scheme}://{host}{tail}")
}

pub fn environment_has_target(lookup: &dyn Lookup) -> bool {
    [
        "REDIS_HOST",
        "REDIS_URL",
        "REDIS_CLUSTER_NODES",
        "REDIS_SENTINEL_NODES",
    ]
    .iter()
    .any(|name| lookup.get(name).is_some())
}

fn invalid(setting: &str, expected: Expected) -> RedisError {
    RedisError::Invalid {
        setting: setting.to_owned(),
        expected,
    }
}

fn parsed<T>(
    kwargs: &Kwargs,
    key: &str,
    expected: Expected,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Option<T>, RedisError> {
    kwargs
        .get(key)
        .and_then(|entry| Some((as_text(&entry.value)?, &entry.source)))
        .map(|(text, source)| parse(&text).ok_or_else(|| invalid(source, expected)))
        .transpose()
}

pub fn parse_seconds(text: &str) -> Option<Duration> {
    text.parse::<f64>()
        .ok()
        .and_then(|seconds| Duration::try_from_secs_f64(seconds).ok())
}

fn seconds(merged: &Kwargs, key: &str) -> Result<Option<Duration>, RedisError> {
    coerced::<f64, _>(merged, key, Expected::Seconds, |seconds| {
        Duration::try_from_secs_f64(seconds).ok()
    })
}

// _coerce_redis_kwargs_types drops a value int() or float() cannot parse, so redis-py connects with its default
fn coerced<N: std::str::FromStr, T>(
    kwargs: &Kwargs,
    key: &str,
    expected: Expected,
    convert: impl Fn(N) -> Option<T>,
) -> Result<Option<T>, RedisError> {
    let Some((text, source)) = kwargs
        .get(key)
        .and_then(|entry| Some((as_text(&entry.value)?, &entry.source)))
    else {
        return Ok(None);
    };
    match text.parse::<N>() {
        Ok(number) => convert(number)
            .map(Some)
            .ok_or_else(|| invalid(source, expected)),
        Err(_) => {
            tracing::warn!(setting = %source, "Redis setting is not a number, so the default is used like redis-py");
            Ok(None)
        }
    }
}

fn warn_ignored(merged: &Kwargs) {
    for (key, entry) in merged {
        if keys::setting(key).is_some_and(|setting| setting.handling == Handling::Warn) {
            tracing::warn!(
                "Redis setting {} is not supported by the Rust client and is ignored: {}",
                entry.source,
                keys::consequence(key)
            );
        }
    }
}

fn environment_kwargs(lookup: &dyn Lookup) -> Kwargs {
    keys::SETTINGS
        .iter()
        .filter_map(|setting| {
            let source = setting.environment_name()?;
            let value = lookup.get(&source)?;
            Some((
                setting.kwarg.to_owned(),
                Entry {
                    value: Value::String(value),
                    source,
                },
            ))
        })
        .collect()
}

// load_config resolves os.environ/ to None when unset, so a missing reference is a null like any other
fn environment_reference(value: &Value, lookup: &dyn Lookup) -> Value {
    match value {
        Value::String(text) => match text.strip_prefix("os.environ/") {
            Some(name) => lookup.get(name).map_or(Value::Null, Value::String),
            None => value.clone(),
        },
        _ => value.clone(),
    }
}

// coordination_redis reaches redis-py through model_dump(exclude_none=True), so every null is dropped. Cache
// and RedisCache drop a null only for the parameters they name, and pass any other key on as an explicit None
// that overrides the REDIS_* environment value
fn keeps_explicit_none(cache: bool, key: &str) -> bool {
    const NAMED_BY_CACHE: &[&str] = &[
        "host",
        "port",
        "password",
        "socket_timeout",
        "startup_nodes",
        "namespace",
        "gcp_service_account",
        "gcp_ssl_ca_certs",
    ];
    cache && !NAMED_BY_CACHE.contains(&key)
}

// redis-py's RedisCluster raises unless db is 0 or None
fn reject_cluster_db(merged: &Kwargs) -> Result<(), RedisError> {
    let Some(entry) = merged.get("db").filter(|entry| !entry.value.is_null()) else {
        return Ok(());
    };
    match integer::<i64>(merged, "db") {
        Ok(None | Some(0)) => Ok(()),
        _ => Err(RedisError::DbInCluster {
            setting: entry.source.clone(),
        }),
    }
}

// redis.asyncio.Sentinel passes the connection kwargs to each monitor's Redis(host=..., port=...), so a host or
// port setting raises TypeError when litellm builds the client
fn reject_sentinel_host(merged: &Kwargs) -> Result<(), RedisError> {
    match ["host", "port"]
        .iter()
        .find_map(|key| merged.get(*key).filter(|entry| !entry.value.is_null()))
    {
        Some(entry) => Err(RedisError::SentinelWithHost {
            setting: entry.source.clone(),
        }),
        None => Ok(()),
    }
}

fn is_set(kwargs: &Kwargs, key: &str) -> bool {
    kwargs.get(key).is_some_and(|entry| !entry.value.is_null())
}

// Python chains these settings with `or`, so a falsy configured value ("", [], 0, False) falls through too
fn configured<'a>(kwargs: &'a Kwargs, key: &str) -> Option<&'a Entry> {
    kwargs.get(key).filter(|entry| truthy(&entry.value))
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Sequence(items) => !items.is_empty(),
        Value::Mapping(entries) => !entries.is_empty(),
        Value::Tagged(_) => true,
    }
}

fn text_or_fallback(kwargs: &Kwargs, key: &str, lookup: &dyn Lookup) -> Option<String> {
    configured(kwargs, key)
        .and_then(|entry| as_text(&entry.value))
        .or_else(|| keys::fallback_value(key, lookup))
}

fn as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn text_value(kwargs: &Kwargs, key: &str) -> Option<String> {
    kwargs.get(key).and_then(|entry| as_text(&entry.value))
}

fn secret_value(kwargs: &Kwargs, key: &str) -> Option<SecretValue> {
    text_value(kwargs, key).map(SecretValue::new)
}

fn bool_value(kwargs: &Kwargs, key: &str) -> bool {
    match kwargs.get(key).map(|entry| &entry.value) {
        Some(Value::Bool(flag)) => *flag,
        Some(value) => as_text(value)
            .is_some_and(|text| matches!(text.to_ascii_lowercase().as_str(), "true" | "1" | "yes")),
        None => false,
    }
}

fn integer<T: TryFrom<i64>>(kwargs: &Kwargs, key: &str) -> Result<Option<T>, RedisError> {
    coerced::<i64, _>(kwargs, key, Expected::Integer, |number| {
        T::try_from(number).ok()
    })
}

fn cluster_nodes(value: &Value) -> Option<Vec<RedisNode>> {
    match value {
        Value::String(json) => {
            let nodes: Vec<serde_json::Map<String, serde_json::Value>> =
                serde_json::from_str(json).ok()?;
            nodes
                .iter()
                .map(|node| {
                    cluster_node(
                        node.get("host").and_then(json_text),
                        node.get("port").and_then(json_text),
                    )
                })
                .collect()
        }
        Value::Sequence(nodes) => nodes
            .iter()
            .map(|node| {
                cluster_node(
                    node.get("host").and_then(as_text),
                    node.get("port").and_then(as_text),
                )
            })
            .collect(),
        _ => None,
    }
}

fn cluster_node(host: Option<String>, port: Option<String>) -> Option<RedisNode> {
    Some(RedisNode {
        host: host?,
        port: port?.parse().ok()?,
    })
}

fn json_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn spelled_text<T: ToString>(value: Option<&Spelled<T>>) -> Option<String> {
    value.map(|value| match value {
        Spelled::Value(value) => value.to_string(),
        Spelled::Text(value) => value.clone(),
    })
}

fn spelled<T: std::str::FromStr>(text: Option<String>) -> Option<Spelled<T>> {
    text.map(|text| match text.parse() {
        Ok(value) => Spelled::Value(value),
        Err(_) => Spelled::Text(text),
    })
}

fn cloned(
    fields: &BTreeMap<String, Value>,
    keep: impl Fn(&str, &Value) -> bool,
) -> AdditionalFields {
    fields
        .iter()
        .filter(|(key, value)| keep(key, value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[derive(Clone, Debug)]
struct DeferredInput(Value);

type DeferredInputs = BTreeMap<String, DeferredInput>;

fn deferred_inputs(fields: &BTreeMap<String, Value>) -> DeferredInputs {
    fields
        .iter()
        .filter(|(key, value)| is_unparsed(key, value))
        .map(|(key, value)| (key.clone(), DeferredInput(value.clone())))
        .collect()
}

fn is_unparsed(key: &str, value: &Value) -> bool {
    SUPPORTED.contains(&key)
        && match key {
            "startup_nodes" => value.is_null(),
            _ => as_text(value).is_none(),
        }
}
