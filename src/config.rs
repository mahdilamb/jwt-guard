use std::env;
use std::time::Duration;

use serde::Deserialize;

use crate::errors::config::ConfigError;

const ENV_PREFIX: &str = "JWT_GUARD_";

#[derive(Debug, Clone)]
pub struct AuthScheme {
    pub issuer: String,
    pub jwks_uri: String,
    pub audiences: Option<Vec<String>>,
}

/// Ordered list of (name, scheme) pairs. Order matches `JWT_GUARD_AUTH_SCHEMES`.
pub type Schemes = Vec<(String, AuthScheme)>;

#[derive(Deserialize)]
struct OpenIdConfig {
    issuer: String,
    jwks_uri: String,
}

/// Raw parsed env vars before OpenID discovery.
struct RawScheme {
    issuer: Option<String>,
    jwks_uri: Option<String>,
    audiences: Vec<String>,
}

fn env_var(key: &str) -> Option<String> {
    env::var(format!("{ENV_PREFIX}{key}")).ok()
}

fn env_required(key: &str) -> Result<String, ConfigError> {
    let full_key = format!("{ENV_PREFIX}{key}");
    env::var(&full_key).map_err(|_| ConfigError::MissingEnvVar(full_key))
}

fn parse_env_schemes() -> Result<Vec<(String, RawScheme)>, ConfigError> {
    let names_raw = env_required("AUTH_SCHEMES")?;
    let names: Vec<String> = names_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut schemes = Vec::new();
    for name in names {
        let issuer = env_var(&format!("{name}_ISSUER"));
        let jwks_uri = env_var(&format!("{name}_JWKS_URI"));

        let mut audiences = Vec::new();
        if let Some(aud) = env_var(&format!("{name}_AUDIENCE")) {
            audiences.push(aud);
        }
        if let Some(auds) = env_var(&format!("{name}_AUDIENCES")) {
            audiences.extend(auds.split(',').map(|s| s.trim().to_string()));
        }

        schemes.push((
            name.to_lowercase(),
            RawScheme {
                issuer,
                jwks_uri,
                audiences,
            },
        ));
    }
    Ok(schemes)
}

async fn fetch_openid_config(base_url: &str) -> Result<OpenIdConfig, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        base_url.trim_end_matches('/')
    );
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("failed to fetch {url}: {e}"))?;
    resp.json::<OpenIdConfig>()
        .await
        .map_err(|e| format!("failed to parse {url}: {e}"))
}

pub async fn auth_schemes() -> Result<Schemes, ConfigError> {
    let raw = parse_env_schemes()?;
    let mut schemes = Vec::new();

    for (name, raw_scheme) in &raw {
        let discovery = match &raw_scheme.issuer {
            Some(iss) => Some(fetch_openid_config(iss).await),
            None => None,
        };

        let (issuer, jwks_uri) = match (&discovery, &raw_scheme.jwks_uri) {
            (Some(Ok(config)), jwks_override) => {
                if let Some(env_iss) = &raw_scheme.issuer
                    && &config.issuer != env_iss
                {
                    return Err(ConfigError::IssuerMismatch {
                        scheme: name.clone(),
                        expected: env_iss.clone(),
                        actual: config.issuer.clone(),
                    });
                }
                let jwks_uri = jwks_override
                    .clone()
                    .unwrap_or_else(|| config.jwks_uri.clone());
                (config.issuer.clone(), jwks_uri)
            }
            (Some(Err(e)), Some(jwks_uri)) => {
                eprintln!("Warning: well-known discovery failed for \"{name}\": {e}");
                let issuer = raw_scheme.issuer.clone().unwrap_or_default();
                (issuer, jwks_uri.clone())
            }
            (None, Some(jwks_uri)) => (String::new(), jwks_uri.clone()),
            (Some(Err(e)), None) => {
                return Err(ConfigError::DiscoveryFailed {
                    scheme: name.clone(),
                    reason: e.clone(),
                });
            }
            (None, None) => {
                return Err(ConfigError::NoSchemeSource {
                    scheme: name.clone(),
                });
            }
        };

        println!("Auth scheme \"{name}\": issuer={issuer}, jwks_uri={jwks_uri}");
        schemes.push((
            name.clone(),
            AuthScheme {
                issuer,
                jwks_uri,
                audiences: if raw_scheme.audiences.is_empty() {
                    None
                } else {
                    Some(raw_scheme.audiences.clone())
                },
            },
        ));
    }

    Ok(schemes)
}

pub fn target_url() -> Result<String, ConfigError> {
    env_required("TARGET_URL")
}

pub fn forward_payload() -> bool {
    env_var("FORWARD_PAYLOAD")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

pub fn forward_scheme() -> bool {
    env_var("FORWARD_SCHEME")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn forward_authorization() -> bool {
    env_var("FORWARD_AUTHORIZATION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn port() -> Result<u16, ConfigError> {
    let raw = env::var("PORT").unwrap_or_else(|_| "8000".to_string());
    raw.parse().map_err(|_| ConfigError::InvalidEnvVar {
        key: "PORT".to_string(),
        reason: "must be a valid u16".to_string(),
    })
}

/// Parse `JWT_GUARD_JWKS_REFRESH` as a number of seconds.
/// Defaults to 900 (15 minutes) if unset.
pub fn jwks_refresh() -> Result<Duration, ConfigError> {
    let secs: u64 = match env_var("JWKS_REFRESH") {
        Some(v) => v.parse().map_err(|_| ConfigError::InvalidEnvVar {
            key: format!("{ENV_PREFIX}JWKS_REFRESH"),
            reason: "must be a number of seconds".to_string(),
        })?,
        None => 900,
    };
    Ok(Duration::from_secs(secs))
}

pub fn logging_format() -> Result<String, ConfigError> {
    match env_var("LOGGING_FORMAT") {
        Some(v) => match v.to_lowercase().as_str() {
            "text" | "google_cloud" => Ok(v.to_lowercase()),
            _ => Err(ConfigError::InvalidEnvVar {
                key: format!("{ENV_PREFIX}LOGGING_FORMAT"),
                reason: "must be \"text\" or \"google_cloud\"".to_string(),
            }),
        },
        None => Ok("text".to_string()),
    }
}

/// Parse `JWT_GUARD_UPSTREAM_TIMEOUT` as a number of seconds.
/// Defaults to 30 seconds if unset.
pub fn upstream_timeout() -> Result<Duration, ConfigError> {
    let secs: u64 = match env_var("UPSTREAM_TIMEOUT") {
        Some(v) => v.parse().map_err(|_| ConfigError::InvalidEnvVar {
            key: format!("{ENV_PREFIX}UPSTREAM_TIMEOUT"),
            reason: "must be a number of seconds".to_string(),
        })?,
        None => 30,
    };
    Ok(Duration::from_secs(secs))
}
