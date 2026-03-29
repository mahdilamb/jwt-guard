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
#[derive(Debug)]
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

        let single_aud = env_var(&format!("{name}_AUDIENCE"));
        let multi_aud = env_var(&format!("{name}_AUDIENCES"));
        if single_aud.is_some() && multi_aud.is_some() {
            return Err(ConfigError::InvalidEnvVar {
                key: format!("{ENV_PREFIX}{name}_AUDIENCE / {ENV_PREFIX}{name}_AUDIENCES"),
                reason: "set one or the other, not both".to_string(),
            });
        }
        let mut audiences = Vec::new();
        if let Some(aud) = single_aud {
            audiences.push(aud);
        }
        if let Some(auds) = multi_aud {
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

/// Parse a forwarding variable that can be a boolean or a custom header name starting with `x-`.
fn parse_forward(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    match lower.as_str() {
        "0" | "false" => None,
        "1" | "true" => Some(String::new()), // empty = use default header
        _ if lower.starts_with("x-") => Some(lower),
        _ => None,
    }
}

pub fn forward_payload() -> Option<String> {
    env_var("FORWARD_PAYLOAD")
        .and_then(|v| parse_forward(&v))
        .or(Some(String::new())) // default: enabled with default header
        .map(|s| {
            if s.is_empty() {
                "x-jwt-payload".to_string()
            } else {
                s
            }
        })
}

pub fn forward_scheme() -> Option<String> {
    env_var("FORWARD_SCHEME")
        .and_then(|v| parse_forward(&v))
        .map(|s| {
            if s.is_empty() {
                "x-jwt-scheme".to_string()
            } else {
                s
            }
        })
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
            "none" | "text" | "google_cloud" => Ok(v.to_lowercase()),
            _ => Err(ConfigError::InvalidEnvVar {
                key: format!("{ENV_PREFIX}LOGGING_FORMAT"),
                reason: "must be \"none\", \"text\", or \"google_cloud\"".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env var tests must run serially to avoid cross-contamination.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn set_env(key: &str, val: &str) {
        unsafe { std::env::set_var(key, val) };
    }

    unsafe fn remove_env(key: &str) {
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn audience_and_audiences_both_set_is_error() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            set_env("JWT_GUARD_AUTH_SCHEMES", "TEST");
            set_env("JWT_GUARD_TEST_JWKS_URI", "http://localhost/jwks");
            set_env("JWT_GUARD_TEST_AUDIENCE", "app1");
            set_env("JWT_GUARD_TEST_AUDIENCES", "app2,app3");
        }

        let result = parse_env_schemes();
        assert!(
            result.is_err(),
            "should reject when both AUDIENCE and AUDIENCES are set"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("AUDIENCE"),
            "error should mention AUDIENCE: {err}"
        );

        unsafe {
            remove_env("JWT_GUARD_AUTH_SCHEMES");
            remove_env("JWT_GUARD_TEST_JWKS_URI");
            remove_env("JWT_GUARD_TEST_AUDIENCE");
            remove_env("JWT_GUARD_TEST_AUDIENCES");
        }
    }

    #[test]
    fn audience_alone_is_ok() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            set_env("JWT_GUARD_AUTH_SCHEMES", "TEST");
            set_env("JWT_GUARD_TEST_JWKS_URI", "http://localhost/jwks");
            set_env("JWT_GUARD_TEST_AUDIENCE", "app1");
            remove_env("JWT_GUARD_TEST_AUDIENCES");
        }

        let result = parse_env_schemes();
        assert!(result.is_ok());
        let schemes = result.unwrap();
        assert_eq!(schemes[0].1.audiences, vec!["app1"]);

        unsafe {
            remove_env("JWT_GUARD_AUTH_SCHEMES");
            remove_env("JWT_GUARD_TEST_JWKS_URI");
            remove_env("JWT_GUARD_TEST_AUDIENCE");
        }
    }

    #[test]
    fn audiences_alone_is_ok() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            set_env("JWT_GUARD_AUTH_SCHEMES", "TEST");
            set_env("JWT_GUARD_TEST_JWKS_URI", "http://localhost/jwks");
            remove_env("JWT_GUARD_TEST_AUDIENCE");
            set_env("JWT_GUARD_TEST_AUDIENCES", "app2,app3");
        }

        let result = parse_env_schemes();
        assert!(result.is_ok());
        let schemes = result.unwrap();
        assert_eq!(schemes[0].1.audiences, vec!["app2", "app3"]);

        unsafe {
            remove_env("JWT_GUARD_AUTH_SCHEMES");
            remove_env("JWT_GUARD_TEST_JWKS_URI");
            remove_env("JWT_GUARD_TEST_AUDIENCES");
        }
    }

    #[test]
    fn parse_forward_booleans() {
        assert_eq!(parse_forward("true"), Some(String::new()));
        assert_eq!(parse_forward("1"), Some(String::new()));
        assert_eq!(parse_forward("false"), None);
        assert_eq!(parse_forward("0"), None);
    }

    #[test]
    fn parse_forward_custom_header() {
        assert_eq!(
            parse_forward("x-custom-payload"),
            Some("x-custom-payload".to_string())
        );
        assert_eq!(
            parse_forward("X-My-Header"),
            Some("x-my-header".to_string())
        );
    }

    #[test]
    fn parse_forward_invalid_falls_back_to_none() {
        assert_eq!(parse_forward("yes"), None);
        assert_eq!(parse_forward("payload"), None);
    }
}
