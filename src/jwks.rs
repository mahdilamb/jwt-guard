use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{DecodingKey, Validation};

use crate::config::{AuthScheme, Schemes};
use crate::errors::jwt::JwtError;

#[derive(Clone)]
pub struct PreparedKey {
    pub decoding_key: DecodingKey,
    pub algorithm: jsonwebtoken::Algorithm,
    pub kid: Option<String>,
}

#[derive(Clone)]
pub struct PreparedScheme {
    pub keys: Vec<PreparedKey>,
    pub validation: Validation,
}

/// The full cache: scheme name → prepared keys + validation.
pub type CacheInner = HashMap<String, PreparedScheme>;
pub type Cache = Arc<ArcSwap<CacheInner>>;

fn prepare_scheme(jwks: &JwkSet, scheme: &AuthScheme) -> PreparedScheme {
    let mut keys = Vec::new();
    for jwk in &jwks.keys {
        if let Ok(decoding_key) = DecodingKey::from_jwk(jwk) {
            let algorithm = jwk
                .common
                .key_algorithm
                .and_then(|a| a.to_string().parse().ok())
                .unwrap_or(jsonwebtoken::Algorithm::RS256);
            let kid = jwk.common.key_id.clone();
            keys.push(PreparedKey {
                decoding_key,
                algorithm,
                kid,
            });
        }
    }

    let mut validation = Validation::default();
    validation.validate_nbf = true;
    if !scheme.issuer.is_empty() {
        validation.set_issuer(&[&scheme.issuer]);
    }
    match &scheme.audiences {
        Some(audiences) => validation.set_audience(audiences),
        None => validation.validate_aud = false,
    }

    PreparedScheme { keys, validation }
}

async fn fetch_jwks(uri: &str) -> Result<JwkSet, JwtError> {
    let resp = reqwest::get(uri)
        .await
        .map_err(|e| JwtError::JwksFetchError(e.to_string()))?;
    resp.json::<JwkSet>()
        .await
        .map_err(|e| JwtError::JwksFetchError(e.to_string()))
}

pub async fn init_cache(schemes: &Schemes) -> Cache {
    let mut map = HashMap::new();
    for (name, scheme) in schemes {
        match fetch_jwks(&scheme.jwks_uri).await {
            Ok(jwks) => {
                println!("Fetched JWKS for \"{name}\"");
                map.insert(name.clone(), prepare_scheme(&jwks, scheme));
            }
            Err(e) => eprintln!("Failed to fetch JWKS for \"{name}\": {}", e),
        }
    }
    Arc::new(ArcSwap::from_pointee(map))
}

pub fn spawn_refresh(cache: Cache, schemes: Arc<Schemes>, refresh_interval: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(refresh_interval);
        interval.tick().await;
        loop {
            interval.tick().await;
            let previous = cache.load();
            let mut map = HashMap::new();
            for (name, scheme) in schemes.iter() {
                match fetch_jwks(&scheme.jwks_uri).await {
                    Ok(jwks) => {
                        map.insert(name.clone(), prepare_scheme(&jwks, scheme));
                        println!("Refreshed JWKS for \"{name}\"");
                    }
                    Err(e) => {
                        eprintln!("Failed to refresh JWKS for \"{name}\": {}", e);
                        if let Some(existing) = previous.get(name) {
                            map.insert(name.clone(), existing.clone());
                        }
                    }
                }
            }
            cache.store(Arc::new(map));
        }
    });
}
