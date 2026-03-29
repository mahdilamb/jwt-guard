use hyper::Request;
use hyper::body::Incoming;
use jsonwebtoken::{decode, decode_header};
use serde_json::Value;

use crate::config::Schemes;
use crate::errors::jwt::JwtError;
use crate::jwks;

fn extract_bearer(req: &Request<Incoming>) -> Result<&str, JwtError> {
    let auth = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .ok_or(JwtError::MissingAuthorizationHeader)?;
    let auth_str = auth
        .to_str()
        .map_err(|_| JwtError::InvalidAuthorizationHeader)?;
    let (scheme, token) = auth_str
        .split_once(' ')
        .ok_or(JwtError::MissingBearerPrefix)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(JwtError::MissingBearerPrefix);
    }
    Ok(token)
}

/// Quick structural check: a JWT must be exactly `header.payload.signature`.
#[inline]
fn is_jwt_shaped(token: &str) -> bool {
    let mut dots = 0;
    for b in token.bytes() {
        if b == b'.' {
            dots += 1;
            if dots > 2 {
                return false;
            }
        }
    }
    dots == 2
}

fn try_verify<'a>(
    token: &'a str,
    prepared: &jwks::PreparedScheme,
    header: &jsonwebtoken::Header,
) -> Result<&'a str, JwtError> {
    let matching_keys: Vec<&jwks::PreparedKey> = match &header.kid {
        Some(kid) => prepared
            .keys
            .iter()
            .filter(|k| k.kid.as_deref() == Some(kid.as_str()))
            .collect(),
        None => prepared.keys.iter().collect(),
    };

    if matching_keys.is_empty() {
        return Err(JwtError::InvalidJwtSignature);
    }

    for key in matching_keys {
        let mut validation = prepared.validation.clone();
        validation.algorithms = vec![header.alg];

        if decode::<Value>(token, &key.decoding_key, &validation).is_ok() {
            let payload = token.split('.').nth(1).unwrap();
            return Ok(payload);
        }
    }

    Err(JwtError::InvalidJwtSignature)
}

pub fn verify<'a>(
    req: &'a Request<Incoming>,
    schemes: &'a Schemes,
    cache: &jwks::CacheInner,
) -> Result<(&'a str, &'a str), JwtError> {
    let token = extract_bearer(req)?;
    verify_token(token, schemes, cache)
}

pub fn verify_token<'a>(
    token: &'a str,
    schemes: &'a Schemes,
    cache: &jwks::CacheInner,
) -> Result<(&'a str, &'a str), JwtError> {
    if !is_jwt_shaped(token) {
        return Err(JwtError::InvalidJwtPayload);
    }

    let header = decode_header(token).map_err(|_| JwtError::InvalidJwtPayload)?;

    if let Some(ref kid) = header.kid {
        let any_scheme_has_kid = schemes.iter().any(|(name, _)| {
            cache
                .get(name)
                .is_some_and(|p| p.keys.iter().any(|k| k.kid.as_deref() == Some(kid)))
        });
        if !any_scheme_has_kid {
            return Err(JwtError::InvalidJwtSignature);
        }
    }

    for (name, _scheme) in schemes {
        if let Some(prepared) = cache.get(name)
            && let Ok(payload) = try_verify(token, prepared, &header)
        {
            return Ok((name, payload));
        }
    }

    Err(JwtError::InvalidJwtSignature)
}
