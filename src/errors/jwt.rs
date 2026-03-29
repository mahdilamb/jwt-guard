use std::fmt;

use hyper::StatusCode;

#[derive(Debug)]
pub enum JwtError {
    MissingAuthorizationHeader,
    InvalidAuthorizationHeader,
    MissingBearerPrefix,
    InvalidJwtPayload,
    InvalidJwtSignature,
    JwksFetchError(String),
}

impl JwtError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingAuthorizationHeader
            | Self::InvalidAuthorizationHeader
            | Self::MissingBearerPrefix
            | Self::InvalidJwtPayload
            | Self::InvalidJwtSignature => StatusCode::UNAUTHORIZED,
            Self::JwksFetchError(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAuthorizationHeader => write!(f, "Missing Authorization header"),
            Self::InvalidAuthorizationHeader => write!(f, "Invalid Authorization header"),
            Self::MissingBearerPrefix => write!(f, "Missing Bearer prefix"),
            Self::InvalidJwtPayload => write!(f, "Invalid JWT payload"),
            Self::InvalidJwtSignature => write!(f, "Invalid JWT signature"),
            Self::JwksFetchError(e) => write!(f, "Failed to fetch JWKS: {e}"),
        }
    }
}

impl std::error::Error for JwtError {}
