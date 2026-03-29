use std::fmt;

#[derive(Debug)]
pub enum ConfigError {
    MissingEnvVar(String),
    InvalidEnvVar {
        key: String,
        reason: String,
    },
    DiscoveryFailed {
        scheme: String,
        reason: String,
    },
    IssuerMismatch {
        scheme: String,
        expected: String,
        actual: String,
    },
    NoSchemeSource {
        scheme: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvVar(key) => write!(f, "Missing required environment variable: {key}"),
            Self::InvalidEnvVar { key, reason } => {
                write!(f, "Invalid environment variable {key}: {reason}")
            }
            Self::DiscoveryFailed { scheme, reason } => {
                write!(f, "OpenID discovery failed for \"{scheme}\": {reason}")
            }
            Self::IssuerMismatch {
                scheme,
                expected,
                actual,
            } => write!(
                f,
                "Issuer mismatch for \"{scheme}\": env has \"{expected}\" but well-known reports \"{actual}\""
            ),
            Self::NoSchemeSource { scheme } => write!(
                f,
                "Cannot configure \"{scheme}\": either an issuer (for OpenID discovery) or a JWKS URI must be provided"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}
