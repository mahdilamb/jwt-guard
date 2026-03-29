//! JWT security test suite.
//!
//! Tests common JWT spoofing / attack vectors against the proxy.
//! A self-contained JWKS server (wiremock) + upstream echo server are spun up
//! per-test so every case is fully isolated.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Generate an RSA-2048 key-pair and return (private DER, JWK JSON) with the
/// given `kid`.
fn generate_rsa_keypair(kid: &str) -> (Vec<u8>, Value) {
    use rsa::RsaPrivateKey;
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let private_der = private_key.to_pkcs1_der().unwrap();
    let public_key = private_key.to_public_key();

    // Build JWK from the RSA public key components
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwk = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    });

    (private_der.to_bytes().to_vec(), jwk)
}

/// Create a valid RS256 JWT signed with the given DER private key.
fn make_jwt(private_der: &[u8], kid: &str, claims: &Value) -> String {
    let key = EncodingKey::from_rsa_der(private_der);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, claims, &key).unwrap()
}

/// Spin up a tiny HTTP echo server that returns 200 with the request path.
/// Returns the socket address it is listening on.
async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async {
                    let body = http_body_util::Full::new(hyper::body::Bytes::from("ok"));
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(body))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

struct TestHarness {
    proxy_addr: SocketAddr,
    private_der: Vec<u8>,
    kid: String,
    issuer: String,
}

/// Build a full test harness: JWKS mock, upstream echo, proxy server.
async fn setup(audience: Option<&str>) -> TestHarness {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let kid = "test-key-1";
    let issuer = "https://test-issuer.example.com";

    let (private_der, jwk) = generate_rsa_keypair(kid);
    let jwks = json!({ "keys": [jwk] });

    // JWKS mock server
    let jwks_server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
        .mount(&jwks_server)
        .await;

    // Upstream echo
    let upstream_addr = spawn_upstream().await;

    // Build config
    let schemes = vec![(
        "test".to_string(),
        jwt_guard::config::AuthScheme {
            issuer: issuer.to_string(),
            jwks_uri: jwks_server.uri(),
            audiences: audience.map(|a| vec![a.to_string()]),
        },
    )];

    // Populate JWKS cache using the library's init_cache
    let cache = jwt_guard::jwks::init_cache(&schemes).await;

    // Proxy server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let target = format!("http://{upstream_addr}");
    let schemes = Arc::new(schemes);
    let client = jwt_guard::proxy::build_client();

    let state = Arc::new(jwt_guard::proxy::AppState {
        client,
        target_url: target,
        schemes,
        jwks_cache: cache,
        forward_payload: true,
        forward_authorization: false,
        forward_scheme: true,
        upstream_timeout: std::time::Duration::from_secs(30),
        logging: jwt_guard::logging::LoggingFormat::None,
    });

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = Arc::clone(&state);
                    async move { jwt_guard::proxy::handle(&state, req).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    TestHarness {
        proxy_addr,
        private_der,
        kid: kid.to_string(),
        issuer: issuer.to_string(),
    }
}

fn valid_claims(issuer: &str) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({
        "iss": issuer,
        "sub": "user-123",
        "iat": now,
        "exp": now + 3600,
    })
}

async fn get(addr: SocketAddr, token: &str) -> (u16, String) {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/test"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    (status, body)
}

async fn get_no_auth(addr: SocketAddr) -> (u16, String) {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/test"))
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    (status, body)
}

// ── Valid baseline ───────────────────────────────────────────────────────────

#[tokio::test]
async fn valid_token_is_forwarded() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    let (status, body) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 200, "valid JWT should be proxied: {body}");
}

// ── Missing / malformed Authorization header ────────────────────────────────

#[tokio::test]
async fn missing_authorization_header() {
    let h = setup(None).await;
    let (status, _) = get_no_auth(h.proxy_addr).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn empty_authorization_header() {
    let h = setup(None).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/test", h.proxy_addr))
        .header("Authorization", "")
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn wrong_scheme_basic_auth() {
    let h = setup(None).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/test", h.proxy_addr))
        .header("Authorization", "Basic dXNlcjpwYXNz")
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ── Algorithm confusion attacks ─────────────────────────────────────────────

#[tokio::test]
async fn alg_none_attack() {
    let h = setup(None).await;
    // Manually craft a token with alg: "none" and no signature
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let claims = valid_claims(&h.issuer);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    let token = format!("{header}.{payload}.");
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "alg:none must be rejected");
}

#[tokio::test]
async fn alg_none_mixed_case_attack() {
    let h = setup(None).await;
    for alg in &["None", "NONE", "nOnE", "noNe"] {
        let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#));
        let claims = valid_claims(&h.issuer);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
        let token = format!("{header}.{payload}.");
        let (status, _) = get(h.proxy_addr, &token).await;
        assert_eq!(status, 401, "alg:{alg} must be rejected");
    }
}

#[tokio::test]
async fn alg_hs256_with_public_key_attack() {
    let h = setup(None).await;
    // Attempt to sign with HS256 using an arbitrary secret — the proxy should
    // reject because it only has RSA keys in JWKS.
    let key = EncodingKey::from_secret(b"some-fake-secret");
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(h.kid.clone());
    let token = encode(&header, &valid_claims(&h.issuer), &key).unwrap();
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "HS256 algorithm confusion must be rejected");
}

// ── Signature manipulation ──────────────────────────────────────────────────

#[tokio::test]
async fn stripped_signature() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    // Remove the signature (everything after the last dot)
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    let stripped = format!("{}.", parts[..2].join("."));
    let (status, _) = get(h.proxy_addr, &stripped).await;
    assert_eq!(status, 401, "stripped signature must be rejected");
}

#[tokio::test]
async fn empty_signature() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    let tampered = format!("{}.{}.", parts[0], parts[1]);
    let (status, _) = get(h.proxy_addr, &tampered).await;
    assert_eq!(status, 401, "empty signature must be rejected");
}

#[tokio::test]
async fn corrupted_signature() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    let mut parts: Vec<String> = token.splitn(3, '.').map(String::from).collect();
    // Flip some bytes in the signature
    let mut sig_bytes = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
    for b in sig_bytes.iter_mut().take(8) {
        *b ^= 0xFF;
    }
    parts[2] = URL_SAFE_NO_PAD.encode(&sig_bytes);
    let tampered = parts.join(".");
    let (status, _) = get(h.proxy_addr, &tampered).await;
    assert_eq!(status, 401, "corrupted signature must be rejected");
}

#[tokio::test]
async fn signature_from_different_key() {
    let h = setup(None).await;
    // Sign with a completely different RSA key
    let (other_der, _) = generate_rsa_keypair("other-key");
    let token = make_jwt(&other_der, &h.kid, &valid_claims(&h.issuer));
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "token signed with wrong key must be rejected");
}

// ── Payload tampering ───────────────────────────────────────────────────────

#[tokio::test]
async fn tampered_payload_claims() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    let mut parts: Vec<String> = token.splitn(3, '.').map(String::from).collect();
    // Decode payload, change sub, re-encode — signature no longer matches
    let payload_bytes = URL_SAFE_NO_PAD.decode(&parts[1]).unwrap();
    let mut claims: Value = serde_json::from_slice(&payload_bytes).unwrap();
    claims["sub"] = json!("admin");
    claims["role"] = json!("superuser");
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let tampered = parts.join(".");
    let (status, _) = get(h.proxy_addr, &tampered).await;
    assert_eq!(status, 401, "tampered payload must be rejected");
}

// ── Issuer attacks ──────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_issuer() {
    let h = setup(None).await;
    let mut claims = valid_claims(&h.issuer);
    claims["iss"] = json!("https://evil-issuer.example.com");
    let token = make_jwt(&h.private_der, &h.kid, &claims);
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "unknown issuer must be rejected");
}

#[tokio::test]
async fn missing_issuer_claim_with_valid_signature() {
    // With the "try all schemes in order" design, a token with a valid
    // signature but no iss claim will succeed against the first scheme
    // whose JWKS contains a matching key.
    let h = setup(None).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "sub": "user-123",
        "iat": now,
        "exp": now + 3600,
    });
    let token = make_jwt(&h.private_der, &h.kid, &claims);
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(
        status, 200,
        "valid signature should pass regardless of missing iss"
    );
}

// ── Expiration / time-based attacks ─────────────────────────────────────────

#[tokio::test]
async fn expired_token() {
    let h = setup(None).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "iss": h.issuer,
        "sub": "user-123",
        "iat": now - 7200,
        "exp": now - 3600, // expired 1 hour ago
    });
    let token = make_jwt(&h.private_der, &h.kid, &claims);
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "expired token must be rejected");
}

#[tokio::test]
async fn token_not_yet_valid_nbf() {
    let h = setup(None).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "iss": h.issuer,
        "sub": "user-123",
        "iat": now,
        "exp": now + 7200,
        "nbf": now + 3600, // not valid for another hour
    });
    let token = make_jwt(&h.private_der, &h.kid, &claims);
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "token with future nbf must be rejected");
}

// ── Audience validation ─────────────────────────────────────────────────────

#[tokio::test]
async fn wrong_audience() {
    let h = setup(Some("my-app")).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "iss": h.issuer,
        "sub": "user-123",
        "aud": "wrong-app",
        "iat": now,
        "exp": now + 3600,
    });
    let token = make_jwt(&h.private_der, &h.kid, &claims);
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "wrong audience must be rejected");
}

#[tokio::test]
async fn correct_audience_accepted() {
    let h = setup(Some("my-app")).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "iss": h.issuer,
        "sub": "user-123",
        "aud": "my-app",
        "iat": now,
        "exp": now + 3600,
    });
    let token = make_jwt(&h.private_der, &h.kid, &claims);
    let (status, body) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 200, "correct audience should pass: {body}");
}

// ── kid manipulation attacks ────────────────────────────────────────────────

#[tokio::test]
async fn kid_path_traversal() {
    let h = setup(None).await;
    let token = make_jwt(
        &h.private_der,
        "../../../../etc/passwd",
        &valid_claims(&h.issuer),
    );
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "path traversal kid must be rejected");
}

#[tokio::test]
async fn kid_sql_injection() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, "' OR 1=1 --", &valid_claims(&h.issuer));
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "SQL injection kid must be rejected");
}

#[tokio::test]
async fn kid_nonexistent() {
    let h = setup(None).await;
    let token = make_jwt(
        &h.private_der,
        "nonexistent-key-id",
        &valid_claims(&h.issuer),
    );
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401, "nonexistent kid must be rejected");
}

// ── Token format attacks ────────────────────────────────────────────────────

#[tokio::test]
async fn completely_garbage_token() {
    let h = setup(None).await;
    let (status, _) = get(h.proxy_addr, "not-a-jwt-at-all").await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn token_with_extra_segments() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    let tampered = format!("{token}.extra-segment");
    let (status, _) = get(h.proxy_addr, &tampered).await;
    assert_eq!(status, 401, "token with extra segments must be rejected");
}

#[tokio::test]
async fn token_single_segment() {
    let h = setup(None).await;
    let (status, _) = get(h.proxy_addr, "eyJhbGciOiJSUzI1NiJ9").await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn token_two_segments_no_trailing_dot() {
    let h = setup(None).await;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"test"}"#);
    let token = format!("{header}.{payload}");
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(status, 401);
}

// ── JWK header injection ────────────────────────────────────────────────────

#[tokio::test]
async fn jwk_header_injection() {
    let h = setup(None).await;
    // Craft a token with an embedded JWK in the header.
    // The proxy should use its own JWKS cache, not the header's jwk field.
    let (attacker_der, attacker_jwk) = generate_rsa_keypair("injected-key");
    let header_json = json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": "injected-key",
        "jwk": attacker_jwk,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header_json).unwrap());
    let claims = valid_claims(&h.issuer);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    // Sign with the attacker key
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};

    let priv_key = RsaPrivateKey::from_pkcs1_der(&attacker_der).unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(priv_key);
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let token = format!("{signing_input}.{sig_b64}");
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(
        status, 401,
        "token with embedded JWK in header must be rejected"
    );
}

// ── jku header injection ────────────────────────────────────────────────────

#[tokio::test]
async fn jku_header_injection() {
    let h = setup(None).await;
    // Create an attacker-controlled JWKS endpoint
    let (attacker_der, attacker_jwk) = generate_rsa_keypair("attacker-key");
    let attacker_jwks = json!({ "keys": [attacker_jwk] });

    let attacker_server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(&attacker_jwks))
        .mount(&attacker_server)
        .await;

    // Craft token with jku pointing to attacker server
    let header_json = json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": "attacker-key",
        "jku": attacker_server.uri(),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header_json).unwrap());
    let claims = valid_claims(&h.issuer);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());

    // Sign with attacker key
    let signing_input = format!("{header_b64}.{claims_b64}");

    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};

    let priv_key = RsaPrivateKey::from_pkcs1_der(&attacker_der).unwrap();
    let signing_key = SigningKey::<sha2::Sha256>::new(priv_key);
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let token = format!("{signing_input}.{sig_b64}");
    let (status, _) = get(h.proxy_addr, &token).await;
    assert_eq!(
        status, 401,
        "token with jku pointing to attacker server must be rejected"
    );
}

// ── Encoding attacks ────────────────────────────────────────────────────────

#[tokio::test]
async fn token_with_invalid_base64_padding() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    // Add invalid base64 padding characters
    let tampered = format!("{token}====");
    let (status, _) = get(h.proxy_addr, &tampered).await;
    assert_eq!(
        status, 401,
        "token with bad base64 padding must be rejected"
    );
}

#[tokio::test]
async fn token_with_whitespace_injection() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    let mid = token.len() / 2;
    let tampered = format!("{} {}", &token[..mid], &token[mid..]);
    let (status, _) = get(h.proxy_addr, &tampered).await;
    assert_eq!(
        status, 401,
        "token with injected whitespace must be rejected"
    );
}

// ── Authorization header edge cases ─────────────────────────────────────────

#[tokio::test]
async fn bearer_case_insensitive() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));

    for prefix in &["Bearer", "bearer", "BEARER", "bEaReR"] {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/test", h.proxy_addr))
            .header("Authorization", format!("{prefix} {token}"))
            .header("Accept", "application/json")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "{prefix} should be accepted as bearer scheme"
        );
    }
}

#[tokio::test]
async fn bearer_no_token() {
    let h = setup(None).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/test", h.proxy_addr))
        .header("Authorization", "Bearer ")
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn multiple_spaces_in_auth_header() {
    let h = setup(None).await;
    let token = make_jwt(&h.private_der, &h.kid, &valid_claims(&h.issuer));
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/test", h.proxy_addr))
        .header("Authorization", format!("Bearer  {token}"))
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    // Extra space means the token starts with a space — should be rejected
    assert_eq!(resp.status(), 401);
}

// ── Response format ─────────────────────────────────────────────────────────

#[tokio::test]
async fn error_response_is_json_when_accept_json() {
    let h = setup(None).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/test", h.proxy_addr))
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("error").is_some(), "JSON error response expected");
}

#[tokio::test]
async fn error_response_is_plain_text_when_accept_text() {
    let h = setup(None).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/test", h.proxy_addr))
        .header("Accept", "text/plain")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/plain"));
}
