//! Load tests for the JWT proxy.
//!
//! Measures throughput and latency under concurrent request load.
//! Run with: `cargo test --test load -- --nocapture`

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn generate_rsa_keypair(kid: &str) -> (Vec<u8>, Value) {
    use rsa::RsaPrivateKey;
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let private_der = private_key.to_pkcs1_der().unwrap();
    let public_key = private_key.to_public_key();

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

fn make_jwt(private_der: &[u8], kid: &str, claims: &Value) -> String {
    let key = EncodingKey::from_rsa_der(private_der);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, claims, &key).unwrap()
}

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

struct LoadTestEnv {
    proxy_addr: SocketAddr,
    token: String,
}

async fn setup_load_env() -> LoadTestEnv {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let kid = "load-key";
    let issuer = "https://load-issuer.example.com";

    let (private_der, jwk) = generate_rsa_keypair(kid);
    let jwks_json = json!({ "keys": [jwk] });

    let jwks_server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(&jwks_json))
        .mount(&jwks_server)
        .await;

    let upstream_addr = spawn_upstream().await;

    let schemes = vec![(
        "load".to_string(),
        jwt_guard::config::AuthScheme {
            issuer: issuer.to_string(),
            jwks_uri: jwks_server.uri(),
            audiences: None,
        },
    )];

    let cache = jwt_guard::jwks::init_cache(&schemes).await;

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
        forward_scheme: false,
        upstream_timeout: std::time::Duration::from_secs(30),
        logging: jwt_guard::logging::LoggingFormat::Text,
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

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "iss": issuer,
        "sub": "load-user",
        "iat": now,
        "exp": now + 3600,
    });
    let token = make_jwt(&private_der, kid, &claims);

    LoadTestEnv { proxy_addr, token }
}

struct LoadResult {
    total_requests: u64,
    successful: u64,
    failed: u64,
    duration: Duration,
    avg_latency: Duration,
    p50_latency: Duration,
    p95_latency: Duration,
    p99_latency: Duration,
    max_latency: Duration,
    rps: f64,
}

impl std::fmt::Display for LoadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "  Requests: {} total, {} ok, {} failed\n\
             Duration: {:.2}s\n\
             Throughput: {:.1} req/s\n\
             Latency: avg={:.2}ms p50={:.2}ms p95={:.2}ms p99={:.2}ms max={:.2}ms",
            self.total_requests,
            self.successful,
            self.failed,
            self.duration.as_secs_f64(),
            self.rps,
            self.avg_latency.as_secs_f64() * 1000.0,
            self.p50_latency.as_secs_f64() * 1000.0,
            self.p95_latency.as_secs_f64() * 1000.0,
            self.p99_latency.as_secs_f64() * 1000.0,
            self.max_latency.as_secs_f64() * 1000.0,
        )
    }
}

async fn run_load(
    addr: SocketAddr,
    auth_header: Option<String>,
    concurrency: usize,
    requests_per_worker: usize,
) -> LoadResult {
    let successful = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let auth = auth_header.clone();
        let ok = Arc::clone(&successful);
        let err = Arc::clone(&failed);
        let lats = Arc::clone(&latencies);
        let addr = addr;

        handles.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut local_lats = Vec::with_capacity(requests_per_worker);

            for _ in 0..requests_per_worker {
                let req_start = Instant::now();
                let mut req = client.get(format!("http://{addr}/load-test"));
                if let Some(ref a) = auth {
                    req = req.header("Authorization", a);
                }
                req = req.header("Accept", "application/json");

                match req.send().await {
                    Ok(resp) => {
                        let _ = resp.bytes().await;
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                }
                local_lats.push(req_start.elapsed());
            }

            lats.lock().await.extend(local_lats);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    let duration = start.elapsed();

    let mut lats = latencies.lock().await.clone();
    lats.sort();

    let total = lats.len() as u64;
    let avg = if total > 0 {
        lats.iter().sum::<Duration>() / total as u32
    } else {
        Duration::ZERO
    };

    let percentile = |p: f64| -> Duration {
        if lats.is_empty() {
            return Duration::ZERO;
        }
        let idx = ((p / 100.0) * (lats.len() - 1) as f64).round() as usize;
        lats[idx]
    };

    LoadResult {
        total_requests: total,
        successful: successful.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
        duration,
        avg_latency: avg,
        p50_latency: percentile(50.0),
        p95_latency: percentile(95.0),
        p99_latency: percentile(99.0),
        max_latency: *lats.last().unwrap_or(&Duration::ZERO),
        rps: total as f64 / duration.as_secs_f64(),
    }
}

// ── Load tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn load_valid_tokens_50_concurrent() {
    let env = setup_load_env().await;
    let auth = format!("Bearer {}", env.token);

    let result = run_load(env.proxy_addr, Some(auth), 50, 20).await;
    println!("\n=== Load: 50 concurrent workers x 20 requests (valid JWT) ===\n{result}");

    assert_eq!(result.failed, 0, "no requests should fail at transport level");
    assert_eq!(result.successful, 1000);
    assert!(
        result.p99_latency < Duration::from_secs(2),
        "p99 latency should be under 2s, got {:.0}ms",
        result.p99_latency.as_secs_f64() * 1000.0
    );
}

#[tokio::test]
async fn load_valid_tokens_100_concurrent() {
    let env = setup_load_env().await;
    let auth = format!("Bearer {}", env.token);

    let result = run_load(env.proxy_addr, Some(auth), 100, 10).await;
    println!("\n=== Load: 100 concurrent workers x 10 requests (valid JWT) ===\n{result}");

    assert_eq!(result.failed, 0);
    assert_eq!(result.successful, 1000);
}

#[tokio::test]
async fn load_invalid_tokens_rejected_quickly() {
    let env = setup_load_env().await;
    let auth = "Bearer invalid.token.here".to_string();

    let result = run_load(env.proxy_addr, Some(auth), 50, 20).await;
    println!("\n=== Load: 50 concurrent workers x 20 requests (invalid JWT) ===\n{result}");

    // All requests should complete (even though they return 401)
    assert_eq!(result.failed, 0, "no transport-level failures");
    assert_eq!(result.successful, 1000);
    // Invalid tokens should be rejected faster than valid ones (no upstream call)
    assert!(
        result.p99_latency < Duration::from_secs(1),
        "p99 for rejections should be under 1s, got {:.0}ms",
        result.p99_latency.as_secs_f64() * 1000.0
    );
}

#[tokio::test]
async fn load_no_auth_rejected_quickly() {
    let env = setup_load_env().await;

    let result = run_load(env.proxy_addr, None, 50, 20).await;
    println!("\n=== Load: 50 concurrent workers x 20 requests (no auth) ===\n{result}");

    assert_eq!(result.failed, 0);
    assert_eq!(result.successful, 1000);
    assert!(
        result.p99_latency < Duration::from_secs(1),
        "p99 for missing-auth rejections should be under 1s"
    );
}

#[tokio::test]
async fn load_mixed_valid_and_invalid() {
    let env = setup_load_env().await;

    // Run valid and invalid concurrently to ensure invalid tokens
    // don't degrade valid request performance.
    let valid_auth = format!("Bearer {}", env.token);
    let addr = env.proxy_addr;

    let valid_handle = tokio::spawn(async move {
        run_load(addr, Some(valid_auth), 25, 20).await
    });
    let invalid_handle = tokio::spawn(async move {
        run_load(addr, Some("Bearer garbage".to_string()), 25, 20).await
    });

    let valid_result = valid_handle.await.unwrap();
    let invalid_result = invalid_handle.await.unwrap();

    println!("\n=== Mixed load: valid tokens ===\n{valid_result}");
    println!("\n=== Mixed load: invalid tokens ===\n{invalid_result}");

    assert_eq!(valid_result.failed, 0);
    assert_eq!(invalid_result.failed, 0);
}
