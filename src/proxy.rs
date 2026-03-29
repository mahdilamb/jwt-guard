use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::config::Schemes;
use crate::jwks;
use crate::logging::{AccessLog, LoggingFormat};

type HttpsConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;
pub type HttpClient = Client<HttpsConnector, Incoming>;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

pub struct AppState {
    pub client: HttpClient,
    pub target_url: String,
    pub schemes: Arc<Schemes>,
    pub jwks_cache: jwks::Cache,
    pub forward_payload: bool,
    pub forward_authorization: bool,
    pub forward_scheme: bool,
    pub upstream_timeout: Duration,
    pub logging: LoggingFormat,
}

pub fn build_client() -> HttpClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

fn accepts_json(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json") || v.contains("*/*"))
}

fn error_response(json: bool, status: StatusCode, msg: &str) -> Response<BoxBody> {
    let (content_type, content) = if json {
        ("application/json", format!("{{\"error\":\"{msg}\"}}"))
    } else {
        ("text/plain", msg.to_string())
    };
    let body = Full::new(Bytes::from(content))
        .map_err(|never| -> hyper::Error { match never {} })
        .boxed();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(body)
        .unwrap()
}

fn trace_header(req: &Request<Incoming>) -> Option<&str> {
    req.headers()
        .get("x-cloud-trace-context")
        .and_then(|v| v.to_str().ok())
}

pub async fn handle(
    state: &AppState,
    req: Request<Incoming>,
) -> Result<Response<BoxBody>, Infallible> {
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let trace = trace_header(&req).map(String::from);
    let json = accepts_json(&req);
    let cache_snapshot = state.jwks_cache.load();

    let (scheme_name, payload) = match crate::jwt::verify(&req, &state.schemes, &cache_snapshot) {
        Ok((name, payload)) => (name.to_string(), payload.to_string()),
        Err(e) => {
            let status = e.status_code();
            let resp = error_response(json, status, &e.to_string());
            state.logging.log(&AccessLog {
                method: &method,
                path: &path,
                status,
                duration: start.elapsed(),
                trace_header: trace.as_deref(),
                detail: &format!("denied: {e}"),
            });
            return Ok(resp);
        }
    };

    let resp = match forward(state, req, &scheme_name, &payload).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("proxy error: {e}");
            error_response(json, StatusCode::BAD_GATEWAY, &format!("Bad Gateway: {e}"))
        }
    };

    state.logging.log(&AccessLog {
        method: &method,
        path: &path,
        status: resp.status(),
        duration: start.elapsed(),
        trace_header: trace.as_deref(),
        detail: &format!("scheme={scheme_name}"),
    });
    Ok(resp)
}

async fn forward(
    state: &AppState,
    req: Request<Incoming>,
    scheme_name: &str,
    payload: &str,
) -> Result<Response<BoxBody>, Box<dyn std::error::Error + Send + Sync>> {
    let uri = format!("{}{}", state.target_url.trim_end_matches('/'), req.uri());
    let (parts, body) = req.into_parts();

    let mut builder = Request::builder().method(parts.method).uri(&uri);
    for (key, value) in &parts.headers {
        if key == hyper::header::AUTHORIZATION && !state.forward_authorization {
            continue;
        }
        builder = builder.header(key, value);
    }

    if state.forward_payload {
        builder = builder.header("X-JWT-Payload", payload);
    }
    if state.forward_scheme {
        builder = builder.header("X-JWT-Scheme", scheme_name);
    }

    let upstream_req = builder
        .body(body)
        .expect("failed to build upstream request");

    let resp = tokio::time::timeout(state.upstream_timeout, state.client.request(upstream_req))
        .await
        .map_err(|_| "upstream request timed out")??;
    let (parts, body) = resp.into_parts();
    let body = body.boxed();
    Ok(Response::from_parts(parts, body))
}
