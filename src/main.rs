use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use jwt_guard::logging::LoggingFormat;
use jwt_guard::{config, jwks, logging, proxy};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let schemes = Arc::new(config::auth_schemes().await.expect("invalid auth scheme config"));
    let jwks_cache = jwks::init_cache(&schemes).await;
    let jwks_refresh = config::jwks_refresh().expect("invalid JWKS refresh config");
    jwks::spawn_refresh(jwks_cache.clone(), Arc::clone(&schemes), jwks_refresh);

    let logging_fmt = config::logging_format().expect("invalid logging format config");
    let logging = match logging_fmt.as_str() {
        "google_cloud" => {
            let project_id = std::env::var("GOOGLE_CLOUD_PROJECT").or_else(|_| {
                eprintln!("GOOGLE_CLOUD_PROJECT not set, fetching from metadata server");
                Ok::<_, String>(String::new())
            }).unwrap();
            let project_id = if project_id.is_empty() {
                logging::fetch_gcp_project_id()
                    .await
                    .expect("failed to fetch GCP project ID from metadata server")
            } else {
                project_id
            };
            println!("Logging: google_cloud (project={project_id})");
            LoggingFormat::GoogleCloud { project_id }
        }
        _ => {
            println!("Logging: text");
            LoggingFormat::Text
        }
    };

    let state = Arc::new(proxy::AppState {
        client: proxy::build_client(),
        target_url: config::target_url().expect("invalid target URL config"),
        schemes,
        jwks_cache,
        forward_payload: config::forward_payload(),
        forward_authorization: config::forward_authorization(),
        forward_scheme: config::forward_scheme(),
        upstream_timeout: config::upstream_timeout().expect("invalid upstream timeout config"),
        logging,
    });

    let port = config::port().expect("invalid PORT config");
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Proxy listening on {addr}, forwarding to {}", state.target_url);

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result.unwrap();
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = Arc::clone(&state);
                        async move { proxy::handle(&state, req).await }
                    });
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        eprintln!("connection error: {e}");
                    }
                });
            }
            _ = &mut shutdown => {
                println!("Shutting down");
                break;
            }
        }
    }
}
