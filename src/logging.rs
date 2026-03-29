use hyper::{Method, StatusCode};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum LoggingFormat {
    Text,
    GoogleCloud { project_id: String },
}

pub struct AccessLog<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub status: StatusCode,
    pub duration: Duration,
    pub trace_header: Option<&'a str>,
    pub detail: &'a str,
}

impl LoggingFormat {
    pub fn log(&self, entry: &AccessLog) {
        match self {
            Self::Text => log_text(entry),
            Self::GoogleCloud { project_id } => log_google_cloud(entry, project_id),
        }
    }
}

fn log_text(entry: &AccessLog) {
    println!(
        "{} {} {} {:.1}ms {}",
        entry.method,
        entry.path,
        entry.status,
        entry.duration.as_secs_f64() * 1000.0,
        entry.detail,
    );
}

fn log_google_cloud(entry: &AccessLog, project_id: &str) {
    let latency_secs = entry.duration.as_secs_f64();
    let severity = if entry.status.is_client_error() {
        "WARNING"
    } else if entry.status.is_server_error() {
        "ERROR"
    } else {
        "INFO"
    };

    let trace = entry
        .trace_header
        .and_then(|h| h.split('/').next())
        .filter(|t| !t.is_empty());

    let trace_field = match trace {
        Some(trace_id) => {
            format!("\"logging.googleapis.com/trace\":\"projects/{project_id}/traces/{trace_id}\",")
        }
        None => String::new(),
    };

    println!(
        "{{\
            \"severity\":\"{severity}\",\
            \"httpRequest\":{{\
                \"requestMethod\":\"{}\",\
                \"requestUrl\":\"{}\",\
                \"status\":{},\
                \"latency\":\"{latency_secs:.6}s\"\
            }},\
            {trace_field}\
            \"message\":\"{}\"\
        }}",
        entry.method,
        entry.path,
        entry.status.as_u16(),
        entry.detail,
    );
}

const METADATA_URL: &str = "http://metadata.google.internal/computeMetadata/v1/project/project-id";

pub async fn fetch_gcp_project_id() -> Result<String, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get(METADATA_URL)
        .header("Metadata-Flavor", "Google")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("metadata server request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("metadata server returned {}", resp.status()));
    }

    resp.text()
        .await
        .map_err(|e| format!("failed to read metadata response: {e}"))
}
