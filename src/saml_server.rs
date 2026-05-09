use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};
use http_body_util::BodyExt;

pub struct SamlResult {
    pub response: String,
}

pub async fn listen_for_saml(
    port: u16,
    saml_url: String,
    timeout_secs: u64,
) -> Result<SamlResult, String> {
    let (tx, mut rx) = mpsc::channel::<String>(1);
    let done = Arc::new(AtomicBool::new(false));

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    info!(addr = %addr, "SAML server starting");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind SAML server on port {port}: {e}"))?;

    open_browser(&saml_url);

    let result = timeout(Duration::from_secs(timeout_secs), async {
        loop {
            let (stream, _) = listener.accept().await.map_err(|e| format!("accept: {e}"))?;
            let io = hyper_util::rt::TokioIo::new(stream);
            let tx = tx.clone();
            let done = done.clone();

            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let tx = tx.clone();
                    let done = done.clone();
                    async move { handle_request(req, tx, done).await }
                });

                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });

            if let Some(response) = rx.recv().await {
                return Ok(SamlResult { response });
            }
        }
    })
    .await;

    match result {
        Ok(Ok(saml_result)) => {
            info!("SAML authentication completed");
            Ok(saml_result)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(format!("SAML authentication timed out ({timeout_secs}s)")),
    }
}

fn open_browser(url: &str) {
    info!(url = &url[..80.min(url.len())], "opening browser");
    match std::process::Command::new("xdg-open").arg(url).spawn() {
        Ok(_) => info!("browser opened"),
        Err(e) => warn!(error = %e, "failed to open browser"),
    }
}

async fn handle_request(
    req: hyper::Request<hyper::body::Incoming>,
    tx: mpsc::Sender<String>,
    done: Arc<AtomicBool>,
) -> Result<hyper::Response<String>, hyper::Error> {
    if done.load(Ordering::Relaxed) {
        return Ok(hyper::Response::new(
            "Authentication already completed.".to_string(),
        ));
    }

    match *req.method() {
        hyper::Method::POST => {
            let body = BodyExt::collect(req.into_body())
                .await?;

            let bytes = body.to_bytes();
            let body_str = String::from_utf8_lossy(&bytes);

            if let Some(response) = extract_saml_response(&body_str) {
                info!("received SAML response");
                done.store(true, Ordering::Relaxed);
                let _ = tx.send(response).await;
                Ok(hyper::Response::new(
                    "Authentication successful! You can close this window.".to_string(),
                ))
            } else {
                Ok(hyper::Response::builder()
                    .status(400)
                    .body("No SAMLResponse found".to_string())
                    .unwrap())
            }
        }
        hyper::Method::GET => {
            Ok(hyper::Response::new(r#"{"status":"ok"}"#.to_string()))
        }
        _ => Ok(hyper::Response::builder()
            .status(405)
            .body("Method not allowed".to_string())
            .unwrap()),
    }
}

fn extract_saml_response(body: &str) -> Option<String> {
    for pair in body.split('&') {
        if let Some(val) = pair.strip_prefix("SAMLResponse=") {
            return Some(urlencoding::decode(val).ok()?.to_string());
        }
    }
    None
}
