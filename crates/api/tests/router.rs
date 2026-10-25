use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn app() -> axum::Router {
    let app = antidote_api::App::new(antidote_api::Loaded::embedded().unwrap(), rusqlite::Connection::open_in_memory().unwrap()).unwrap();
    antidote_api::router(app)
}

async fn call(r: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let res = r.clone().oneshot(req).await.unwrap();
    let status = res.status();
    (status, String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap())
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

fn post(body: &str) -> Request<Body> {
    Request::post("/v1/stats").header("content-type", "application/json").body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn check_entries_and_badges() {
    let r = app();
    let (s, b) = call(&r, get("/v1/check/npm/mcp-remote?version=0.1.15")).await;
    assert_eq!(s, StatusCode::OK);
    let f: serde_json::Value = serde_json::from_str(&b).unwrap();
    let id = f[0]["id"].as_str().expect("mcp-remote 0.1.15 has an advisory").to_string();
    assert_eq!(call(&r, get("/v1/check/npm/mcp-remote?version=0.1.16")).await.1, "[]");
    assert_eq!(call(&r, get("/v1/check/cargo/x")).await.0, StatusCode::BAD_REQUEST);

    let (s, b) = call(&r, get(&format!("/v1/entries/{id}"))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b.contains("mcp-remote"));
    assert_eq!(call(&r, get("/v1/entries/AGT-0000-0000")).await.0, StatusCode::NOT_FOUND);

    assert!(call(&r, get("/badge/npm/postmark-mcp.svg?version=1.0.16")).await.1.contains("malicious"));
    assert!(call(&r, get("/badge/npm/mcp-remote.svg?version=0.1.15")).await.1.contains("advisor"));
    assert!(call(&r, get("/badge/npm/@modelcontextprotocol/sdk-not-real.svg")).await.1.contains("no known threats"));
    assert!(call(&r, get("/v1/feed.json")).await.1.contains("\"entries\""));
    assert_eq!(call(&r, get("/v1/feed.json.minisig")).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn stats_sum_and_reject_junk() {
    let r = app();
    for _ in 0..2 {
        assert_eq!(call(&r, post(r#"{"corpus_version":1,"counts":{"AGT-R-0101":2,"AGT-T-0003":1}}"#)).await.0, StatusCode::NO_CONTENT);
    }
    let v: serde_json::Value = serde_json::from_str(&call(&r, get("/v1/stats")).await.1).unwrap();
    assert_eq!(v["reports"], 2);
    assert_eq!(v["counts"]["AGT-R-0101"], 4);
    assert_eq!(call(&r, post(r#"{"corpus_version":1,"counts":{"/etc/passwd":1}}"#)).await.0, StatusCode::BAD_REQUEST);
    assert!(call(&r, post(r#"{"corpus_version":1}"#)).await.0.is_client_error());
    let big = format!(r#"{{"corpus_version":1,"counts":{{"AGT-X":1}},"pad":"{}"}}"#, "x".repeat(20_000));
    assert_eq!(call(&r, post(&big)).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}
