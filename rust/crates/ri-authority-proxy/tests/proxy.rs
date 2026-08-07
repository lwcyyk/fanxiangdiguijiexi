use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Json, State};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::routing::{get, post};
use futures_util::stream;
use ri_authority_proxy::{
    AuthorityProxyConfig, AuthorityProxyState, DnsTransport, authority_trace_events, make_servfail,
    valid_response,
};
use ri_core::{TraceEventKind, dns_correlation_id, dns_wire_digest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn query() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w',
        b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]
}

fn response() -> Vec<u8> {
    let mut response = query();
    response[2] |= 0x84;
    response
}

fn state(
    backend: std::net::SocketAddr,
    agent_url: String,
    agent_timeout: Duration,
    max_agent_response_bytes: usize,
) -> AuthorityProxyState {
    AuthorityProxyState::new(
        AuthorityProxyConfig {
            server_id: "operator/authdns".into(),
            public_ip: "192.0.2.53".parse().unwrap(),
            public_port: 53,
            backend,
            agent_url,
            trace_ingest_token: "trace-token-that-is-longer-than-thirty-two-bytes".into(),
            backend_timeout: Duration::from_secs(1),
            agent_timeout,
            max_agent_response_bytes,
        },
        reqwest::Client::builder().no_proxy().build().unwrap(),
    )
    .unwrap()
}

async fn tcp_backend(
    expected_response: Vec<u8>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let length = usize::from(stream.read_u16().await.unwrap());
        let mut received = vec![0_u8; length];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, query());
        stream
            .write_u16(u16::try_from(expected_response.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&expected_response).await.unwrap();
    });
    (address, task)
}

#[test]
fn trace_lineage_binds_authority_response_without_changing_dns() {
    let query = query();
    let response = response();
    let events = authority_trace_events(
        "operator/authdns",
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        53,
        DnsTransport::Udp,
        &query,
        &response,
    )
    .unwrap();
    assert_eq!(events[0].kind, TraceEventKind::ClientQuery);
    assert_eq!(events[0].sequence, 1);
    assert!(events[0].parent_event_id.is_none());
    assert_eq!(events[1].kind, TraceEventKind::AuthorityResponse);
    assert_eq!(events[1].sequence, 2);
    assert_eq!(
        events[1].parent_event_id.as_deref(),
        Some(events[0].event_id.as_str())
    );
    assert_eq!(
        events[1].correlation_id,
        dns_correlation_id(&query).unwrap()
    );
    assert_eq!(events[1].query_digest, dns_wire_digest(&query));
    assert_eq!(
        events[1].response_digest.as_deref(),
        Some(dns_wire_digest(&response).as_str())
    );
    assert_eq!(events[1].target_endpoint.as_ref().unwrap().transport, "udp");
    assert!(valid_response(&query, &response));
}

#[test]
fn standard_servfail_preserves_id_and_question() {
    let query = query();
    let servfail = make_servfail(&query);
    assert_eq!(&servfail[..2], &query[..2]);
    assert_ne!(servfail[2] & 0x80, 0);
    assert_eq!(servfail[3] & 0x0f, 2);
    assert_eq!(&servfail[4..6], &[0, 1]);
    assert_eq!(&servfail[6..12], &[0; 6]);
    assert_eq!(&servfail[12..], &query[12..]);
}

#[derive(Clone)]
struct IngestState {
    token: String,
}

async fn ingest(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Json(events): Json<Vec<ri_core::TraceEventV2>>,
) -> StatusCode {
    let expected = format!("Bearer {}", state.token);
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(expected.as_str())
        || events.len() != 2
    {
        return StatusCode::UNAUTHORIZED;
    }
    StatusCode::NO_CONTENT
}

#[tokio::test]
async fn proxy_releases_exact_response_only_after_durable_ingestion() {
    let backend = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let expected_response = response();
    let backend_task = tokio::spawn({
        let expected_response = expected_response.clone();
        async move {
            let mut buffer = [0_u8; 512];
            let (_, peer) = backend.recv_from(&mut buffer).await.unwrap();
            backend.send_to(&expected_response, peer).await.unwrap();
        }
    });

    let token = "trace-token-that-is-longer-than-thirty-two-bytes".to_owned();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/v2/trace-events/batch", post(ingest))
        .route("/readyz", get(|| async { StatusCode::NO_CONTENT }))
        .with_state(IngestState {
            token: token.clone(),
        });
    let agent_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let state = AuthorityProxyState::new(
        AuthorityProxyConfig {
            server_id: "operator/authdns".into(),
            public_ip: "192.0.2.53".parse().unwrap(),
            public_port: 53,
            backend: backend_address,
            agent_url,
            trace_ingest_token: token,
            backend_timeout: std::time::Duration::from_secs(1),
            agent_timeout: std::time::Duration::from_secs(1),
            max_agent_response_bytes: 4_096,
        },
        reqwest::Client::builder().no_proxy().build().unwrap(),
    )
    .unwrap();
    let actual = state.process_query(&query(), DnsTransport::Udp).await;
    assert_eq!(actual, expected_response);
    backend_task.await.unwrap();
    agent_task.abort();
}

#[tokio::test]
async fn failed_ingestion_fails_closed_after_backend_remains_functional() {
    let backend = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let expected_response = response();
    let backend_task = tokio::spawn({
        let expected_response = expected_response.clone();
        async move {
            let mut buffer = [0_u8; 512];
            let (_, peer) = backend.recv_from(&mut buffer).await.unwrap();
            backend.send_to(&expected_response, peer).await.unwrap();
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/v2/trace-events/batch",
        post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
    );
    let agent_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let state = AuthorityProxyState::new(
        AuthorityProxyConfig {
            server_id: "operator/authdns".into(),
            public_ip: "192.0.2.53".parse().unwrap(),
            public_port: 53,
            backend: backend_address,
            agent_url,
            trace_ingest_token: "trace-token-that-is-longer-than-thirty-two-bytes".into(),
            backend_timeout: std::time::Duration::from_secs(1),
            agent_timeout: std::time::Duration::from_secs(1),
            max_agent_response_bytes: 4_096,
        },
        reqwest::Client::builder().no_proxy().build().unwrap(),
    )
    .unwrap();
    let actual = state.process_query(&query(), DnsTransport::Udp).await;
    assert_eq!(actual, make_servfail(&query()));
    backend_task.await.unwrap();
    agent_task.abort();
}

#[tokio::test]
async fn tcp_backend_response_is_released_after_ingestion() {
    let expected_response = response();
    let (backend_address, backend_task) = tcp_backend(expected_response.clone()).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/v2/trace-events/batch", post(ingest))
        .with_state(IngestState {
            token: "trace-token-that-is-longer-than-thirty-two-bytes".into(),
        });
    let agent_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let actual = state(backend_address, agent_url, Duration::from_secs(1), 4_096)
        .process_query(&query(), DnsTransport::Tcp)
        .await;
    assert_eq!(actual, expected_response);
    backend_task.await.unwrap();
    agent_task.abort();
}

#[tokio::test]
async fn malformed_backend_response_fails_closed() {
    let backend = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (_, peer) = backend.recv_from(&mut buffer).await.unwrap();
        let mut malformed = response();
        malformed[0] ^= 0xff;
        backend.send_to(&malformed, peer).await.unwrap();
    });
    let actual = state(
        backend_address,
        "http://127.0.0.1:1".into(),
        Duration::from_secs(1),
        4_096,
    )
    .process_query(&query(), DnsTransport::Udp)
    .await;
    assert_eq!(actual, make_servfail(&query()));
    backend_task.await.unwrap();
}

#[tokio::test]
async fn ingestion_timeout_fails_closed() {
    let backend = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let expected_response = response();
    let backend_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (_, peer) = backend.recv_from(&mut buffer).await.unwrap();
        backend.send_to(&expected_response, peer).await.unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/v2/trace-events/batch",
        post(|| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            StatusCode::NO_CONTENT
        }),
    );
    let agent_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let actual = state(backend_address, agent_url, Duration::from_millis(10), 4_096)
        .process_query(&query(), DnsTransport::Udp)
        .await;
    assert_eq!(actual, make_servfail(&query()));
    backend_task.await.unwrap();
    agent_task.abort();
}

async fn oversized_chunked_error() -> Response<Body> {
    let chunks = stream::iter([
        Ok::<_, Infallible>(Bytes::from(vec![b'a'; 600])),
        Ok::<_, Infallible>(Bytes::from(vec![b'b'; 600])),
    ]);
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(Body::from_stream(chunks))
        .unwrap()
}

#[tokio::test]
async fn oversized_chunked_agent_error_fails_closed_without_unbounded_buffering() {
    let backend = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let expected_response = response();
    let backend_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 512];
        let (_, peer) = backend.recv_from(&mut buffer).await.unwrap();
        backend.send_to(&expected_response, peer).await.unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route("/v2/trace-events/batch", post(oversized_chunked_error));
    let agent_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let state = state(backend_address, agent_url, Duration::from_secs(1), 1_024);
    let actual = state.process_query(&query(), DnsTransport::Udp).await;
    assert_eq!(actual, make_servfail(&query()));
    assert!(
        state
            .metrics()
            .render()
            .contains("resolver_identity_authority_evidence_failures_total 1\n")
    );
    backend_task.await.unwrap();
    agent_task.abort();
}

#[tokio::test]
async fn readiness_tracks_agent_probe_result() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route("/readyz", get(|| async { StatusCode::NO_CONTENT }));
    let agent_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let state = state(
        "127.0.0.1:1".parse().unwrap(),
        agent_url,
        Duration::from_secs(1),
        4_096,
    );
    assert!(!state.metrics().is_ready());
    assert!(state.probe_agent().await);
    assert!(state.metrics().is_ready());
    agent_task.abort();
}
