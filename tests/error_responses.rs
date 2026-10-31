//! Federation endpoints answer errors with the error response of OpenID Federation 1.0,
//! Section 8.9. `FederationClient` reads it from a response with a status other than 2xx, and still
//! reports the status when the body is not one.

use openid_federation::{
    EndpointError, EntityId, ErrorCode, ErrorResponse, FederationClient, FederationError, HttpClient, HttpResponse,
};
use url::Url;
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

fn endpoint_error(error: FederationError) -> EndpointError {
    match error {
        FederationError::Endpoint(error) => *error,
        other => panic!("expected FederationError::Endpoint, got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_reads_the_error_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fetch"))
        .and(query_param("sub", "https://op.example.org"))
        .respond_with(
            ResponseTemplate::new(404)
                .insert_header("content-type", "application/json")
                .set_body_string(
                    r#"{"error":"not_found","error_description":"Unknown subject https://op.example.org"}"#,
                ),
        )
        .mount(&server)
        .await;

    let fetch_endpoint = Url::parse(&format!("{}/fetch", server.uri())).unwrap();
    let subject = EntityId::parse("https://op.example.org").unwrap();
    let error = FederationClient::new()
        .fetch_subordinate_statement(&fetch_endpoint, &subject)
        .await
        .unwrap_err();

    let error = endpoint_error(error);
    assert_eq!(error.status, 404);
    let mut expected_url = fetch_endpoint.clone();
    expected_url.query_pairs_mut().append_pair("sub", subject.as_str());
    assert_eq!(error.url, expected_url);
    assert_eq!(
        error.response,
        Some(ErrorResponse::new(
            ErrorCode::NotFound,
            "Unknown subject https://op.example.org"
        ))
    );
    assert!(error.to_string().contains("HTTP 404: not_found"), "{error}");
}

#[tokio::test]
async fn non_json_error_body_still_reports_the_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/list"))
        .respond_with(
            ResponseTemplate::new(502)
                .insert_header("content-type", "text/html")
                .set_body_string("<html>Bad Gateway</html>"),
        )
        .mount(&server)
        .await;

    let list_endpoint = Url::parse(&format!("{}/list", server.uri())).unwrap();
    let error = endpoint_error(FederationClient::new().list_entities(&list_endpoint).await.unwrap_err());

    assert_eq!(error.status, 502);
    assert_eq!(error.response, None);
    assert!(error.to_string().ends_with("HTTP 502"), "{error}");
}

#[tokio::test]
async fn configuration_endpoint_errors_are_reported_too() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-federation"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_string(r#"{"error":"temporarily_unavailable","error_description":"Down for maintenance"}"#),
        )
        .mount(&server)
        .await;

    let entity_id = EntityId::parse(&server.uri()).unwrap();
    let error = endpoint_error(
        FederationClient::new()
            .fetch_entity_configuration(&entity_id)
            .await
            .unwrap_err(),
    );

    assert_eq!(error.status, 503);
    assert_eq!(
        error.response.map(|response| response.error),
        Some(ErrorCode::TemporarilyUnavailable)
    );
}

/// An application's own `HttpClient` hands back the response, whatever its status, and the
/// `FederationClient` decides what an error is.
#[tokio::test]
async fn custom_http_client_returns_every_status() {
    struct Unauthorized;

    #[async_trait::async_trait]
    impl HttpClient for Unauthorized {
        async fn get(&self, _url: Url) -> openid_federation::FederationResult<HttpResponse> {
            Ok(HttpResponse::new(
                401,
                Some("application/json".to_string()),
                r#"{"error":"invalid_client","error_description":"Client authentication required"}"#,
            ))
        }
    }

    let fetch_endpoint = Url::parse("https://ta.example.org/fetch").unwrap();
    let subject = EntityId::parse("https://op.example.org").unwrap();
    let error = endpoint_error(
        FederationClient::with_http_client(Unauthorized)
            .fetch_subordinate_statement(&fetch_endpoint, &subject)
            .await
            .unwrap_err(),
    );

    assert_eq!(error.status, 401);
    assert_eq!(
        error.response.map(|response| response.error),
        Some(ErrorCode::InvalidClient)
    );
}

#[tokio::test]
async fn truncated_error_body_still_reports_the_status() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A server that promises a longer body than it sends, then closes the connection.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = socket.read(&mut request).await;
        socket
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"error\":")
            .await
            .unwrap();
        socket.shutdown().await.unwrap();
    });

    let fetch_endpoint = Url::parse(&format!("http://{address}/fetch")).unwrap();
    let subject = EntityId::parse("https://op.example.org").unwrap();
    let error = FederationClient::new()
        .fetch_subordinate_statement(&fetch_endpoint, &subject)
        .await
        .unwrap_err();

    let error = endpoint_error(error);
    assert_eq!(error.status, 503);
    assert_eq!(error.response, None);
}

#[tokio::test]
async fn oversized_error_body_is_discarded() {
    // A valid error response padded past the 64 KiB limit: the client stops reading and does not
    // parse what it read.
    let body = format!(
        "{}{}",
        r#"{"error":"not_found","error_description":"Unknown subject"}"#,
        " ".repeat(70 * 1024)
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fetch"))
        .respond_with(ResponseTemplate::new(404).set_body_raw(body, "application/json"))
        .mount(&server)
        .await;

    let fetch_endpoint = Url::parse(&format!("{}/fetch", server.uri())).unwrap();
    let subject = EntityId::parse("https://op.example.org").unwrap();
    let error = FederationClient::new()
        .fetch_subordinate_statement(&fetch_endpoint, &subject)
        .await
        .unwrap_err();

    let error = endpoint_error(error);
    assert_eq!(error.status, 404);
    assert_eq!(error.response, None);
}
