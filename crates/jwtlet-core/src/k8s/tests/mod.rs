//  Copyright (c) 2026 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

#![allow(clippy::unwrap_used)]

pub mod renewal;

use crate::k8s::{K8S_UID_CLAIM, K8sTokenReviewVerifier};
use dsdk_facet_core::jwt::{JwtVerificationError, JwtVerifier};
use serde_json::json;
use std::path::PathBuf;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN_REVIEW_PATH: &str = "/apis/authentication.k8s.io/v1/tokenreviews";
const CLUSTER_ISSUER: &str = "https://kubernetes.default.svc";
const AUDIENCE: &str = "https://my-service.example.com";
const SUBJECT_TOKEN: &str = "subject.jwt.token";

fn write_sa_token_file(token: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("jwtlet-k8s-test-{}.token", uuid::Uuid::new_v4()));
    std::fs::write(&p, token).unwrap();
    p
}

async fn make_verifier(server: &MockServer, token_file: &PathBuf) -> K8sTokenReviewVerifier {
    let mut v = K8sTokenReviewVerifier::builder()
        .api_server_url(server.uri())
        .cluster_issuer(CLUSTER_ISSUER)
        .token_file(token_file.clone())
        .build();
    v.initialize().await.unwrap();
    v
}

#[tokio::test]
async fn verify_token_returns_claims_for_authenticated_token() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");

    Mock::given(method("POST"))
        .and(path(TOKEN_REVIEW_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": {
                "authenticated": true,
                "audiences": [AUDIENCE],
                "user": {
                    "username": "system:serviceaccount:default:test-sa",
                    "uid": "7a1c7e65-b871-4d3a-9f0e-000000000001",
                    "groups": ["system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"]
                }
            }
        })))
        .mount(&server)
        .await;

    let v = make_verifier(&server, &token_file).await;
    let claims = v.verify_token(AUDIENCE, SUBJECT_TOKEN).await.unwrap();

    assert_eq!(claims.sub, "system:serviceaccount:default:test-sa");
    assert_eq!(claims.iss, CLUSTER_ISSUER);
    assert_eq!(claims.aud, AUDIENCE);
    assert_eq!(claims.custom[K8S_UID_CLAIM], "7a1c7e65-b871-4d3a-9f0e-000000000001");
}

#[tokio::test]
async fn verify_token_fails_when_not_authenticated() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");

    Mock::given(method("POST"))
        .and(path(TOKEN_REVIEW_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": {
                "authenticated": false,
                "error": "token has expired"
            }
        })))
        .mount(&server)
        .await;

    let v = make_verifier(&server, &token_file).await;
    let Err(JwtVerificationError::VerificationFailed(msg)) = v.verify_token(AUDIENCE, SUBJECT_TOKEN).await else {
        panic!("expected VerificationFailed");
    };
    assert!(msg.contains("token has expired"), "unexpected message: {msg}");
}

#[tokio::test]
async fn verify_token_fails_on_api_server_error() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");

    Mock::given(method("POST"))
        .and(path(TOKEN_REVIEW_PATH))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let v = make_verifier(&server, &token_file).await;
    let err = v.verify_token(AUDIENCE, SUBJECT_TOKEN).await;
    assert!(matches!(err, Err(JwtVerificationError::VerificationFailed(_))));
}

#[tokio::test]
async fn verify_token_retries_on_401_with_refreshed_sa_token() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");

    // First call: stale SA token -> 401 triggers re-read of token file and a retry
    Mock::given(method("POST"))
        .and(path(TOKEN_REVIEW_PATH))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Retry succeeds
    Mock::given(method("POST"))
        .and(path(TOKEN_REVIEW_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": {
                "authenticated": true,
                "audiences": [AUDIENCE],
                "user": {
                    "username": "system:serviceaccount:ns:sa",
                    "groups": ["system:serviceaccounts", "system:serviceaccounts:ns"]
                }
            }
        })))
        .mount(&server)
        .await;

    let v = make_verifier(&server, &token_file).await;
    let claims = v.verify_token(AUDIENCE, SUBJECT_TOKEN).await.unwrap();
    assert_eq!(claims.sub, "system:serviceaccount:ns:sa");
}

#[tokio::test]
async fn verify_token_fails_when_authenticated_but_no_user_info() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");

    Mock::given(method("POST"))
        .and(path(TOKEN_REVIEW_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": { "authenticated": true }
        })))
        .mount(&server)
        .await;

    let v = make_verifier(&server, &token_file).await;
    let err = v.verify_token(AUDIENCE, SUBJECT_TOKEN).await;
    assert!(matches!(err, Err(JwtVerificationError::VerificationFailed(_))));
}

#[tokio::test]
async fn verify_token_fails_before_initialize() {
    let v = K8sTokenReviewVerifier::builder()
        .api_server_url("http://127.0.0.1:9999")
        .cluster_issuer(CLUSTER_ISSUER)
        .build();

    let Err(JwtVerificationError::VerificationFailed(msg)) = v.verify_token(AUDIENCE, SUBJECT_TOKEN).await else {
        panic!("expected VerificationFailed");
    };
    assert!(msg.contains("not initialized"), "unexpected message: {msg}");
}

async fn mount_review(server: &MockServer, status: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path(TOKEN_REVIEW_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": status })))
        .mount(server)
        .await;
}

async fn expect_verification_failure(v: &K8sTokenReviewVerifier) -> String {
    let Err(JwtVerificationError::VerificationFailed(msg)) = v.verify_token(AUDIENCE, SUBJECT_TOKEN).await else {
        panic!("expected VerificationFailed");
    };
    msg
}

#[tokio::test]
async fn verify_token_fails_when_review_omits_audiences() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");
    mount_review(
        &server,
        json!({
            "authenticated": true,
            "user": { "username": "system:serviceaccount:ns:sa", "groups": ["system:serviceaccounts"] }
        }),
    )
    .await;

    let v = make_verifier(&server, &token_file).await;
    let msg = expect_verification_failure(&v).await;
    assert!(msg.contains("audience"), "unexpected message: {msg}");
}

#[tokio::test]
async fn verify_token_fails_when_review_returns_other_audience() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");
    // An audience-unaware authenticator answers with the API server's own audiences.
    mount_review(
        &server,
        json!({
            "authenticated": true,
            "audiences": ["https://kubernetes.default.svc.cluster.local"],
            "user": { "username": "system:serviceaccount:ns:sa", "groups": ["system:serviceaccounts"] }
        }),
    )
    .await;

    let v = make_verifier(&server, &token_file).await;
    let msg = expect_verification_failure(&v).await;
    assert!(msg.contains("audience"), "unexpected message: {msg}");
}

#[tokio::test]
async fn verify_token_rejects_non_service_account_identity() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");
    mount_review(
        &server,
        json!({
            "authenticated": true,
            "audiences": [AUDIENCE],
            "user": { "username": "oidc:alice@example.com", "groups": ["system:authenticated"] }
        }),
    )
    .await;

    let v = make_verifier(&server, &token_file).await;
    let msg = expect_verification_failure(&v).await;
    assert!(
        msg.contains("not a Kubernetes service account"),
        "unexpected message: {msg}"
    );
}

#[tokio::test]
async fn verify_token_rejects_service_account_username_without_group() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");
    // A username that merely looks like a SA (e.g. from an unprefixed OIDC claim) is not enough.
    mount_review(
        &server,
        json!({
            "authenticated": true,
            "audiences": [AUDIENCE],
            "user": { "username": "system:serviceaccount:ns:sa", "groups": ["system:authenticated"] }
        }),
    )
    .await;

    let v = make_verifier(&server, &token_file).await;
    let msg = expect_verification_failure(&v).await;
    assert!(
        msg.contains("not a Kubernetes service account"),
        "unexpected message: {msg}"
    );
}

#[tokio::test]
async fn verify_token_accepts_non_service_account_when_not_required() {
    let server = MockServer::start().await;
    let token_file = write_sa_token_file("sa-token");
    mount_review(
        &server,
        json!({
            "authenticated": true,
            "audiences": [AUDIENCE],
            "user": { "username": "oidc:alice@example.com" }
        }),
    )
    .await;

    let mut v = K8sTokenReviewVerifier::builder()
        .api_server_url(server.uri())
        .cluster_issuer(CLUSTER_ISSUER)
        .token_file(token_file.clone())
        .require_service_account(false)
        .build();
    v.initialize().await.unwrap();

    let claims = v.verify_token(AUDIENCE, SUBJECT_TOKEN).await.unwrap();
    assert_eq!(claims.sub, "oidc:alice@example.com");
    assert!(!claims.custom.contains_key(K8S_UID_CLAIM));
}
