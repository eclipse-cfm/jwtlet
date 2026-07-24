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

//! End-to-end tests for jwtlet RFC 8693 token exchange.

use crate::fixtures::jwtlet::ensure_jwtlet_deployed;
use serde_json::{Value, json};

const PARTICIPANT_CONTEXT: &str = "test-context";
const SA_NAME: &str = "test-app-sa";
// subject_token audience must match jwtlet's token.client_audience config
const CLIENT_AUDIENCE: &str = "https://kubernetes.default.svc.cluster.local";
// issued token audience, matches token.audience in jwtlet-config.yaml
const TOKEN_AUDIENCE: &str = "jwtlet-e2e";

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_jwtlet_health() -> anyhow::Result<()> {
    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://127.0.0.1:{}/health", jwtlet.token_exchange_port))
        .send()
        .await?;
    assert!(resp.status().is_success(), "health check failed: {}", resp.status());

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_token_exchange() -> anyhow::Result<()> {
    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();

    let token_url = format!("http://127.0.0.1:{}", jwtlet.token_exchange_port);
    let mgmt_url = format!("http://127.0.0.1:{}", jwtlet.management_port);
    let namespace = crate::utils::E2E_NAMESPACE;
    let client_identifier = format!("system:serviceaccount:{namespace}:{SA_NAME}");

    // Get a management SA token for the management API caller
    let mgmt_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;

    // Register the SA -> participant context mapping with an audience allowlist
    let mapping = json!({
        "clientIdentifier": client_identifier,
        "participantContext": PARTICIPANT_CONTEXT,
        "scopes": ["read"],
        "audiences": [TOKEN_AUDIENCE]
    });
    // delete mapping - fire and forget, in case it exists
    client
        .delete(format!(
            "{mgmt_url}/api/v1/mappings/{client_identifier}/{PARTICIPANT_CONTEXT}"
        ))
        .bearer_auth(&mgmt_token)
        .send()
        .await?;
    let resp = client
        .post(format!("{mgmt_url}/api/v1/mappings"))
        .bearer_auth(&mgmt_token)
        .json(&mapping)
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 201, "create mapping failed: {}", resp.status());

    // Get a bounded SA token with the expected audience
    let sa_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;

    // POST /token (RFC 8693 token exchange) — explicitly request the allowed audience
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", sa_token.as_str()),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        ("resource", PARTICIPANT_CONTEXT),
        ("scope", "read"),
        ("audience", TOKEN_AUDIENCE),
    ];
    let resp = client.post(format!("{token_url}/token")).form(&params).send().await?;

    assert!(resp.status().is_success(), "token exchange failed: {}", resp.status());

    let body: Value = resp.json().await?;
    assert!(body["access_token"].is_string(), "missing access_token");
    assert_eq!(body["token_type"].as_str(), Some("Bearer"));
    assert_eq!(
        body["issued_token_type"].as_str(),
        Some("urn:ietf:params:oauth:token-type:jwt")
    );
    assert!(body["expires_in"].is_number(), "missing expires_in");

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_token_exchange_with_scope_mapping() -> anyhow::Result<()> {
    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();

    let token_url = format!("http://127.0.0.1:{}", jwtlet.token_exchange_port);
    let mgmt_url = format!("http://127.0.0.1:{}", jwtlet.management_port);
    let namespace = crate::utils::E2E_NAMESPACE;
    let client_identifier = format!("system:serviceaccount:{namespace}:{SA_NAME}");

    // Get a management SA token for the management API caller
    let mgmt_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;

    // Register the SA -> participant context mapping with an audience allowlist
    let resource_mapping = json!({
        "clientIdentifier": client_identifier,
        "participantContext": PARTICIPANT_CONTEXT,
        "scopes": ["read","write"],
        "audiences": [TOKEN_AUDIENCE]
    });
    // delete mapping - fire and forget, in case it exists
    client
        .delete(format!(
            "{mgmt_url}/api/v1/mappings/{client_identifier}/{PARTICIPANT_CONTEXT}"
        ))
        .bearer_auth(&mgmt_token)
        .send()
        .await?;

    let resp = client
        .post(format!("{mgmt_url}/api/v1/mappings"))
        .bearer_auth(&mgmt_token)
        .json(&resource_mapping)
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 201, "create mapping failed: {}", resp.status());

    // register scope mapping: read -> some-api:read some-other-api:read
    let scope_mapping1 = json!({
        "scope": "read",
        "claims": {
            "scope": "some-api:read some-other-api:read"
        }
    });
    let resp2 = client
        .post(format!("{mgmt_url}/api/v1/scopes"))
        .bearer_auth(&mgmt_token)
        .json(&scope_mapping1)
        .send()
        .await?;
    assert_eq!(
        resp2.status().as_u16(),
        201,
        "create scope mapping failed: {}",
        resp.status()
    );

    // register scope mapping: write -> some-api:write some-other-api:write
    let scope_mapping2 = json!({
        "scope": "write",
        "claims": {
            "scope": "some-api:write some-other-api:write"
        }
    });
    let resp3 = client
        .post(format!("{mgmt_url}/api/v1/scopes"))
        .bearer_auth(&mgmt_token)
        .json(&scope_mapping2)
        .send()
        .await?;
    assert_eq!(
        resp3.status().as_u16(),
        201,
        "create scope mapping failed: {}",
        resp.status()
    );

    // Get a bounded SA token with the expected audience
    let sa_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;

    // POST /token (RFC 8693 token exchange) — explicitly request the allowed audience
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", sa_token.as_str()),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        ("resource", PARTICIPANT_CONTEXT),
        ("scope", "read write"),
        ("audience", TOKEN_AUDIENCE),
    ];
    let resp = client.post(format!("{token_url}/token")).form(&params).send().await?;

    assert!(resp.status().is_success(), "token exchange failed: {}", resp.status());

    let body: Value = resp.json().await?;
    assert!(body["access_token"].is_string(), "missing access_token");
    assert_eq!(body["token_type"].as_str(), Some("Bearer"));
    assert_eq!(
        body["issued_token_type"].as_str(),
        Some("urn:ietf:params:oauth:token-type:jwt")
    );
    assert!(body["expires_in"].is_number(), "missing expires_in");

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_token_exchange_audience_not_in_allowlist() -> anyhow::Result<()> {
    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();
    let token_url = format!("http://127.0.0.1:{}", jwtlet.token_exchange_port);
    let mgmt_url = format!("http://127.0.0.1:{}", jwtlet.management_port);
    let namespace = crate::utils::E2E_NAMESPACE;
    let client_identifier = format!("system:serviceaccount:{namespace}:{SA_NAME}");

    // Ensure the mapping exists with a restricted audience allowlist
    let mgmt_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;
    let mapping = json!({
        "clientIdentifier": client_identifier,
        "participantContext": PARTICIPANT_CONTEXT,
        "scopes": ["read"],
        "audiences": [TOKEN_AUDIENCE]
    });
    let status = client
        .post(format!("{mgmt_url}/api/v1/mappings"))
        .bearer_auth(&mgmt_token)
        .json(&mapping)
        .send()
        .await?
        .status()
        .as_u16();
    assert!(status == 201 || status == 409, "create mapping failed: {status}");

    let sa_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", sa_token.as_str()),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        ("resource", PARTICIPANT_CONTEXT),
        ("scope", "read"),
        ("audience", "https://not-in-allowlist.example.com"),
    ];
    let resp = client.post(format!("{token_url}/token")).form(&params).send().await?;

    assert_eq!(resp.status().as_u16(), 403, "expected 403 for disallowed audience");

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_token_exchange_unauthorized() -> anyhow::Result<()> {
    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();
    let token_url = format!("http://127.0.0.1:{}", jwtlet.token_exchange_port);
    let namespace = crate::utils::E2E_NAMESPACE;

    // Get a valid SA token but request a context with no mapping
    let sa_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;

    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", sa_token.as_str()),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        ("resource", "no-such-context"),
        ("scope", "read"),
    ];
    let resp = client.post(format!("{token_url}/token")).form(&params).send().await?;

    // Expect 403 Forbidden for unmapped context
    assert_eq!(resp.status().as_u16(), 403, "expected 403 for unauthorized context");

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_token_jwks_verification() -> anyhow::Result<()> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();

    let token_url = format!("http://127.0.0.1:{}", jwtlet.token_exchange_port);
    let mgmt_url = format!("http://127.0.0.1:{}", jwtlet.management_port);
    let namespace = crate::utils::E2E_NAMESPACE;
    let client_identifier = format!("system:serviceaccount:{namespace}:{SA_NAME}");

    // Register the SA -> participant context mapping (idempotent — may already exist from another test)
    let mgmt_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;
    let mapping = json!({
        "clientIdentifier": client_identifier,
        "participantContext": PARTICIPANT_CONTEXT,
        "scopes": ["read"],
        "audiences": [TOKEN_AUDIENCE]
    });
    let status = client
        .post(format!("{mgmt_url}/api/v1/mappings"))
        .bearer_auth(&mgmt_token)
        .json(&mapping)
        .send()
        .await?
        .status()
        .as_u16();
    assert!(status == 201 || status == 409, "create mapping failed: {status}");

    // Get a bounded SA token and exchange it for a jwtlet-issued token
    let sa_token = crate::utils::create_service_account_token(SA_NAME, namespace, CLIENT_AUDIENCE)?;
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
        ("subject_token", sa_token.as_str()),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        ("resource", PARTICIPANT_CONTEXT),
        ("scope", "read"),
    ];
    let resp = client.post(format!("{token_url}/token")).form(&params).send().await?;
    assert!(resp.status().is_success(), "token exchange failed: {}", resp.status());
    let body: Value = resp.json().await?;
    let access_token = body["access_token"].as_str().expect("missing access_token").to_string();

    // Fetch the JWKS from the server
    let resp = client.get(format!("{token_url}/.well-known/jwks.json")).send().await?;
    assert!(resp.status().is_success(), "JWKS fetch failed: {}", resp.status());
    let jwks: jsonwebtoken::jwk::JwkSet = resp.json().await?;
    assert!(!jwks.keys.is_empty(), "JWKS contains no keys");

    // Identify the signing key via the token's kid header and verify the signature
    let header = decode_header(&access_token)?;
    let kid = header.kid.expect("issued token has no kid header");
    let jwk = jwks.find(&kid).expect("kid from token not found in JWKS");
    let decoding_key = DecodingKey::from_jwk(jwk)?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[TOKEN_AUDIENCE]);
    let token_data = decode::<Value>(&access_token, &decoding_key, &validation)?;

    assert!(token_data.claims["sub"].is_string(), "missing sub claim");
    assert!(token_data.claims["exp"].is_number(), "missing exp claim");

    Ok(())
}
