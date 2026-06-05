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

//! End-to-end tests for the RFC 8414 authorization server metadata endpoint.

use crate::fixtures::jwtlet::ensure_jwtlet_deployed;
use serde_json::Value;

// Must match the top-level `issuer` value in jwtlet-config.yaml.
const ISSUER: &str = "http://jwtlet.vault-e2e-test.svc.cluster.local";

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_authorization_server_metadata() -> anyhow::Result<()> {
    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/.well-known/oauth-authorization-server",
            jwtlet.token_exchange_port
        ))
        .send()
        .await?;
    assert!(resp.status().is_success(), "metadata fetch failed: {}", resp.status());

    let body: Value = resp.json().await?;

    assert_eq!(body["issuer"].as_str(), Some(ISSUER), "unexpected issuer");
    assert_eq!(
        body["token_endpoint"].as_str(),
        Some(format!("{ISSUER}/token").as_str()),
        "unexpected token_endpoint"
    );
    assert_eq!(
        body["jwks_uri"].as_str(),
        Some(format!("{ISSUER}/.well-known/jwks.json").as_str()),
        "unexpected jwks_uri"
    );
    assert_eq!(
        body["grant_types_supported"],
        serde_json::json!(["urn:ietf:params:oauth:grant-type:token-exchange"]),
        "unexpected grant_types_supported"
    );
    assert_eq!(
        body["token_endpoint_auth_methods_supported"],
        serde_json::json!(["none"]),
        "unexpected token_endpoint_auth_methods_supported"
    );

    Ok(())
}

#[tokio::test]
#[cfg_attr(not(feature = "e2e"), ignore)]
async fn test_jwks_endpoint_returns_keys() -> anyhow::Result<()> {
    crate::utils::verify_e2e_setup().await?;

    let jwtlet = ensure_jwtlet_deployed().await?;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/.well-known/jwks.json",
            jwtlet.token_exchange_port
        ))
        .send()
        .await?;
    assert!(resp.status().is_success(), "JWKS fetch failed: {}", resp.status());

    let jwks: jsonwebtoken::jwk::JwkSet = resp.json().await?;
    assert!(!jwks.keys.is_empty(), "JWKS contains no keys");

    // Every advertised key must carry a kid so issued tokens can reference it.
    for jwk in &jwks.keys {
        assert!(
            jwk.common.key_id.as_deref().is_some_and(|k| !k.is_empty()),
            "JWKS key is missing a kid"
        );
    }

    Ok(())
}
