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

use axum::{Json, extract::State, response::IntoResponse};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize, Clone)]
pub struct AuthorizationServerMetadata {
    issuer: String,
    token_endpoint: String,
    jwks_uri: String,
    grant_types_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
}

impl AuthorizationServerMetadata {
    pub fn new(issuer: impl Into<String>) -> Self {
        let issuer = issuer.into();
        let token_endpoint = format!("{issuer}/token");
        let jwks_uri = format!("{issuer}/.well-known/jwks.json");
        Self {
            issuer,
            token_endpoint,
            jwks_uri,
            grant_types_supported: vec!["urn:ietf:params:oauth:grant-type:token-exchange"],
            token_endpoint_auth_methods_supported: vec!["none"],
        }
    }
}

pub async fn get_authorization_server_metadata(
    State(meta): State<Arc<AuthorizationServerMetadata>>,
) -> impl IntoResponse {
    Json(meta.as_ref().clone())
}
