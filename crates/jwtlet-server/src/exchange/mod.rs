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

mod error;
#[cfg(test)]
mod tests;

use crate::exchange::error::ExchangeApiError;
use axum::{
    Json,
    extract::{Form, State},
    http::StatusCode,
    response::IntoResponse,
};
use dsdk_facet_core::jwt::JwkSetProvider;
use jwtlet_core::token::TokenExchangeService;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ISSUED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// RFC 8693 token exchange request (form-encoded).
#[derive(Deserialize)]
pub struct TokenExchangeForm {
    grant_type: String,
    subject_token: String,
    /// RFC 8693 required parameter identifying the type of `subject_token`.
    subject_token_type: String,
    /// Identifies the participant context the caller is requesting a token for.
    resource: String,
    #[serde(default)]
    scope: Option<String>,
    /// Optional RFC 8693 audience parameter. Must be present in the mapping's
    /// audience allowlist; falls back to the server default when absent.
    #[serde(default)]
    audience: Option<String>,
}

/// RFC 8693 token exchange response.
#[derive(Serialize)]
pub struct TokenExchangeResponse {
    access_token: String,
    issued_token_type: &'static str,
    token_type: &'static str,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

pub async fn get_swk_set(State(resolver): State<Arc<dyn JwkSetProvider>>) -> impl IntoResponse {
    Json(resolver.jwk_set().await)
}

pub async fn token_exchange(
    State(service): State<Arc<TokenExchangeService>>,
    Form(form): Form<TokenExchangeForm>,
) -> Result<(StatusCode, Json<TokenExchangeResponse>), ExchangeApiError> {
    if form.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
        return Err(ExchangeApiError::UnsupportedGrantType(form.grant_type));
    }

    if form.subject_token_type != ISSUED_TOKEN_TYPE {
        return Err(ExchangeApiError::UnsupportedTokenType(form.subject_token_type));
    }

    let scopes: Vec<String> = form
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_string)
        .collect();

    let token = service
        .exchange_token(&form.resource, scopes, &form.subject_token, form.audience)
        .await?;

    Ok((
        StatusCode::OK,
        Json(TokenExchangeResponse {
            access_token: token,
            issued_token_type: ISSUED_TOKEN_TYPE,
            token_type: "Bearer",
            expires_in: service.token_ttl_secs(),
            scope: form.scope,
        }),
    ))
}
