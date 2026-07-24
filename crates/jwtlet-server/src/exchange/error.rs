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

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use jwtlet_core::token::ExchangeError;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExchangeApiError {
    #[error("Unsupported grant_type: {0}")]
    UnsupportedGrantType(String),
    #[error("Unsupported subject_token_type: {0}")]
    UnsupportedTokenType(String),
    #[error(transparent)]
    Exchange(#[from] ExchangeError),
}

#[derive(Serialize)]
struct OAuthErrorResponse {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

impl IntoResponse for ExchangeApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            ExchangeApiError::UnsupportedGrantType(_) => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
            ExchangeApiError::UnsupportedTokenType(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            ExchangeApiError::Exchange(ExchangeError::TokenVerification(_)) => {
                (StatusCode::BAD_REQUEST, "invalid_grant")
            }
            ExchangeApiError::Exchange(ExchangeError::Unauthorized) => (StatusCode::FORBIDDEN, "unauthorized_client"),
            ExchangeApiError::Exchange(ExchangeError::ScopeConflict(_)) => (StatusCode::BAD_REQUEST, "invalid_scope"),
            ref e @ ExchangeApiError::Exchange(ExchangeError::ServiceError(_) | ExchangeError::Generation(_)) => {
                tracing::error!("Token exchange internal error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
            }
        };
        (
            status,
            Json(OAuthErrorResponse {
                error,
                error_description: None,
            }),
        )
            .into_response()
    }
}
