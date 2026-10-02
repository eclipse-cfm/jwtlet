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
use jwtlet_core::resource::ResourceError;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManagementApiError {
    #[error("Path parameters do not match request body")]
    PathMismatch,
    #[error(transparent)]
    Resource(#[from] ResourceError),
}

impl IntoResponse for ManagementApiError {
    fn into_response(self) -> Response {
        match self {
            ManagementApiError::PathMismatch => StatusCode::BAD_REQUEST.into_response(),
            ManagementApiError::Resource(ResourceError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
            ManagementApiError::Resource(ResourceError::Conflict(_)) => StatusCode::CONFLICT.into_response(),
            ManagementApiError::Resource(ResourceError::ReservedClaim(ref key)) => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Claim key '{key}' is reserved and cannot be set via scope mapping")})),
            )
                .into_response(),
            ManagementApiError::Resource(ResourceError::InvalidMapping(ref msg)) => {
                (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
            }
            ManagementApiError::Resource(ResourceError::ClaimConflict(_)) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            ref e @ ManagementApiError::Resource(ResourceError::DatabaseError(_)) => {
                tracing::error!("Storage error: {e}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
