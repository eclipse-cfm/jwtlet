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

#[cfg(test)]
mod tests;

use crate::resource::{ResourceError, ResourceService};
use bon::Builder;
use chrono::Utc;
use dsdk_facet_core::context::ParticipantContext;
use dsdk_facet_core::jwt::{JwtGenerationError, JwtGenerator, JwtVerificationError, JwtVerifier, TokenClaims};
use serde_json::json;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Builder)]
pub struct TokenExchangeService {
    #[builder(into)]
    client_audience: String,
    #[builder(into)]
    audience: String,
    #[builder(into)]
    issuer: String,
    #[builder(into, default = "jwtlet_pc")]
    jwtlet_participant_context: String,
    #[builder(default = 3600)]
    token_ttl_secs: i64,
    verifier: Box<dyn JwtVerifier>,
    resource_service: ResourceService,
    generator: Box<dyn JwtGenerator>,
}

impl TokenExchangeService {
    pub fn token_ttl_secs(&self) -> i64 {
        self.token_ttl_secs
    }

    pub async fn exchange_token(
        &self,
        participant_context: &str,
        scopes: Vec<String>,
        auth_token: &str,
        audience: Option<String>,
    ) -> Result<String, ExchangeError> {
        let client_claims = self
            .verifier
            .verify_token(self.client_audience.as_str(), auth_token)
            .await?;
        let client_id = client_claims.sub.as_str();

        let verification = match self
            .resource_service
            .verify(client_id, participant_context, scopes)
            .await
        {
            Ok(r) if r.verified => r,
            Ok(_) => return Err(ExchangeError::Unauthorized),
            Err(ResourceError::ClaimConflict(msg)) => return Err(ExchangeError::ScopeConflict(msg)),
            Err(e) => return Err(ExchangeError::ServiceError(e)),
        };

        let aud = resolve_audience(audience, &verification.audiences, &self.audience)?;

        let mut custom = serde_json::Map::new();
        custom.extend(verification.claims.into_iter().map(|(k, v)| (k, v)));
        custom.insert(
            "act".to_string(),
            json!({
                "sub": client_claims.sub,
                "iss": client_claims.iss,
            }),
        );

        let now = Utc::now().timestamp();
        let participant_claims = TokenClaims::builder()
            .sub(participant_context)
            .iss(self.issuer.as_str())
            .aud(aud.as_str())
            .iat(now)
            .nbf(now)
            .exp(now + self.token_ttl_secs)
            .custom(custom)
            .build();

        let jwtlet_pc = &ParticipantContext::builder()
            .id(self.jwtlet_participant_context.clone())
            .build();
        let token = self.generator.generate_token(jwtlet_pc, participant_claims).await?;
        Ok(token)
    }
}

/// Resolves the audience for the issued token.
///
/// - No requested audience + empty allowlist -> global default.
/// - No requested audience + non-empty allowlist -> only valid if default is in the allowlist.
/// - Requested audience + empty allowlist -> only the global default is valid.
/// - Requested audience + non-empty allowlist -> must be present in the set.
fn resolve_audience(
    requested: Option<String>,
    allowed: &HashSet<String>,
    default: &str,
) -> Result<String, ExchangeError> {
    match requested {
        None if allowed.is_empty() => Ok(default.to_string()),
        None if allowed.contains(default) => Ok(default.to_string()),
        None => Err(ExchangeError::Unauthorized),
        Some(req) if allowed.is_empty() && req == default => Ok(req),
        Some(_) if allowed.is_empty() => Err(ExchangeError::Unauthorized),
        Some(req) if allowed.contains(&req) => Ok(req),
        Some(_) => Err(ExchangeError::Unauthorized),
    }
}

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("Token verification failed: {0}")]
    TokenVerification(#[from] JwtVerificationError),

    #[error("Unauthorized: client does not have the required scopes")]
    Unauthorized,

    #[error("Service error: {0}")]
    ServiceError(ResourceError),

    #[error("Scope conflict: {0}")]
    ScopeConflict(String),

    #[error("Token generation failed: {0}")]
    Generation(#[from] JwtGenerationError),
}

impl From<ResourceError> for ExchangeError {
    fn from(e: ResourceError) -> Self {
        ExchangeError::ServiceError(e)
    }
}
