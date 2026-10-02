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

mod renewal;

#[cfg(test)]
mod tests;

use JwtVerificationError::VerificationFailed;
use async_trait::async_trait;
use bon::Builder;
use dsdk_facet_core::jwt::{JwtVerificationError, JwtVerifier, TokenClaims};
use renewal::{FileBasedRenewalTrigger, SaTokenRenewer, SaTokenState, TaskHandle};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Map;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

const TOKEN_REVIEW_API: &str = "/apis/authentication.k8s.io/v1/tokenreviews";
const SERVICE_ACCOUNT_USERNAME_PREFIX: &str = "system:serviceaccount:";
const SERVICE_ACCOUNTS_GROUP: &str = "system:serviceaccounts";

/// Custom claim carrying the authenticated identity's K8s UID, when the TokenReview returns one.
pub const K8S_UID_CLAIM: &str = "k8s_uid";

/// Verifies a Kubernetes Service Account JWT using the K8S TokenReview API.
///
/// The verifier authenticates to the K8S API server using the pod's own SA token
/// (typically at `/var/run/secrets/kubernetes.io/serviceaccount/token`).
/// Call [`initialize()`](Self::initialize) before use to load the token and start
/// the background rotation watcher.
#[derive(Builder)]
pub struct K8sTokenReviewVerifier {
    /// Base URL of the K8S API server, e.g. `https://kubernetes.default.svc`
    #[builder(into)]
    api_server_url: String,

    /// Issuer URL for this cluster, used as `iss` in the returned claims.
    #[builder(into)]
    cluster_issuer: String,

    /// Path to the pod's mounted SA token file.
    /// Defaults to the standard in-cluster path.
    #[builder(default = PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token"))]
    token_file: PathBuf,

    #[builder(default = Client::new())]
    client: Client,

    /// When `true` (the default), only Kubernetes service account identities are accepted.
    /// Identities from other API server authenticators (OIDC users, static or bootstrap tokens)
    /// are rejected even when TokenReview reports them as authenticated.
    #[builder(default = true)]
    require_service_account: bool,

    #[builder(skip)]
    state: Option<Arc<RwLock<SaTokenState>>>,

    #[builder(skip)]
    _renewal_handle: Option<TaskHandle>,
}

impl K8sTokenReviewVerifier {
    /// Reads the initial SA token from the configured file and starts a background
    /// task that re-reads and updates the token whenever the kubelet rotates it.
    ///
    /// Must be called before [`JwtVerifier::verify_token`].
    pub async fn initialize(&mut self) -> Result<(), JwtVerificationError> {
        if self.state.is_some() {
            return Ok(());
        }

        let raw = tokio::fs::read_to_string(&self.token_file).await.map_err(|e| {
            VerificationFailed(format!(
                "Failed to read SA token file {}: {e}",
                self.token_file.display()
            ))
        })?;

        let state = Arc::new(RwLock::new(SaTokenState::new(raw.trim().to_string())));

        let trigger = FileBasedRenewalTrigger::new(self.token_file.clone())?;
        let renewer = Arc::new(SaTokenRenewer {
            token_file: self.token_file.clone(),
            state: Arc::clone(&state),
        });
        let handle = renewer.start(Box::new(trigger));

        self.state = Some(state);
        self._renewal_handle = Some(handle);
        Ok(())
    }

    fn ensure_initialized(&self) -> Result<&Arc<RwLock<SaTokenState>>, JwtVerificationError> {
        self.state.as_ref().ok_or_else(|| {
            VerificationFailed("K8sTokenReviewVerifier not initialized; call initialize() first".to_string())
        })
    }

    /// Re-reads the SA token file and updates the shared state.
    ///
    /// Called when the API server returns 401, indicating the cached token was
    /// rotated between the file-watcher event and this request.
    async fn refresh_sa_token(&self) -> Result<String, JwtVerificationError> {
        let raw = tokio::fs::read_to_string(&self.token_file).await.map_err(|e| {
            VerificationFailed(format!(
                "Failed to re-read SA token file {}: {e}",
                self.token_file.display()
            ))
        })?;
        let token = raw.trim().to_string();
        let state = self.ensure_initialized()?;
        state.write().await.token = token.clone();
        Ok(token)
    }

    async fn call_token_review(
        &self,
        sa_token: &str,
        audience: &str,
        subject_token: &str,
    ) -> Result<TokenReviewResponse, (StatusCode, JwtVerificationError)> {
        let request = TokenReviewRequest {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: TokenReviewSpec {
                token: subject_token.to_string(),
                audiences: vec![audience.to_string()],
            },
        };

        let response = self
            .client
            .post(format!("{}{}", self.api_server_url, TOKEN_REVIEW_API))
            .bearer_auth(sa_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                let status = e.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                (status, VerificationFailed(e.to_string()))
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err((
                status,
                VerificationFailed(format!("TokenReview API returned status {status}")),
            ));
        }

        response
            .json()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, VerificationFailed(e.to_string())))
    }
}

#[async_trait]
impl JwtVerifier for K8sTokenReviewVerifier {
    async fn verify_token(&self, audience: &str, token: &str) -> Result<TokenClaims, JwtVerificationError> {
        let sa_token = {
            let state = self.ensure_initialized()?.read().await;
            state.token()
        };

        let review = match self.call_token_review(&sa_token, audience, token).await {
            Ok(r) => r,
            Err((status, _)) if status == StatusCode::UNAUTHORIZED => {
                // Our SA token was rotated — re-read the file and retry once.
                let refreshed = self.refresh_sa_token().await?;
                self.call_token_review(&refreshed, audience, token)
                    .await
                    .map_err(|(_, e)| e)?
            }
            Err((_, e)) => return Err(e),
        };

        if !review.status.authenticated {
            let msg = review
                .status
                .error
                .unwrap_or_else(|| "token not authenticated".to_string());
            return Err(VerificationFailed(msg));
        }

        // Authenticators that are not audience-aware may authenticate a token without honoring the
        // requested audiences; the TokenReview contract requires clients to check the intersection.
        if !review.status.audiences.iter().any(|a| a == audience) {
            return Err(VerificationFailed(format!(
                "TokenReview did not confirm the requested audience '{audience}'"
            )));
        }

        let user = review.status.user.ok_or_else(|| {
            VerificationFailed("TokenReview returned authenticated=true but no user info".to_string())
        })?;

        if self.require_service_account && !user.is_service_account() {
            return Err(VerificationFailed(format!(
                "identity '{}' is not a Kubernetes service account",
                user.username
            )));
        }

        let mut custom = Map::new();
        if let Some(uid) = user.uid.filter(|u| !u.is_empty()) {
            custom.insert(K8S_UID_CLAIM.to_string(), uid.into());
        }

        Ok(TokenClaims {
            sub: user.username,
            iss: self.cluster_issuer.clone(),
            aud: audience.to_string(),
            iat: 0,
            exp: 0,
            nbf: None,
            custom,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenReviewRequest {
    api_version: &'static str,
    kind: &'static str,
    spec: TokenReviewSpec,
}

#[derive(Serialize)]
struct TokenReviewSpec {
    token: String,
    audiences: Vec<String>,
}

#[derive(Deserialize)]
struct TokenReviewResponse {
    status: TokenReviewStatus,
}

#[derive(Deserialize)]
struct TokenReviewStatus {
    authenticated: bool,
    #[serde(default)]
    user: Option<UserInfo>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    audiences: Vec<String>,
}

#[derive(Deserialize)]
struct UserInfo {
    username: String,
    #[serde(default)]
    uid: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

impl UserInfo {
    fn is_service_account(&self) -> bool {
        self.username.starts_with(SERVICE_ACCOUNT_USERNAME_PREFIX)
            && self.groups.iter().any(|g| g == SERVICE_ACCOUNTS_GROUP)
    }
}
