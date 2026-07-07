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

pub mod mem;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use bon::Builder;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;

#[async_trait]
pub trait ResourceStore: Send + Sync {
    async fn resolve_mapping(
        &self,
        client_identifier: &str,
        participant_context: &str,
    ) -> Result<Option<MappingPair>, ResourceError>;

    async fn save_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError>;
    async fn update_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError>;
    async fn remove_mapping(&self, client_identifier: &str, participant_context: &str) -> Result<(), ResourceError>;
    async fn remove_mappings_for(&self, client_identifier: &str) -> Result<(), ResourceError>;

    /// Persists all `mappings` atomically: either every mapping is saved or none is.
    async fn save_scope_mappings(&self, mappings: Vec<ScopeMapping>) -> Result<(), ResourceError>;
    async fn update_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError>;
    async fn remove_scope_mapping(&self, scope: &str) -> Result<(), ResourceError>;

    async fn list_mappings(&self) -> Result<Vec<ResourceMapping>, ResourceError>;
    async fn list_scope_mappings(&self) -> Result<Vec<ScopeMapping>, ResourceError>;
}

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Mapping not found for client: {0}")]
    NotFound(String),

    #[error("Mapping already exists for client: {0}")]
    Conflict(String),

    #[error("Scope claim key conflict: {0}")]
    ClaimConflict(String),

    #[error("Reserved JWT claim key used in scope mapping: {0}")]
    ReservedClaim(String),
}

const RESERVED_CLAIMS: &[&str] = &["sub", "iss", "aud", "exp", "iat", "nbf", "act", "jti"];

fn validate_scope_claims(claims: &Map<String, Value>) -> Result<(), ResourceError> {
    for key in claims.keys() {
        if RESERVED_CLAIMS.contains(&key.as_str()) {
            return Err(ResourceError::ReservedClaim(key.clone()));
        }
    }
    Ok(())
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMapping {
    pub client_identifier: String,
    pub participant_context: String,
    pub scopes: HashSet<String>,
    /// Permitted audiences for issued tokens. Empty means only the global server
    /// default audience is valid; callers may not request an alternative.
    #[builder(default)]
    #[serde(default)]
    pub audiences: HashSet<String>,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeMapping {
    pub scope: String,
    pub claims: Map<String, Value>,
}

pub struct MappingPair {
    pub resource_mapping: ResourceMapping,
    pub scope_mappings: HashMap<String, ScopeMapping>,
}

#[derive(Builder)]
pub struct ResourceService {
    store: Arc<dyn ResourceStore>,
}

pub struct VerificationResult {
    pub verified: bool,
    pub claims: HashMap<String, Value>,
    /// Propagated from the matching `ResourceMapping.audiences`.
    pub audiences: HashSet<String>,
}

impl ResourceService {
    pub async fn verify(
        &self,
        client_identifier: &str,
        participant_context: &str,
        scopes: Vec<String>,
    ) -> Result<VerificationResult, ResourceError> {
        let Some(pair) = self
            .store
            .resolve_mapping(client_identifier, participant_context)
            .await?
        else {
            return Ok(VerificationResult {
                verified: false,
                claims: HashMap::new(),
                audiences: HashSet::new(),
            });
        };
        if !scopes.iter().all(|s| pair.resource_mapping.scopes.contains(s)) {
            return Ok(VerificationResult {
                verified: false,
                claims: HashMap::new(),
                audiences: HashSet::new(),
            });
        }
        let mut claims: HashMap<String, Value> = HashMap::new();
        for s in &scopes {
            if let Some(sm) = pair.scope_mappings.get(s) {
                for (k, v) in &sm.claims {
                    match claims.get(k) {
                        Some(Value::String(existing)) => {
                            if let Value::String(new_val) = v {
                                claims.insert(k.clone(), Value::String(format!("{existing} {new_val}")));
                            } else {
                                return Err(ResourceError::ClaimConflict(format!(
                                    "claim key '{k}' has conflicting types across scopes"
                                )));
                            }
                        }
                        Some(_) => {
                            return Err(ResourceError::ClaimConflict(format!(
                                "claim key '{k}' is defined by multiple requested scopes"
                            )));
                        }
                        None => {
                            claims.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
        }
        Ok(VerificationResult {
            verified: true,
            claims,
            audiences: pair.resource_mapping.audiences.clone(),
        })
    }

    pub async fn save(&self, mapping: ResourceMapping) -> Result<(), ResourceError> {
        self.store.save_mapping(mapping).await
    }

    pub async fn update(&self, mapping: ResourceMapping) -> Result<(), ResourceError> {
        self.store.update_mapping(mapping).await
    }

    pub async fn remove(&self, client_id: &str, context: &str) -> Result<(), ResourceError> {
        self.store.remove_mapping(client_id, context).await
    }

    pub async fn remove_for(&self, client_id: &str) -> Result<(), ResourceError> {
        self.store.remove_mappings_for(client_id).await
    }

    /// Validates and persists all `mappings` atomically. If any mapping fails
    /// validation, none is persisted.
    pub async fn save_scope_mappings(&self, mappings: Vec<ScopeMapping>) -> Result<(), ResourceError> {
        for mapping in &mappings {
            validate_scope_claims(&mapping.claims)?;
        }
        self.store.save_scope_mappings(mappings).await
    }

    pub async fn update_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError> {
        validate_scope_claims(&mapping.claims)?;
        self.store.update_scope_mapping(mapping).await
    }

    pub async fn delete_scope_mapping(&self, scope: &str) -> Result<(), ResourceError> {
        self.store.remove_scope_mapping(scope).await
    }

    pub async fn list_mappings(&self) -> Result<Vec<ResourceMapping>, ResourceError> {
        self.store.list_mappings().await
    }

    pub async fn list_scope_mappings(&self) -> Result<Vec<ScopeMapping>, ResourceError> {
        self.store.list_scope_mappings().await
    }
}
