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

use super::{MappingPair, ResourceError, ResourceMapping, ResourceStore, ScopeMapping};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;

struct InnerStore {
    entries: HashMap<(String, String), ResourceMapping>,
    scope_mappings: HashMap<String, ScopeMapping>,
}

/// In-memory resource store for testing and development.
pub struct MemoryResourceStore {
    store: RwLock<InnerStore>,
}

impl MemoryResourceStore {
    pub fn new() -> Self {
        Self {
            store: RwLock::new(InnerStore {
                entries: HashMap::new(),
                scope_mappings: HashMap::new(),
            }),
        }
    }
}

impl Default for MemoryResourceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ResourceStore for MemoryResourceStore {
    async fn resolve_mapping(
        &self,
        client_identifier: &str,
        participant_context: &str,
    ) -> Result<Option<MappingPair>, ResourceError> {
        let store = self.store.read().await;
        let Some(resource_mapping) = store
            .entries
            .get(&(client_identifier.to_string(), participant_context.to_string()))
            .cloned()
        else {
            return Ok(None);
        };
        let scope_mappings = resource_mapping
            .scopes
            .iter()
            .filter_map(|s| store.scope_mappings.get(s).map(|m| (s.clone(), m.clone())))
            .collect();
        Ok(Some(MappingPair {
            resource_mapping,
            scope_mappings,
        }))
    }

    async fn save_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError> {
        let mut store = self.store.write().await;
        let key = (mapping.client_identifier.clone(), mapping.participant_context.clone());
        if store.entries.contains_key(&key) {
            return Err(ResourceError::Conflict(mapping.client_identifier.clone()));
        }
        store.entries.insert(key, mapping);
        Ok(())
    }

    async fn update_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError> {
        let mut store = self.store.write().await;
        let key = (mapping.client_identifier.clone(), mapping.participant_context.clone());
        if !store.entries.contains_key(&key) {
            return Err(ResourceError::NotFound(mapping.client_identifier.clone()));
        }
        store.entries.insert(key, mapping);
        Ok(())
    }

    async fn remove_mapping(&self, client_identifier: &str, participant_context: &str) -> Result<(), ResourceError> {
        let mut store = self.store.write().await;
        store
            .entries
            .remove(&(client_identifier.to_string(), participant_context.to_string()));
        Ok(())
    }

    async fn remove_mappings_for(&self, client_identifier: &str) -> Result<(), ResourceError> {
        let mut store = self.store.write().await;
        store.entries.retain(|(client_id, _), _| client_id != client_identifier);
        Ok(())
    }

    async fn save_scope_mappings(&self, mappings: Vec<ScopeMapping>) -> Result<(), ResourceError> {
        // Holding the write lock for the whole batch makes the insert atomic.
        let mut store = self.store.write().await;
        for mapping in mappings {
            store.scope_mappings.insert(mapping.scope.clone(), mapping);
        }
        Ok(())
    }

    async fn update_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError> {
        let mut store = self.store.write().await;
        if !store.scope_mappings.contains_key(&mapping.scope) {
            return Err(ResourceError::NotFound(mapping.scope.clone()));
        }
        store.scope_mappings.insert(mapping.scope.clone(), mapping);
        Ok(())
    }

    async fn remove_scope_mapping(&self, scope: &str) -> Result<(), ResourceError> {
        let mut store = self.store.write().await;
        store.scope_mappings.remove(scope);
        Ok(())
    }

    async fn list_mappings(&self) -> Result<Vec<ResourceMapping>, ResourceError> {
        let store = self.store.read().await;
        Ok(store.entries.values().cloned().collect())
    }

    async fn list_scope_mappings(&self) -> Result<Vec<ScopeMapping>, ResourceError> {
        let store = self.store.read().await;
        Ok(store.scope_mappings.values().cloned().collect())
    }
}
