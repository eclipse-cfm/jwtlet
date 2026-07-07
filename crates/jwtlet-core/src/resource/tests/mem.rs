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

use crate::resource::mem::MemoryResourceStore;
use crate::resource::{ResourceError, ResourceMapping, ResourceStore, ScopeMapping};
use serde_json::{Map, Value};
use std::collections::HashSet;

fn scope_mapping(scope: &str) -> ScopeMapping {
    ScopeMapping::builder()
        .scope(scope.to_string())
        .claims(Map::<String, Value>::new())
        .build()
}

fn mapping(client_id: &str, context: &str, scopes: &[&str]) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier(client_id.to_string())
        .participant_context(context.to_string())
        .scopes(scopes.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
        .build()
}

#[tokio::test]
async fn save_and_resolve() {
    let store = MemoryResourceStore::new();
    let m = mapping("client1", "ctx1", &["read", "write"]);

    store.save_mapping(m).await.unwrap();

    let result = store.resolve_mapping("client1", "ctx1").await.unwrap();
    assert!(result.is_some());
    let found = result.unwrap();
    assert_eq!(found.resource_mapping.client_identifier, "client1");
    assert_eq!(found.resource_mapping.participant_context, "ctx1");
    assert!(found.resource_mapping.scopes.contains("read"));
    assert!(found.resource_mapping.scopes.contains("write"));
}

#[tokio::test]
async fn resolve_returns_none_when_not_found() {
    let store = MemoryResourceStore::new();

    let result = store.resolve_mapping("unknown", "ctx1").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn update_replaces_existing() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();

    let updated = mapping("client1", "ctx1", &["read", "write", "admin"]);
    store.update_mapping(updated).await.unwrap();

    let found = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(found.resource_mapping.scopes.len(), 3);
    assert!(found.resource_mapping.scopes.contains("admin"));
}

#[tokio::test]
async fn update_returns_not_found_for_missing_mapping() {
    let store = MemoryResourceStore::new();

    let err = store
        .update_mapping(mapping("ghost", "ctx1", &["read"]))
        .await
        .unwrap_err();
    assert!(matches!(err, ResourceError::NotFound(_)));
}

#[tokio::test]
async fn remove_mapping_deletes_entry() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();

    store.remove_mapping("client1", "ctx1").await.unwrap();

    let result = store.resolve_mapping("client1", "ctx1").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn remove_mappings_for_deletes_all_client_entries() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();
    store
        .save_mapping(mapping("client1", "ctx2", &["write"]))
        .await
        .unwrap();
    store.save_mapping(mapping("client2", "ctx1", &["read"])).await.unwrap();

    store.remove_mappings_for("client1").await.unwrap();

    assert!(store.resolve_mapping("client1", "ctx1").await.unwrap().is_none());
    assert!(store.resolve_mapping("client1", "ctx2").await.unwrap().is_none());
    assert!(store.resolve_mapping("client2", "ctx1").await.unwrap().is_some());
}

#[tokio::test]
async fn save_and_update_scope_mapping() {
    let store = MemoryResourceStore::new();
    store.save_scope_mappings(vec![scope_mapping("read")]).await.unwrap();

    let updated = ScopeMapping::builder()
        .scope("read".to_string())
        .claims({
            let mut m = Map::new();
            m.insert("role".to_string(), Value::String("admin".to_string()));
            m
        })
        .build();
    store.update_scope_mapping(updated).await.unwrap();
}

#[tokio::test]
async fn save_scope_mappings_persists_all_entries() {
    let store = MemoryResourceStore::new();
    store
        .save_scope_mappings(vec![
            scope_mapping("read"),
            scope_mapping("write"),
            scope_mapping("admin"),
        ])
        .await
        .unwrap();

    let all = store.list_scope_mappings().await.unwrap();
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn update_scope_mapping_returns_not_found_for_missing() {
    let store = MemoryResourceStore::new();

    let err = store.update_scope_mapping(scope_mapping("ghost")).await.unwrap_err();
    assert!(matches!(err, ResourceError::NotFound(_)));
}

#[tokio::test]
async fn delete_scope_mapping_removes_entry() {
    let store = MemoryResourceStore::new();
    store.save_scope_mappings(vec![scope_mapping("write")]).await.unwrap();

    store.remove_scope_mapping("write").await.unwrap();

    let err = store.update_scope_mapping(scope_mapping("write")).await.unwrap_err();
    assert!(matches!(err, ResourceError::NotFound(_)));
}

#[tokio::test]
async fn resolve_mapping_includes_registered_scope_mappings() {
    let store = MemoryResourceStore::new();
    store
        .save_mapping(mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();
    store.save_scope_mappings(vec![scope_mapping("read")]).await.unwrap();
    store.save_scope_mappings(vec![scope_mapping("write")]).await.unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(pair.scope_mappings.len(), 2);
    assert!(pair.scope_mappings.contains_key("read"));
    assert!(pair.scope_mappings.contains_key("write"));
}

#[tokio::test]
async fn resolve_mapping_omits_scope_mappings_not_registered() {
    let store = MemoryResourceStore::new();
    store
        .save_mapping(mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();
    store.save_scope_mappings(vec![scope_mapping("read")]).await.unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(pair.scope_mappings.len(), 1);
    assert!(pair.scope_mappings.contains_key("read"));
    assert!(!pair.scope_mappings.contains_key("write"));
}

#[tokio::test]
async fn resolve_mapping_returns_empty_scope_mappings_when_none_registered() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert!(pair.scope_mappings.is_empty());
}

#[tokio::test]
async fn save_mapping_returns_conflict_on_duplicate() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();

    let err = store
        .save_mapping(mapping("client1", "ctx1", &["write"]))
        .await
        .unwrap_err();
    assert!(matches!(err, ResourceError::Conflict(_)));
}

#[tokio::test]
async fn save_mapping_allows_same_client_in_different_contexts() {
    let store = MemoryResourceStore::new();
    store.save_mapping(mapping("client1", "ctx1", &["read"])).await.unwrap();
    store.save_mapping(mapping("client1", "ctx2", &["read"])).await.unwrap();

    assert!(store.resolve_mapping("client1", "ctx1").await.unwrap().is_some());
    assert!(store.resolve_mapping("client1", "ctx2").await.unwrap().is_some());
}
