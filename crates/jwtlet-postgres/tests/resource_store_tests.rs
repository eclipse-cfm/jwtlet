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

#![allow(clippy::unwrap_used)]

use jwtlet_core::resource::{ResourceMapping, ResourceStore, ScopeMapping};
use jwtlet_postgres::PostgresResourceStore;
use serde_json::{Map, Value, json};
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use tokio::time::Duration;

#[tokio::test]
async fn initialize_idempotent() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);

    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
    store.initialize().await.unwrap();
}

#[tokio::test]
async fn save_and_resolve_mapping() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let mapping = resource_mapping("client1", "ctx1", &["read", "write"]);
    store.save_mapping(mapping.clone()).await.unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(pair.resource_mapping.client_identifier, "client1");
    assert_eq!(pair.resource_mapping.participant_context, "ctx1");
    assert_eq!(
        pair.resource_mapping.scopes,
        HashSet::from(["read".to_string(), "write".to_string()])
    );
}

#[tokio::test]
async fn save_mapping_conflict() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let mapping = resource_mapping("client1", "ctx1", &["read"]);
    store.save_mapping(mapping.clone()).await.unwrap();

    let err = store.save_mapping(mapping).await.unwrap_err();
    assert!(matches!(err, jwtlet_core::resource::ResourceError::Conflict(_)));
}

#[tokio::test]
async fn resolve_mapping_not_found() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let result = store.resolve_mapping("nonexistent", "ctx1").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn resolve_mapping_wrong_context_not_found() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();

    let result = store.resolve_mapping("client1", "ctx2").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn update_mapping() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();

    let updated = resource_mapping("client1", "ctx1", &["read", "write", "delete"]);
    store.update_mapping(updated).await.unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(pair.resource_mapping.scopes.len(), 3);
    assert!(pair.resource_mapping.scopes.contains("delete"));
}

#[tokio::test]
async fn update_mapping_not_found() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let err = store
        .update_mapping(resource_mapping("nonexistent", "ctx1", &["read"]))
        .await
        .unwrap_err();
    assert!(matches!(err, jwtlet_core::resource::ResourceError::NotFound(_)));
}

#[tokio::test]
async fn remove_mapping() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();

    store.remove_mapping("client1", "ctx1").await.unwrap();

    let result = store.resolve_mapping("client1", "ctx1").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn remove_mapping_nonexistent_is_noop() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store.remove_mapping("nonexistent", "ctx1").await.unwrap();
}

#[tokio::test]
async fn remove_mappings_for_client() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();
    store
        .save_mapping(resource_mapping("client1", "ctx2", &["write"]))
        .await
        .unwrap();
    store
        .save_mapping(resource_mapping("client1", "ctx3", &["delete"]))
        .await
        .unwrap();

    store.remove_mappings_for("client1").await.unwrap();

    assert!(store.resolve_mapping("client1", "ctx1").await.unwrap().is_none());
    assert!(store.resolve_mapping("client1", "ctx2").await.unwrap().is_none());
    assert!(store.resolve_mapping("client1", "ctx3").await.unwrap().is_none());
}

#[tokio::test]
async fn remove_mappings_for_client_does_not_affect_other_clients() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();
    store
        .save_mapping(resource_mapping("client2", "ctx1", &["write"]))
        .await
        .unwrap();

    store.remove_mappings_for("client1").await.unwrap();

    assert!(store.resolve_mapping("client1", "ctx1").await.unwrap().is_none());
    assert!(store.resolve_mapping("client2", "ctx1").await.unwrap().is_some());
}

#[tokio::test]
async fn list_mappings_empty() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let mappings = store.list_mappings().await.unwrap();
    assert!(mappings.is_empty());
}

#[tokio::test]
async fn list_mappings_returns_all() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();
    store
        .save_mapping(resource_mapping("client2", "ctx1", &["write"]))
        .await
        .unwrap();
    store
        .save_mapping(resource_mapping("client1", "ctx2", &["delete"]))
        .await
        .unwrap();

    let mappings = store.list_mappings().await.unwrap();
    assert_eq!(mappings.len(), 3);

    let clients: HashSet<String> = mappings.iter().map(|m| m.client_identifier.clone()).collect();
    assert!(clients.contains("client1"));
    assert!(clients.contains("client2"));
}

#[tokio::test]
async fn list_mappings_reflects_updates() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();
    store
        .save_mapping(resource_mapping("client2", "ctx1", &["write"]))
        .await
        .unwrap();

    store.remove_mapping("client1", "ctx1").await.unwrap();

    let mappings = store.list_mappings().await.unwrap();
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].client_identifier, "client2");
}

#[tokio::test]
async fn resolve_mapping_preserves_audiences() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let mapping = resource_mapping_with_audiences("client1", "ctx1", &["read"], &["aud1", "aud2"]);
    store.save_mapping(mapping).await.unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(
        pair.resource_mapping.audiences,
        HashSet::from(["aud1".to_string(), "aud2".to_string()])
    );
}

#[tokio::test]
async fn update_mapping_replaces_audiences() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping_with_audiences("client1", "ctx1", &["read"], &["aud1"]))
        .await
        .unwrap();

    let updated = resource_mapping_with_audiences("client1", "ctx1", &["read"], &["aud2", "aud3"]);
    store.update_mapping(updated).await.unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(
        pair.resource_mapping.audiences,
        HashSet::from(["aud2".to_string(), "aud3".to_string()])
    );
}

#[tokio::test]
async fn save_scope_mapping() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let sm = scope_mapping("read", claims(&[("role", json!("viewer"))]));
    store.save_scope_mapping(sm).await.unwrap();

    let all = store.list_scope_mappings().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].scope, "read");
    assert_eq!(all[0].claims["role"], json!("viewer"));
}

#[tokio::test]
async fn save_scope_mapping_is_upsert() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_scope_mapping(scope_mapping("read", claims(&[("role", json!("viewer"))])))
        .await
        .unwrap();

    // Save again with different claims — should overwrite, not error.
    store
        .save_scope_mapping(scope_mapping("read", claims(&[("role", json!("editor"))])))
        .await
        .unwrap();

    let all = store.list_scope_mappings().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].claims["role"], json!("editor"));
}

#[tokio::test]
async fn update_scope_mapping() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_scope_mapping(scope_mapping("read", claims(&[("role", json!("viewer"))])))
        .await
        .unwrap();

    store
        .update_scope_mapping(scope_mapping(
            "read",
            claims(&[("role", json!("editor")), ("level", json!(2))]),
        ))
        .await
        .unwrap();

    let all = store.list_scope_mappings().await.unwrap();
    assert_eq!(all[0].claims["role"], json!("editor"));
    assert_eq!(all[0].claims["level"], json!(2));
}

#[tokio::test]
async fn update_scope_mapping_not_found() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let err = store
        .update_scope_mapping(scope_mapping("nonexistent", claims(&[])))
        .await
        .unwrap_err();
    assert!(matches!(err, jwtlet_core::resource::ResourceError::NotFound(_)));
}

#[tokio::test]
async fn remove_scope_mapping() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_scope_mapping(scope_mapping("read", claims(&[("role", json!("viewer"))])))
        .await
        .unwrap();

    store.remove_scope_mapping("read").await.unwrap();

    let all = store.list_scope_mappings().await.unwrap();
    assert!(all.is_empty());
}

#[tokio::test]
async fn remove_scope_mapping_nonexistent_is_noop() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store.remove_scope_mapping("nonexistent").await.unwrap();
}

#[tokio::test]
async fn list_scope_mappings_empty() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let all = store.list_scope_mappings().await.unwrap();
    assert!(all.is_empty());
}

#[tokio::test]
async fn list_scope_mappings_returns_all() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_scope_mapping(scope_mapping("read", claims(&[("role", json!("viewer"))])))
        .await
        .unwrap();
    store
        .save_scope_mapping(scope_mapping("write", claims(&[("role", json!("editor"))])))
        .await
        .unwrap();
    store
        .save_scope_mapping(scope_mapping("admin", claims(&[("role", json!("admin"))])))
        .await
        .unwrap();

    let all = store.list_scope_mappings().await.unwrap();
    assert_eq!(all.len(), 3);

    let scopes: HashSet<String> = all.iter().map(|s| s.scope.clone()).collect();
    assert!(scopes.contains("read"));
    assert!(scopes.contains("write"));
    assert!(scopes.contains("admin"));
}

#[tokio::test]
async fn resolve_mapping_returns_matching_scope_mappings() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_scope_mapping(scope_mapping("read", claims(&[("can_read", json!(true))])))
        .await
        .unwrap();
    store
        .save_scope_mapping(scope_mapping("write", claims(&[("can_write", json!(true))])))
        .await
        .unwrap();
    store
        .save_scope_mapping(scope_mapping("admin", claims(&[("is_admin", json!(true))])))
        .await
        .unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();

    // Only "read" and "write" scope mappings should be returned — not "admin".
    assert_eq!(pair.scope_mappings.len(), 2);
    assert!(pair.scope_mappings.contains_key("read"));
    assert!(pair.scope_mappings.contains_key("write"));
    assert!(!pair.scope_mappings.contains_key("admin"));

    assert_eq!(pair.scope_mappings["read"].claims["can_read"], json!(true));
    assert_eq!(pair.scope_mappings["write"].claims["can_write"], json!(true));
}

#[tokio::test]
async fn resolve_mapping_with_no_scope_mappings_defined() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    // Resource mapping resolved fine; no scope mappings present.
    assert!(pair.scope_mappings.is_empty());
    assert_eq!(
        pair.resource_mapping.scopes,
        HashSet::from(["read".to_string(), "write".to_string()])
    );
}

#[tokio::test]
async fn resolve_mapping_with_partial_scope_mappings() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    // Only define scope mapping for "read", not "write".
    store
        .save_scope_mapping(scope_mapping("read", claims(&[("role", json!("viewer"))])))
        .await
        .unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert_eq!(pair.scope_mappings.len(), 1);
    assert!(pair.scope_mappings.contains_key("read"));
}

#[tokio::test]
async fn resolve_mapping_scope_mapping_with_complex_claims() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let complex_claims = claims(&[
        ("string_claim", json!("value")),
        ("number_claim", json!(42)),
        ("bool_claim", json!(true)),
        ("array_claim", json!(["a", "b", "c"])),
        ("nested_claim", json!({"key": "val"})),
    ]);

    store
        .save_scope_mapping(scope_mapping("read", complex_claims.clone()))
        .await
        .unwrap();
    store
        .save_mapping(resource_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    let retrieved = &pair.scope_mappings["read"].claims;

    assert_eq!(retrieved["string_claim"], json!("value"));
    assert_eq!(retrieved["number_claim"], json!(42));
    assert_eq!(retrieved["bool_claim"], json!(true));
    assert_eq!(retrieved["array_claim"], json!(["a", "b", "c"]));
    assert_eq!(retrieved["nested_claim"], json!({"key": "val"}));
}

// ── Concurrency ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_save_mappings() {
    let (pool, _container) = setup_postgres().await;
    let store = Arc::new(PostgresResourceStore::new(pool));
    store.initialize().await.unwrap();

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .save_mapping(resource_mapping(
                        &format!("client{}", i),
                        &format!("ctx{}", i),
                        &["read"],
                    ))
                    .await
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    let all = store.list_mappings().await.unwrap();
    assert_eq!(all.len(), 10);
}

#[tokio::test]
async fn concurrent_save_and_resolve() {
    let (pool, _container) = setup_postgres().await;
    let store = Arc::new(PostgresResourceStore::new(pool));
    store.initialize().await.unwrap();

    // Pre-populate some mappings.
    for i in 0..5 {
        store
            .save_mapping(resource_mapping(&format!("client{}", i), "ctx1", &["read"]))
            .await
            .unwrap();
    }

    // Concurrently resolve all of them.
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let store = store.clone();
            tokio::spawn(async move { store.resolve_mapping(&format!("client{}", i), "ctx1").await })
        })
        .collect();

    for handle in handles {
        let result = handle.await.unwrap().unwrap();
        assert!(result.is_some());
    }
}

#[tokio::test]
async fn save_mapping_with_long_identifiers() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    let long_client = "c".repeat(255);
    let long_context = "x".repeat(255);
    let long_scope = "s".repeat(255);

    store
        .save_mapping(resource_mapping(&long_client, &long_context, &[&long_scope]))
        .await
        .unwrap();

    let pair = store
        .resolve_mapping(&long_client, &long_context)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pair.resource_mapping.client_identifier, long_client);
    assert!(pair.resource_mapping.scopes.contains(&long_scope));
}

#[tokio::test]
async fn save_mapping_with_empty_scopes() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "ctx1", &[]))
        .await
        .unwrap();

    let pair = store.resolve_mapping("client1", "ctx1").await.unwrap().unwrap();
    assert!(pair.resource_mapping.scopes.is_empty());
    assert!(pair.scope_mappings.is_empty());
}

#[tokio::test]
async fn multiple_clients_same_context_are_independent() {
    let (pool, _container) = setup_postgres().await;
    let store = PostgresResourceStore::new(pool);
    store.initialize().await.unwrap();

    store
        .save_mapping(resource_mapping("client1", "shared-ctx", &["read"]))
        .await
        .unwrap();
    store
        .save_mapping(resource_mapping("client2", "shared-ctx", &["write"]))
        .await
        .unwrap();

    let pair1 = store.resolve_mapping("client1", "shared-ctx").await.unwrap().unwrap();
    let pair2 = store.resolve_mapping("client2", "shared-ctx").await.unwrap().unwrap();

    assert!(pair1.resource_mapping.scopes.contains("read"));
    assert!(!pair1.resource_mapping.scopes.contains("write"));
    assert!(pair2.resource_mapping.scopes.contains("write"));
    assert!(!pair2.resource_mapping.scopes.contains("read"));
}

async fn setup_postgres() -> (PgPool, ContainerAsync<Postgres>) {
    let container = Postgres::default().start().await.unwrap();
    let connection_string = format!(
        "postgresql://postgres:postgres@127.0.0.1:{}/postgres",
        container.get_host_port_ipv4(5432).await.unwrap()
    );
    let pool = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match PgPool::connect(&connection_string).await {
                Ok(pool) => break pool,
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("PostgreSQL failed to start"));
    (pool, container)
}

fn resource_mapping(client_id: &str, context: &str, scopes: &[&str]) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier(client_id.to_string())
        .participant_context(context.to_string())
        .scopes(scopes.iter().map(|s| s.to_string()).collect())
        .build()
}

fn resource_mapping_with_audiences(
    client_id: &str,
    context: &str,
    scopes: &[&str],
    audiences: &[&str],
) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier(client_id.to_string())
        .participant_context(context.to_string())
        .scopes(scopes.iter().map(|s| s.to_string()).collect())
        .audiences(audiences.iter().map(|s| s.to_string()).collect())
        .build()
}

fn scope_mapping(scope: &str, claims: serde_json::Map<String, Value>) -> ScopeMapping {
    ScopeMapping::builder().scope(scope.to_string()).claims(claims).build()
}

fn claims(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}
