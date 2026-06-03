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
use crate::resource::{ResourceError, ResourceMapping, ResourceService, ScopeMapping};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::Arc;

#[tokio::test]
async fn verify_returns_false_when_no_mapping_exists() {
    let service = create_service();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string()])
        .await
        .unwrap();
    assert!(!result.verified);
}

#[tokio::test]
async fn verify_returns_true_when_all_scopes_present() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string(), "write".to_string()])
        .await
        .unwrap();
    assert!(result.verified);
}

#[tokio::test]
async fn verify_returns_true_when_requested_scopes_are_subset() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write", "admin"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string()])
        .await
        .unwrap();
    assert!(result.verified);
}

#[tokio::test]
async fn verify_returns_false_when_scope_is_missing() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string(), "write".to_string()])
        .await
        .unwrap();
    assert!(!result.verified);
}

#[tokio::test]
async fn verify_is_scoped_to_participant_context() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx2", vec!["read".to_string()])
        .await
        .unwrap();
    assert!(!result.verified);
}

#[tokio::test]
async fn verify_populates_claims_from_scope_mappings() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let mut read_claims = Map::new();
    read_claims.insert("role".to_string(), Value::String("reader".to_string()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("read".to_string())
                .claims(read_claims)
                .build(),
        )
        .await
        .unwrap();

    let mut write_claims = Map::new();
    write_claims.insert("level".to_string(), Value::String("editor".to_string()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("write".to_string())
                .claims(write_claims)
                .build(),
        )
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string(), "write".to_string()])
        .await
        .unwrap();
    assert!(result.verified);
    assert_eq!(result.claims["role"], Value::String("reader".to_string()));
    assert_eq!(result.claims["level"], Value::String("editor".to_string()));
}

#[tokio::test]
async fn verify_returns_empty_claims_when_no_scope_mappings_registered() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read"]))
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string()])
        .await
        .unwrap();
    assert!(result.verified);
    assert!(result.claims.is_empty());
}

#[tokio::test]
async fn verify_returns_error_when_scopes_have_conflicting_claim_keys() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let mut read_claims = Map::new();
    read_claims.insert("role".to_string(), Value::Number(42.into()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("read".to_string())
                .claims(read_claims)
                .build(),
        )
        .await
        .unwrap();

    let mut write_claims = Map::new();
    write_claims.insert("role".to_string(), Value::String("writer".to_string()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("write".to_string())
                .claims(write_claims)
                .build(),
        )
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string(), "write".to_string()])
        .await;
    assert!(matches!(result, Err(ResourceError::ClaimConflict(_))));
}

#[tokio::test]
async fn verify_returns_merged_claim_when_scopes_have_mergeable_claim_keys() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let mut read_claims = Map::new();
    read_claims.insert("role".to_string(), Value::String("reader".to_string()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("read".to_string())
                .claims(read_claims)
                .build(),
        )
        .await
        .unwrap();

    let mut write_claims = Map::new();
    write_claims.insert("role".to_string(), Value::String("writer".to_string()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("write".to_string())
                .claims(write_claims)
                .build(),
        )
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string(), "write".to_string()])
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.verified);
    assert_eq!(result.claims["role"], Value::String("reader writer".to_string()));

}

#[tokio::test]
async fn verify_succeeds_when_scopes_have_distinct_claim_keys() {
    let service = create_service();
    service
        .save(create_mapping("client1", "ctx1", &["read", "write"]))
        .await
        .unwrap();

    let mut read_claims = Map::new();
    read_claims.insert("read_role".to_string(), Value::String("reader".to_string()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("read".to_string())
                .claims(read_claims)
                .build(),
        )
        .await
        .unwrap();

    let mut write_claims = Map::new();
    write_claims.insert("write_role".to_string(), Value::String("writer".to_string()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("write".to_string())
                .claims(write_claims)
                .build(),
        )
        .await
        .unwrap();

    let result = service
        .verify("client1", "ctx1", vec!["read".to_string(), "write".to_string()])
        .await
        .unwrap();
    assert!(result.verified);
    assert_eq!(result.claims["read_role"], Value::String("reader".to_string()));
    assert_eq!(result.claims["write_role"], Value::String("writer".to_string()));
}

#[tokio::test]
async fn save_scope_mapping_rejects_reserved_claims() {
    let service = create_service();
    for reserved in &["sub", "iss", "aud", "exp", "iat", "nbf", "act", "jti"] {
        let mut claims = Map::new();
        claims.insert((*reserved).to_string(), Value::String("x".to_string()));
        let result = service
            .save_scope_mapping(ScopeMapping::builder().scope("read".to_string()).claims(claims).build())
            .await;
        assert!(
            matches!(result, Err(ResourceError::ReservedClaim(ref k)) if k == reserved),
            "expected ReservedClaim for key '{reserved}'"
        );
    }
}

#[tokio::test]
async fn save_scope_mapping_allows_non_reserved_claims() {
    let service = create_service();
    let mut claims = Map::new();
    claims.insert("role".to_string(), Value::String("reader".to_string()));
    claims.insert("department".to_string(), Value::String("eng".to_string()));
    let result = service
        .save_scope_mapping(ScopeMapping::builder().scope("read".to_string()).claims(claims).build())
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn update_scope_mapping_rejects_reserved_claims() {
    let service = create_service();
    let mut ok_claims = Map::new();
    ok_claims.insert("role".to_string(), Value::String("reader".to_string()));
    service
        .save_scope_mapping(
            ScopeMapping::builder()
                .scope("read".to_string())
                .claims(ok_claims)
                .build(),
        )
        .await
        .unwrap();

    let mut bad_claims = Map::new();
    bad_claims.insert("sub".to_string(), Value::String("injected".to_string()));
    let result = service
        .update_scope_mapping(
            ScopeMapping::builder()
                .scope("read".to_string())
                .claims(bad_claims)
                .build(),
        )
        .await;
    assert!(matches!(result, Err(ResourceError::ReservedClaim(_))));
}

fn create_service() -> ResourceService {
    ResourceService::builder()
        .store(Arc::new(MemoryResourceStore::new()))
        .build()
}

fn create_mapping(client_id: &str, context: &str, scopes: &[&str]) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier(client_id.to_string())
        .participant_context(context.to_string())
        .scopes(scopes.iter().map(|s| s.to_string()).collect::<HashSet<_>>())
        .build()
}
