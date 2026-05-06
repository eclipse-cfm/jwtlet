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

use async_trait::async_trait;
use jwtlet_core::resource::{MappingPair, ResourceError, ResourceMapping, ResourceStore, ScopeMapping};
use serde_json::{Map, Value};
use sqlx::PgPool;
use std::collections::HashMap;

const CREATE_RESOURCE_MAPPINGS: &str = "
    CREATE TABLE IF NOT EXISTS resource_mappings (
        client_identifier TEXT NOT NULL,
        participant_context TEXT NOT NULL,
        scopes TEXT[] NOT NULL DEFAULT '{}',
        audiences TEXT[] NOT NULL DEFAULT '{}',
        PRIMARY KEY (client_identifier, participant_context)
    )";

const CREATE_RESOURCE_MAPPINGS_INDEX: &str = "
    CREATE INDEX IF NOT EXISTS idx_resource_mappings_client
    ON resource_mappings (client_identifier)";

const CREATE_SCOPE_MAPPINGS: &str = "
    CREATE TABLE IF NOT EXISTS scope_mappings (
        scope TEXT PRIMARY KEY,
        claims JSONB NOT NULL DEFAULT '{}'
    )";

#[derive(sqlx::FromRow)]
struct ResourceMappingRow {
    client_identifier: String,
    participant_context: String,
    scopes: Vec<String>,
    audiences: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct ScopeMappingRow {
    scope: String,
    claims: serde_json::Value,
}

pub struct PostgresResourceStore {
    pool: PgPool,
}

impl PostgresResourceStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn initialize(&self) -> Result<(), ResourceError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ResourceError::DatabaseError(e.to_string()))?;

        sqlx::query(CREATE_RESOURCE_MAPPINGS)
            .execute(&mut *tx)
            .await
            .map_err(|e| ResourceError::DatabaseError(e.to_string()))?;

        sqlx::query(CREATE_RESOURCE_MAPPINGS_INDEX)
            .execute(&mut *tx)
            .await
            .map_err(|e| ResourceError::DatabaseError(e.to_string()))?;

        sqlx::query(CREATE_SCOPE_MAPPINGS)
            .execute(&mut *tx)
            .await
            .map_err(|e| ResourceError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ResourceError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}

fn row_to_resource_mapping(row: ResourceMappingRow) -> ResourceMapping {
    ResourceMapping::builder()
        .client_identifier(row.client_identifier)
        .participant_context(row.participant_context)
        .scopes(row.scopes.into_iter().collect())
        .audiences(row.audiences.into_iter().collect())
        .build()
}

fn row_to_scope_mapping(row: ScopeMappingRow) -> ScopeMapping {
    let claims = match row.claims {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    ScopeMapping::builder().scope(row.scope).claims(claims).build()
}

fn db_error(e: sqlx::Error) -> ResourceError {
    ResourceError::DatabaseError(e.to_string())
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[async_trait]
impl ResourceStore for PostgresResourceStore {
    async fn resolve_mapping(
        &self,
        client_identifier: &str,
        participant_context: &str,
    ) -> Result<Option<MappingPair>, ResourceError> {
        let row = sqlx::query_as::<_, ResourceMappingRow>(
            "SELECT client_identifier, participant_context, scopes, audiences
             FROM resource_mappings
             WHERE client_identifier = $1 AND participant_context = $2",
        )
        .bind(client_identifier)
        .bind(participant_context)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let resource_mapping = row_to_resource_mapping(row);

        let scopes: Vec<String> = resource_mapping.scopes.iter().cloned().collect();
        let scope_rows =
            sqlx::query_as::<_, ScopeMappingRow>("SELECT scope, claims FROM scope_mappings WHERE scope = ANY($1)")
                .bind(&scopes)
                .fetch_all(&self.pool)
                .await
                .map_err(db_error)?;

        let scope_mappings: HashMap<String, ScopeMapping> = scope_rows
            .into_iter()
            .map(|r| {
                let sm = row_to_scope_mapping(r);
                (sm.scope.clone(), sm)
            })
            .collect();

        Ok(Some(MappingPair {
            resource_mapping,
            scope_mappings,
        }))
    }

    async fn save_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError> {
        let scopes: Vec<String> = mapping.scopes.iter().cloned().collect();
        let audiences: Vec<String> = mapping.audiences.iter().cloned().collect();

        sqlx::query(
            "INSERT INTO resource_mappings (client_identifier, participant_context, scopes, audiences)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&mapping.client_identifier)
        .bind(&mapping.participant_context)
        .bind(&scopes)
        .bind(&audiences)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                ResourceError::Conflict(mapping.client_identifier.clone())
            } else {
                db_error(e)
            }
        })?;

        Ok(())
    }

    async fn update_mapping(&self, mapping: ResourceMapping) -> Result<(), ResourceError> {
        let scopes: Vec<String> = mapping.scopes.iter().cloned().collect();
        let audiences: Vec<String> = mapping.audiences.iter().cloned().collect();

        let result = sqlx::query(
            "UPDATE resource_mappings SET scopes = $3, audiences = $4
             WHERE client_identifier = $1 AND participant_context = $2",
        )
        .bind(&mapping.client_identifier)
        .bind(&mapping.participant_context)
        .bind(&scopes)
        .bind(&audiences)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;

        if result.rows_affected() == 0 {
            return Err(ResourceError::NotFound(mapping.client_identifier.clone()));
        }

        Ok(())
    }

    async fn remove_mapping(&self, client_identifier: &str, participant_context: &str) -> Result<(), ResourceError> {
        sqlx::query("DELETE FROM resource_mappings WHERE client_identifier = $1 AND participant_context = $2")
            .bind(client_identifier)
            .bind(participant_context)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        Ok(())
    }

    async fn remove_mappings_for(&self, client_identifier: &str) -> Result<(), ResourceError> {
        sqlx::query("DELETE FROM resource_mappings WHERE client_identifier = $1")
            .bind(client_identifier)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        Ok(())
    }

    async fn save_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError> {
        let claims = Value::Object(mapping.claims.clone());

        sqlx::query(
            "INSERT INTO scope_mappings (scope, claims) VALUES ($1, $2)
             ON CONFLICT (scope) DO UPDATE SET claims = EXCLUDED.claims",
        )
        .bind(&mapping.scope)
        .bind(&claims)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(())
    }

    async fn update_scope_mapping(&self, mapping: ScopeMapping) -> Result<(), ResourceError> {
        let claims = Value::Object(mapping.claims.clone());

        let result = sqlx::query("UPDATE scope_mappings SET claims = $2 WHERE scope = $1")
            .bind(&mapping.scope)
            .bind(&claims)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        if result.rows_affected() == 0 {
            return Err(ResourceError::NotFound(mapping.scope.clone()));
        }

        Ok(())
    }

    async fn remove_scope_mapping(&self, scope: &str) -> Result<(), ResourceError> {
        sqlx::query("DELETE FROM scope_mappings WHERE scope = $1")
            .bind(scope)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        Ok(())
    }

    async fn list_mappings(&self) -> Result<Vec<ResourceMapping>, ResourceError> {
        let rows = sqlx::query_as::<_, ResourceMappingRow>(
            "SELECT client_identifier, participant_context, scopes, audiences FROM resource_mappings",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(rows.into_iter().map(row_to_resource_mapping).collect())
    }

    async fn list_scope_mappings(&self) -> Result<Vec<ScopeMapping>, ResourceError> {
        let rows = sqlx::query_as::<_, ScopeMappingRow>("SELECT scope, claims FROM scope_mappings")
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?;

        Ok(rows.into_iter().map(row_to_scope_mapping).collect())
    }
}
