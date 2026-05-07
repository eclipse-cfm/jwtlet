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

use crate::config::{JwtletConfig, K8sConfig, StorageBackend, VaultConfig};
use dsdk_facet_core::jwt::{
    JwkSetProvider, JwtGenerator, JwtVerifier, VaultJwtGenerator, VaultVerificationKeyResolver,
};
use dsdk_facet_core::vault::VaultSigningClient;
use dsdk_facet_hashicorp_vault::{HashicorpVaultClient, HashicorpVaultConfig, VaultAuthConfig};
use jwtlet_core::k8s::K8sTokenReviewVerifier;
use jwtlet_core::resource::mem::MemoryResourceStore;
use jwtlet_core::resource::{ResourceService, ResourceStore};
use jwtlet_core::saccount::{MemoryServiceAccountStore, ServiceAccount, ServiceAccountAuthorizer};
use jwtlet_core::token::TokenExchangeService;
use jwtlet_postgres::PostgresResourceStore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;
// ============================================================================
// Constants
// ============================================================================

/// Prefix for the Vault transit key used to sign issued tokens.
/// The full key name per participant context is `{prefix}-{pc.id}`.
pub const DEFAULT_SIGNING_KEY_PREFIX: &str = "signing";

// ============================================================================
// Runtime
// ============================================================================

/// The fully assembled Jwtlet runtime, ready to be passed to `run_server`.
pub struct JwtletRuntime {
    /// Handles RFC 8693 token exchange requests.
    pub token_service: Arc<TokenExchangeService>,
    /// Manages resource mappings; shared with `token_service` via the underlying store.
    pub resource_service: Arc<ResourceService>,
    /// Provides the JWKS endpoint with Vault-backed public keys for token verification.
    pub key_resolver: Arc<dyn JwkSetProvider>,
    /// Authorizes management API requests against a set of service accounts and roles.
    pub service_account_authorizer: Arc<dyn ServiceAccountAuthorizer>,
    /// Verifies incoming Bearer tokens on the management API.
    pub management_verifier: Arc<dyn JwtVerifier>,
    /// Audience used when verifying management Bearer tokens via K8s TokenReview.
    pub management_client_audience: String,
}

// ============================================================================
// Error
// ============================================================================

#[derive(Debug, Error)]
pub enum JwtletError {
    #[error("Invalid configuration: {0}")]
    Configuration(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Vault error: {0}")]
    Vault(Box<dyn std::error::Error + Send + Sync>),

    #[error("K8s verifier error: {0}")]
    Verifier(dsdk_facet_core::jwt::JwtVerificationError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// Top-Level Assembly
// ============================================================================

/// Assembles the Jwtlet runtime using the in-memory resource store.
pub async fn assemble_memory(cfg: &JwtletConfig) -> Result<JwtletRuntime, JwtletError> {
    let store = Arc::new(MemoryResourceStore::new());
    assemble(cfg, store).await
}

/// Assembles the Jwtlet runtime using the Postgres-backed resource store.
pub async fn assemble_postgres(cfg: &JwtletConfig) -> Result<JwtletRuntime, JwtletError> {
    let StorageBackend::Postgres { url } = &cfg.storage_backend else {
        return Err(JwtletError::Configuration(
            "assemble_postgres called with non-postgres backend".to_string(),
        ));
    };
    if url.is_empty() {
        return Err(JwtletError::Configuration(
            "storage_backend.url is required for postgres backend".to_string(),
        ));
    }

    let store = connect_postgres(url).await?;
    assemble(cfg, Arc::new(store)).await
}

// ============================================================================
// Internal Assembly
// ============================================================================

/// Connects to Postgres and initializes the resource store schema.
async fn connect_postgres(url: &str) -> Result<PostgresResourceStore, JwtletError> {
    let pool = sqlx::PgPool::connect(url)
        .await
        .map_err(|e| JwtletError::Database(format!("Failed to connect to Postgres: {e}")))?;

    let store = PostgresResourceStore::new(pool);
    store
        .initialize()
        .await
        .map_err(|e| JwtletError::Database(format!("Failed to initialize Postgres store: {e}")))?;

    Ok(store)
}

async fn assemble(config: &JwtletConfig, store: Arc<dyn ResourceStore>) -> Result<JwtletRuntime, JwtletError> {
    // The signing key in Vault is named "{prefix}-{participant_context_claim}" — matching
    // how VaultJwtGenerator derives the key and how configure-vault.sh provisions it.
    let signing_key_name = format!(
        "{}-{}",
        DEFAULT_SIGNING_KEY_PREFIX, config.token.participant_context_claim
    );
    let vault_client = create_vault_client(&config.vault, &signing_key_name).await?;
    let key_resolver = create_key_resolver(vault_client.clone()).await?;
    let jwt_generator = create_jwt_generator(vault_client, DEFAULT_SIGNING_KEY_PREFIX);

    let exchange_resource_service = build_resource_service(store.clone());
    let management_resource_service = Arc::new(build_resource_service(store));

    let client_audience = config
        .token
        .client_audience
        .clone()
        .ok_or_else(|| JwtletError::Configuration("token.client_audience is required".to_string()))?;
    let audience = config
        .token
        .audience
        .clone()
        .ok_or_else(|| JwtletError::Configuration("token.audience is required".to_string()))?;

    let token_service = Arc::new(
        TokenExchangeService::builder()
            .client_audience(client_audience.clone())
            .audience(audience)
            .jwtlet_participant_context(config.token.participant_context_claim.clone())
            .token_ttl_secs(config.token.token_ttl_secs)
            .verifier(Box::new(create_k8s_verifier(&config.k8s).await?))
            .resource_service(exchange_resource_service)
            .generator(jwt_generator)
            .build(),
    );

    let service_account_authorizer = build_service_account_authorizer(&config.service_accounts);
    let management_verifier: Arc<dyn JwtVerifier> = Arc::new(create_k8s_verifier(&config.k8s).await?);

    // Use a dedicated management audience if configured; fall back to the exchange audience.
    let management_client_audience = config
        .management
        .client_audience
        .clone()
        .unwrap_or_else(|| client_audience.clone());

    if management_client_audience == client_audience {
        warn!(
            "management.client_audience is not set or equals token.client_audience — \
             exchange callers and management callers share the same token audience. \
             Consider setting management.client_audience to a distinct value."
        );
    }

    Ok(JwtletRuntime {
        token_service,
        resource_service: management_resource_service,
        key_resolver,
        service_account_authorizer,
        management_verifier,
        management_client_audience,
    })
}

// ============================================================================
// Component Helpers
// ============================================================================

fn build_resource_service(store: Arc<dyn ResourceStore>) -> ResourceService {
    ResourceService::builder().store(store).build()
}

fn build_service_account_authorizer(accounts: &HashMap<String, Vec<String>>) -> Arc<dyn ServiceAccountAuthorizer> {
    let all_roles: Vec<&str> = accounts.values().flat_map(|r| r.iter().map(String::as_str)).collect();
    for role in &["jwtlet:management:mappings:write", "jwtlet:management:scope:write"] {
        if !all_roles.contains(role) {
            warn!(
                "No service account with '{role}' role is configured — \
                 those management API routes will return 403 Forbidden"
            );
        }
    }

    let iter = accounts.iter().map(|(id, roles)| {
        ServiceAccount::builder()
            .client_id(id.clone())
            .roles(roles.iter().cloned().collect())
            .build()
    });
    Arc::new(MemoryServiceAccountStore::from_accounts(iter))
}

async fn create_key_resolver(
    vault_client: Arc<dyn VaultSigningClient>,
) -> Result<Arc<dyn JwkSetProvider>, JwtletError> {
    let resolver = VaultVerificationKeyResolver::builder()
        .vault_client(vault_client)
        .build();
    resolver.initialize().await.map_err(JwtletError::Verifier)?;
    Ok(Arc::new(resolver))
}

fn create_jwt_generator(vault_client: Arc<dyn VaultSigningClient>, prefix: &str) -> Box<dyn JwtGenerator> {
    Box::new(
        VaultJwtGenerator::builder()
            .signing_client(vault_client)
            .key_name_prefix(prefix)
            .build(),
    )
}

async fn create_k8s_verifier(cfg: &K8sConfig) -> Result<K8sTokenReviewVerifier, JwtletError> {
    let api_server_url = cfg
        .api_server_url
        .clone()
        .ok_or_else(|| JwtletError::Configuration("k8s.api_server_url is required".to_string()))?;
    let cluster_issuer = cfg
        .cluster_issuer
        .clone()
        .ok_or_else(|| JwtletError::Configuration("k8s.cluster_issuer is required".to_string()))?;

    const K8S_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    let client = if std::path::Path::new(K8S_CA).exists() {
        let cert_pem = std::fs::read(K8S_CA)?;
        let cert = reqwest::Certificate::from_pem(&cert_pem)
            .map_err(|e| JwtletError::Configuration(format!("Invalid cluster CA cert: {e}")))?;
        reqwest::Client::builder()
            .add_root_certificate(cert)
            .build()
            .map_err(|e| JwtletError::Configuration(format!("Failed to build HTTP client: {e}")))?
    } else {
        reqwest::Client::new()
    };

    let mut verifier = K8sTokenReviewVerifier::builder()
        .api_server_url(api_server_url)
        .cluster_issuer(cluster_issuer)
        .token_file(PathBuf::from(&cfg.token_file))
        .client(client)
        .build();

    verifier.initialize().await.map_err(JwtletError::Verifier)?;
    Ok(verifier)
}

async fn create_vault_client(
    cfg: &VaultConfig,
    signing_key_name: &str,
) -> Result<Arc<dyn VaultSigningClient>, JwtletError> {
    let vault_url = cfg
        .url
        .as_ref()
        .ok_or_else(|| JwtletError::Configuration("vault.url is required".to_string()))?;

    let token_file = match (&cfg.token_file, &cfg.token) {
        (Some(path), _) => PathBuf::from(path),
        (None, Some(token)) => {
            let path = std::env::temp_dir().join("jwtlet_vault_token");
            std::fs::write(&path, token)?;
            warn!("Using literal vault token from config — do not use in production");
            path
        }
        (None, None) => {
            return Err(JwtletError::Configuration(
                "Either vault.token or vault.token_file is required".to_string(),
            ));
        }
    };

    let vault_cfg = HashicorpVaultConfig::builder()
        .vault_url(vault_url)
        .auth_config(VaultAuthConfig::KubernetesServiceAccount {
            token_file_path: token_file,
        })
        .signing_key_name(signing_key_name.to_string())
        .build();

    let mut client = HashicorpVaultClient::new(vault_cfg).map_err(|e| JwtletError::Vault(Box::new(e)))?;

    client.initialize().await.map_err(|e| JwtletError::Vault(Box::new(e)))?;

    Ok(Arc::new(client))
}
