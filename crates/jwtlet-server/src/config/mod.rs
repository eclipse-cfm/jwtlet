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

use config::{Config, Environment, File};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

#[cfg(test)]
mod tests;

// ============================================================================
// Configuration Constants
// ============================================================================

pub const DEFAULT_TOKEN_EXCHANGE_PORT: u16 = 8080;
pub const DEFAULT_MANAGEMENT_PORT: u16 = 8081;
pub const DEFAULT_BIND_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
pub const DEFAULT_SA_TOKEN_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
pub const DEFAULT_PARTICIPANT_CONTEXT_CLAIM: &str = "jwtlet_pc";
pub const DEFAULT_TOKEN_TTL_SECS: i64 = 3600;
pub const ENV_CONFIG_FILE: &str = "JWTLET_CONFIG_FILE";

/// Accepted values for `storage_backend.pool.sslmode`. Mirrors libpq / sqlx semantics.
pub const VALID_SSL_MODES: &[&str] = &["disable", "prefer", "require", "verify-ca", "verify-full"];

// ============================================================================
// Type Definitions
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum StorageBackend {
    Memory,
    Postgres {
        url: String,
        #[serde(default)]
        pool: PostgresPoolConfig,
    },
}

impl Default for StorageBackend {
    fn default() -> Self {
        StorageBackend::Memory
    }
}

/// Tuning knobs for the Postgres connection pool.
///
/// All fields are optional; unset fields fall back to sqlx defaults (or to a
/// jwtlet default where noted). `Duration` fields accept human-readable strings
/// such as `"30s"`, `"5m"`, or `"1h30m"`.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct PostgresPoolConfig {
    /// Maximum number of connections kept by the pool. sqlx default = 10.
    pub max_connections: Option<u32>,
    /// Minimum warm connections kept even when idle. sqlx default = 0.
    pub min_connections: Option<u32>,
    /// How long an `acquire()` waits for a free connection before erroring. sqlx default = 30s.
    #[serde(with = "humantime_serde")]
    pub acquire_timeout: Option<Duration>,
    /// Drop idle connections older than this. sqlx default = 10m. `None` here keeps the sqlx default.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Option<Duration>,
    /// Recycle connections older than this regardless of activity. sqlx default = 30m.
    #[serde(with = "humantime_serde")]
    pub max_lifetime: Option<Duration>,
    /// Ping each connection before handing it out. sqlx default = true.
    pub test_before_acquire: Option<bool>,
    /// Value sent as `application_name` on each Postgres session.
    pub application_name: Option<String>,
    /// LRU capacity for the prepared-statement cache. Set to 0 behind transaction-mode PgBouncer.
    pub statement_cache_capacity: Option<usize>,
    /// One of `disable | prefer | require | verify-ca | verify-full`. Overrides any `?sslmode=` in the URL.
    pub sslmode: Option<String>,
    /// CA bundle used by `verify-ca` / `verify-full` modes.
    pub ssl_root_cert: Option<PathBuf>,
    /// Whether to run `PostgresResourceStore::initialize()` (DDL) on startup. Defaults to true when unset.
    pub run_migrations_on_startup: Option<bool>,
}

/// Configuration for the HashiCorp Vault signing backend.
#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct VaultConfig {
    /// Vault server URL, e.g. `https://vault.example.com:8200`.
    pub url: Option<String>,
    /// Direct Vault token (development only — written to a temp file at startup).
    pub token: Option<String>,
    /// Path to the file containing the Vault service-account token (production).
    pub token_file: Option<String>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            url: None,
            token: None,
            token_file: None,
        }
    }
}

/// Configuration for the Kubernetes TokenReview verifier.
#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct K8sConfig {
    /// Base URL of the Kubernetes API server, e.g. `https://kubernetes.default.svc`.
    pub api_server_url: Option<String>,
    /// OIDC issuer URL for this cluster, used as the `iss` claim in issued tokens.
    pub cluster_issuer: Option<String>,
    /// Path to the pod's mounted service account token file.
    /// Defaults to the standard in-cluster path.
    #[serde(default = "default_sa_token_file")]
    pub token_file: String,
}

impl Default for K8sConfig {
    fn default() -> Self {
        Self {
            api_server_url: None,
            cluster_issuer: None,
            token_file: DEFAULT_SA_TOKEN_FILE.to_string(),
        }
    }
}

/// Configuration for the management API.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ManagementConfig {
    /// Audience used when verifying management API Bearer tokens via K8s TokenReview.
    /// When absent, falls back to `token.client_audience`. Set this to a dedicated
    /// audience to cryptographically separate management callers from token-exchange callers.
    pub client_audience: Option<String>,
}

/// Configuration for issued JWT tokens.
#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct TokenConfig {
    /// The expected audience of incoming subject tokens (client JWTs to be exchanged).
    pub client_audience: Option<String>,
    /// The audience placed in issued participant-context tokens.
    pub audience: Option<String>,
    /// Claim name used to identify the participant context. Defaults to `"jwtlet_pc"`.
    #[serde(default = "default_participant_context_claim")]
    pub participant_context_claim: String,
    /// Lifetime of issued tokens in seconds. Defaults to 3600.
    #[serde(default = "default_token_ttl_secs")]
    pub token_ttl_secs: i64,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            client_audience: None,
            audience: None,
            participant_context_claim: DEFAULT_PARTICIPANT_CONTEXT_CLAIM.to_string(),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct JwtletConfig {
    #[serde(default = "default_token_exchange_port")]
    pub token_exchange_port: u16,
    #[serde(default = "default_management_port")]
    pub management_port: u16,
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default)]
    pub storage_backend: StorageBackend,
    #[serde(default)]
    pub k8s: K8sConfig,
    #[serde(default)]
    pub token: TokenConfig,
    #[serde(default)]
    pub vault: VaultConfig,
    #[serde(default)]
    pub service_accounts: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub management: ManagementConfig,
}

impl Default for JwtletConfig {
    fn default() -> Self {
        Self {
            token_exchange_port: DEFAULT_TOKEN_EXCHANGE_PORT,
            management_port: DEFAULT_MANAGEMENT_PORT,
            bind: DEFAULT_BIND_ADDRESS,
            storage_backend: StorageBackend::Memory,
            k8s: K8sConfig::default(),
            token: TokenConfig::default(),
            vault: VaultConfig::default(),
            service_accounts: HashMap::new(),
            management: ManagementConfig::default(),
        }
    }
}

impl JwtletConfig {
    /// Validates the configuration, collecting all errors before returning.
    ///
    /// Call immediately after loading to fail fast before starting any services.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut errors = Vec::new();

        // Vault configuration
        match &self.vault.url {
            None => errors.push("vault.url is required".to_string()),
            Some(url) if url.parse::<reqwest::Url>().is_err() => {
                errors.push(format!("vault.url is not a valid URL: '{url}'"));
            }
            _ => {}
        }
        if self.vault.token.is_none() && self.vault.token_file.is_none() {
            errors.push("Either vault.token or vault.token_file is required".to_string());
        }

        // K8s configuration
        match &self.k8s.api_server_url {
            None => errors.push("k8s.api_server_url is required".to_string()),
            Some(url) if url.parse::<reqwest::Url>().is_err() => {
                errors.push(format!("k8s.api_server_url is not a valid URL: '{url}'"));
            }
            _ => {}
        }

        if self.k8s.cluster_issuer.is_none() {
            errors.push("k8s.cluster_issuer is required".to_string());
        }

        if self.k8s.token_file.is_empty() {
            errors.push("k8s.token_file cannot be empty".to_string());
        }

        // Token configuration
        if self.token.client_audience.is_none() {
            errors.push("token.client_audience is required".to_string());
        }

        if self.token.audience.is_none() {
            errors.push("token.audience is required".to_string());
        }

        if self.token.participant_context_claim.is_empty() {
            errors.push("token.participant_context_claim cannot be empty".to_string());
        }

        if self.token.token_ttl_secs <= 0 {
            errors.push(format!(
                "token.token_ttl_secs must be positive, got {}",
                self.token.token_ttl_secs
            ));
        }

        // Postgres URL required when using that backend
        if let StorageBackend::Postgres { url, pool } = &self.storage_backend {
            if url.is_empty() {
                errors.push("storage_backend.url is required for Postgres backend".to_string());
            }

            if let Some(0) = pool.max_connections {
                errors.push("storage_backend.pool.max_connections must be > 0".to_string());
            }
            if let (Some(min), Some(max)) = (pool.min_connections, pool.max_connections)
                && min > max
            {
                errors.push(format!(
                    "storage_backend.pool.min_connections ({min}) cannot exceed max_connections ({max})"
                ));
            }
            if let Some(d) = pool.acquire_timeout
                && d.is_zero()
            {
                errors.push("storage_backend.pool.acquire_timeout must be > 0".to_string());
            }
            if let Some(mode) = &pool.sslmode
                && !VALID_SSL_MODES.contains(&mode.as_str())
            {
                errors.push(format!(
                    "storage_backend.pool.sslmode '{mode}' is invalid; expected one of {VALID_SSL_MODES:?}"
                ));
            }
            if let Some(path) = &pool.ssl_root_cert
                && !path.exists()
            {
                errors.push(format!(
                    "storage_backend.pool.ssl_root_cert path does not exist: {}",
                    path.display()
                ));
            }
        }

        // Port validation
        if self.token_exchange_port == 0 {
            errors.push("token_exchange_port cannot be 0".to_string());
        }
        if self.management_port == 0 {
            errors.push("management_port cannot be 0".to_string());
        }
        if self.token_exchange_port == self.management_port {
            errors.push(format!(
                "token_exchange_port and management_port cannot be the same (both are {})",
                self.token_exchange_port
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::Multiple(errors))
        }
    }
}

// ============================================================================
// Default functions
// ============================================================================

const fn default_token_exchange_port() -> u16 {
    DEFAULT_TOKEN_EXCHANGE_PORT
}

const fn default_management_port() -> u16 {
    DEFAULT_MANAGEMENT_PORT
}

fn default_bind() -> IpAddr {
    DEFAULT_BIND_ADDRESS
}

fn default_sa_token_file() -> String {
    DEFAULT_SA_TOKEN_FILE.to_string()
}

fn default_participant_context_claim() -> String {
    DEFAULT_PARTICIPANT_CONTEXT_CLAIM.to_string()
}

const fn default_token_ttl_secs() -> i64 {
    DEFAULT_TOKEN_TTL_SECS
}

// ============================================================================
// Loading
// ============================================================================

pub fn load_config() -> anyhow::Result<JwtletConfig> {
    let path = std::env::args().nth(1);
    let config_file = std::env::var(ENV_CONFIG_FILE)
        .map(PathBuf::from)
        .ok()
        .or_else(|| path.map(PathBuf::from));

    let mut builder = Config::builder();
    if let Some(path) = config_file {
        builder = builder.add_source(File::from(path));
    }

    builder
        .add_source(Environment::with_prefix("JWTLET").separator("__"))
        .build()?
        .try_deserialize()
        .map_err(Into::into)
}

// ============================================================================
// Validation Error
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    Single(String),
    Multiple(Vec<String>),
}

impl ValidationError {
    pub fn single(msg: impl Into<String>) -> Self {
        ValidationError::Single(msg.into())
    }

    pub fn error_count(&self) -> usize {
        match self {
            ValidationError::Single(_) => 1,
            ValidationError::Multiple(errors) => errors.len(),
        }
    }

    pub fn messages(&self) -> Vec<&str> {
        match self {
            ValidationError::Single(msg) => vec![msg.as_str()],
            ValidationError::Multiple(errors) => errors.iter().map(|s| s.as_str()).collect(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::Single(msg) => write!(f, "Configuration validation failed: {msg}"),
            ValidationError::Multiple(errors) => {
                writeln!(f, "Configuration validation failed with {} error(s):", errors.len())?;
                for (i, error) in errors.iter().enumerate() {
                    writeln!(f, "  {}. {error}", i + 1)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ValidationError {}
