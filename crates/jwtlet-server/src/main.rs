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

use jwtlet_server::{
    assembly::{assemble_memory, assemble_postgres},
    config::{JwtletConfig, StorageBackend, load_config},
    server::run_server,
};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = load_config().unwrap_or_else(|e| {
        error!("Failed to load configuration: {e}");
        std::process::exit(1);
    });

    if let Err(e) = config.validate() {
        error!("{e}");
        std::process::exit(1);
    }

    match run(config).await {
        Ok(()) => info!("Shutdown complete"),
        Err(e) => {
            error!("Fatal error: {e}");
            std::process::exit(1);
        }
    }
}

async fn run(config: JwtletConfig) -> anyhow::Result<()> {
    let runtime = match &config.storage_backend {
        StorageBackend::Memory => assemble_memory(&config).await?,
        StorageBackend::Postgres { .. } => assemble_postgres(&config).await?,
    };

    run_server(
        config,
        runtime.token_service,
        runtime.resource_service,
        runtime.key_resolver,
        runtime.service_account_authorizer,
        runtime.management_verifier,
        runtime.management_client_audience,
        runtime.metadata,
    )
    .await
    .map_err(Into::into)
}
