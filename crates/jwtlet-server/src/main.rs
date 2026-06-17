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

#[tokio::main]
async fn main() {
    let tracer_provider = jwtlet_server::telemetry::init();

    let result = run_jwtlet().await;

    // flush any buffered spans before the process exits
    jwtlet_server::telemetry::shutdown(tracer_provider);

    match result {
        Ok(()) => info!("Shutdown complete"),
        Err(e) => {
            error!("Fatal error: {e}");
            std::process::exit(1);
        }
    }
}

async fn run_jwtlet() -> anyhow::Result<()> {
    let config = load_config().map_err(|e| anyhow::anyhow!("Failed to load configuration: {e}"))?;
    config.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
    run(config).await
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
