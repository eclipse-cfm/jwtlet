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

use crate::utils::*;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::OnceCell;

static POSTGRES_DEPLOYMENT: OnceCell<Arc<PostgresDeployment>> = OnceCell::const_new();

/// Information about the deployed PostgreSQL instance.
pub struct PostgresDeployment {
    pub pod_name: String,
}

/// Deploys PostgreSQL to K8S.
/// This function is idempotent and thread-safe — multiple tests can call it concurrently.
pub async fn ensure_postgres_deployed() -> Result<Arc<PostgresDeployment>> {
    POSTGRES_DEPLOYMENT
        .get_or_try_init(|| async {
            verify_e2e_setup().await?;

            println!("Deploying PostgreSQL");
            kubectl_apply_server_side("manifests/postgres-deployment.yaml")
                .context("Failed to apply postgres-deployment.yaml")?;

            println!("Waiting for PostgreSQL to be ready");
            wait_for_rollout_complete(E2E_NAMESPACE, "postgres", 120).await?;

            let pod_name_output = std::process::Command::new("kubectl")
                .args([
                    "get",
                    "pods",
                    "-n",
                    E2E_NAMESPACE,
                    "-l",
                    "app=postgres",
                    "-o",
                    "go-template={{range .items}}{{if not .metadata.deletionTimestamp}}{{.metadata.name}}{{end}}{{end}}",
                ])
                .output()
                .context("Failed to get postgres pod name")?;
            let pod_name = String::from_utf8_lossy(&pod_name_output.stdout).trim().to_string();

            println!("PostgreSQL deployed: pod={}", pod_name);
            Ok(Arc::new(PostgresDeployment { pod_name }))
        })
        .await
        .map(|arc| arc.clone())
}
