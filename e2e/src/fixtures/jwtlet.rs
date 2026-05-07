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

//! Jwtlet deployment fixture — applies manifests, waits for readiness, and
//! sets up port-forwards for the token-exchange and management APIs.

use anyhow::{Context, Result};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

pub struct JwtletDeployment {
    pub token_exchange_port: u16,
    pub management_port: u16,
    _port_forwards: Mutex<Vec<std::process::Child>>,
}

static JWTLET: OnceCell<Arc<JwtletDeployment>> = OnceCell::const_new();

pub async fn ensure_jwtlet_deployed() -> Result<Arc<JwtletDeployment>> {
    JWTLET
        .get_or_try_init(|| async {
            crate::utils::verify_e2e_setup().await?;

            // PostgreSQL must be running before Jwtlet starts (Postgres backend).
            crate::fixtures::postgres::ensure_postgres_deployed().await?;

            for manifest in [
                "manifests/jwtlet-config.yaml",
                "manifests/jwtlet-deployment.yaml",
                "manifests/jwtlet-service.yaml",
            ] {
                crate::utils::kubectl_apply_server_side(manifest)
                    .with_context(|| format!("Failed to apply {manifest}"))?;
            }

            crate::utils::wait_for_rollout_complete(crate::utils::E2E_NAMESPACE, "jwtlet", 120).await?;

            let token_exchange_port = get_available_port();
            let management_port = get_available_port();

            let ns = crate::utils::E2E_NAMESPACE;
            let pf1 = setup_port_forward(ns, token_exchange_port, 8080)
                .await
                .context("Failed to set up token-exchange port-forward")?;
            let pf2 = setup_port_forward(ns, management_port, 8081)
                .await
                .context("Failed to set up management port-forward")?;

            Ok(Arc::new(JwtletDeployment {
                token_exchange_port,
                management_port,
                _port_forwards: Mutex::new(vec![pf1, pf2]),
            }))
        })
        .await
        .map(Arc::clone)
}

async fn setup_port_forward(ns: &str, local_port: u16, remote_port: u16) -> Result<std::process::Child> {
    let mut child = std::process::Command::new("kubectl")
        .args([
            "port-forward",
            "-n",
            ns,
            "svc/jwtlet",
            &format!("{local_port}:{remote_port}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn kubectl port-forward")?;

    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    let timeout_secs = 30;

    loop {
        if start.elapsed().as_secs() > timeout_secs {
            let _ = child.kill();
            anyhow::bail!(
                "Failed to establish port-forward to jwtlet :{remote_port} on local port {local_port} after {timeout_secs}s"
            );
        }

        match child
            .try_wait()
            .context("Failed to poll kubectl port-forward process")?
        {
            Some(status) => anyhow::bail!("kubectl port-forward exited unexpectedly: {status}"),
            None => {}
        }

        if client
            .get(format!("http://127.0.0.1:{local_port}/health"))
            .timeout(std::time::Duration::from_secs(1))
            .send()
            .await
            .is_ok()
        {
            return Ok(child);
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

fn get_available_port() -> u16 {
    use std::net::TcpListener;
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to port 0")
        .local_addr()
        .expect("Failed to get local address")
        .port()
}
