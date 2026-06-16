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

use crate::config::JwtletConfig;
use crate::exchange::{get_swk_set, token_exchange};
use crate::management::{ManagementState, management_routes};
use crate::meta::{AuthorizationServerMetadata, get_authorization_server_metadata};
use axum::{
    Router,
    extract::FromRef,
    routing::{get, post},
};
use dsdk_facet_core::jwt::{JwkSetProvider, JwtVerifier};
use jwtlet_core::resource::ResourceService;
use jwtlet_core::saccount::ServiceAccountAuthorizer;
use jwtlet_core::token::TokenExchangeService;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::select;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use opentelemetry::global;
use opentelemetry_http::HeaderExtractor;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[derive(Clone, FromRef)]
struct ExchangeApiState {
    token_service: Arc<TokenExchangeService>,
    key_resolver: Arc<dyn JwkSetProvider>,
    metadata: Arc<AuthorizationServerMetadata>,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn run_server(
    config: JwtletConfig,
    token_service: Arc<TokenExchangeService>,
    resource_service: Arc<ResourceService>,
    key_resolver: Arc<dyn JwkSetProvider>,
    service_account_authorizer: Arc<dyn ServiceAccountAuthorizer>,
    management_verifier: Arc<dyn JwtVerifier>,
    management_client_audience: String,
    metadata: Arc<AuthorizationServerMetadata>,
) -> Result<(), ServerError> {
    let cancel_token = CancellationToken::new();
    let mut join_set: JoinSet<Result<(), ServerError>> = JoinSet::new();

    join_set.spawn(run_token_exchange_api(
        config.bind.clone(),
        config.token_exchange_port,
        token_service,
        key_resolver,
        metadata,
        cancel_token.clone(),
    ));

    let management_state = ManagementState {
        resource_service,
        authorizer: service_account_authorizer,
        verifier: management_verifier,
        client_audience: management_client_audience,
    };

    join_set.spawn(run_management_api(
        config.bind.clone(),
        config.management_port,
        management_state,
        cancel_token.clone(),
    ));

    select! {
        _ = wait_for_shutdown() => {
            info!("Received shutdown signal");
            cancel_token.cancel();
        }
        Some(result) = join_set.join_next() => {
            handle_task_result(result);
            cancel_token.cancel();
        }
    }

    while let Some(result) = join_set.join_next().await {
        handle_task_result(result);
    }

    Ok(())
}

async fn run_token_exchange_api(
    bind: IpAddr,
    port: u16,
    service: Arc<TokenExchangeService>,
    key_resolver: Arc<dyn JwkSetProvider>,
    metadata: Arc<AuthorizationServerMetadata>,
    cancel: CancellationToken,
) -> Result<(), ServerError> {
    let addr = format!("{bind}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    info!("Token exchange API listening on {addr}");

    let state = ExchangeApiState {
        token_service: service,
        key_resolver,
        metadata,
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/token", post(token_exchange))
        .route("/.well-known/jwks.json", get(get_swk_set))
        .route(
            "/.well-known/oauth-authorization-server",
            get(get_authorization_server_metadata),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http().make_span_with(make_http_span));

    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await?;

    Ok(())
}

async fn run_management_api(
    bind: IpAddr,
    port: u16,
    state: ManagementState,
    cancel: CancellationToken,
) -> Result<(), ServerError> {
    let addr = format!("{bind}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    info!("Management API listening on {addr}");

    let app = Router::new()
        .route("/health", get(health))
        .nest("/api/v1", management_routes(state))
        .layer(TraceLayer::new_for_http().make_span_with(make_http_span));

    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await?;

    Ok(())
}

async fn health() -> &'static str {
    "OK"
}

/// Builds the per-request span, continuing the caller's trace by extracting the W3C trace context
/// (`traceparent`/`tracestate`) from the inbound request headers, so jwtlet's spans become children
/// of the calling service's span rather than starting a new trace.
fn make_http_span(request: &axum::extract::Request) -> tracing::Span {
    let parent_cx = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });
    let span = tracing::info_span!(
        "http_request",
        otel.kind = "server",
        otel.name = %format!("{} {}", request.method(), request.uri().path()),
        http.request.method = %request.method(),
        url.path = %request.uri().path(),
    );
    // best-effort: a missing/invalid traceparent simply yields no parent
    let _ = span.set_parent(parent_cx);
    span
}

fn handle_task_result(result: Result<Result<(), ServerError>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => info!("Server task completed"),
        Ok(Err(e)) => error!("Server task failed: {e}"),
        Err(e) => error!("Server task panicked: {e}"),
    }
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
        select! {
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    tracing::error!("ctrl_c signal error: {e}");
                }
            }
            _ = sigterm.recv() => {}
        }
        return;
    }
    if let Err(e) = tokio::signal::ctrl_c().await {
        error!("ctrl_c signal error: {e}");
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        error!("ctrl_c signal error: {e}");
    }
}
