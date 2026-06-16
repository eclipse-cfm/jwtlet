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

//! Observability bootstrap for jwtlet.
//!
//! Initializes the global `tracing` subscriber and, when an OTLP endpoint is configured, an
//! OpenTelemetry layer that exports spans over OTLP/HTTP. The W3C TraceContext propagator is
//! installed so that trace context is carried across HTTP boundaries (extracted from inbound
//! requests on the HTTP servers, see [`crate::server`]).

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

/// Default value used for the OpenTelemetry `service.name` resource attribute and the tracer name.
const SERVICE_NAME: &str = "jwtlet";

/// Initializes logging and tracing.
///
/// A `fmt` layer (filtered via `RUST_LOG`, default `info`) is always installed. If
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is set, an OpenTelemetry export pipeline is also installed and
/// its [`SdkTracerProvider`] is returned so the caller can flush it on shutdown via [`shutdown`].
/// The service name is taken from `OTEL_SERVICE_NAME` (defaulting to `jwtlet`).
pub fn init() -> Option<SdkTracerProvider> {
    let provider = if std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some() {
        match build_provider() {
            Ok(provider) => Some(provider),
            Err(e) => {
                // tracing is not initialized yet, so fall back to stderr.
                eprintln!("jwtlet: failed to initialize OpenTelemetry export ({e}); continuing without it");
                None
            }
        }
    } else {
        None
    };

    let otel_layer = provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer(SERVICE_NAME)));

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .with(otel_layer)
        .init();

    provider
}

fn build_provider() -> anyhow::Result<SdkTracerProvider> {
    // Propagate trace context across services using the W3C `traceparent`/`tracestate` headers.
    global::set_text_map_propagator(TraceContextPropagator::new());

    // OTLP/HTTP exporter; endpoint and headers are read from the standard `OTEL_*` environment
    // variables (e.g. `OTEL_EXPORTER_OTLP_ENDPOINT`).
    let exporter = opentelemetry_otlp::SpanExporter::builder().with_http().build()?;

    let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| SERVICE_NAME.to_string());

    let provider = SdkTracerProvider::builder()
        .with_resource(Resource::builder().with_service_name(service_name).build())
        .with_batch_exporter(exporter)
        .build();

    global::set_tracer_provider(provider.clone());

    Ok(provider)
}

/// Flushes and shuts down the tracer provider, ensuring buffered spans are exported before exit.
pub fn shutdown(provider: Option<SdkTracerProvider>) {
    if let Some(provider) = provider
        && let Err(e) = provider.shutdown()
    {
        eprintln!("jwtlet: error shutting down tracer provider: {e}");
    }
}
