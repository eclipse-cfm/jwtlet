#!/bin/bash
#  Copyright (c) 2026 Metaform Systems, Inc
#  SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${E2E_DIR}/.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
E2E_NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"

if ! kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
  echo "Cluster '$KIND_CLUSTER_NAME' not found — running full setup first..."
  exec "${SCRIPT_DIR}/setup.sh"
fi

detect_platform() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64)       echo "linux/amd64" ;;
    aarch64|arm64) echo "linux/arm64" ;;
    *)
      echo "Warning: Unknown architecture '$arch', defaulting to linux/amd64" >&2
      echo "linux/amd64"
      ;;
  esac
}

wait_for_jwtlet() {
  echo "Waiting for jwtlet to be ready (up to 300s)..."
  local deadline=$(( $(date +%s) + 300 ))

  while true; do
    if kubectl wait --for=condition=Available deployment/jwtlet \
        -n "$E2E_NAMESPACE" --timeout=5s 2>/dev/null; then
      echo "jwtlet is ready"
      return 0
    fi

    if (( $(date +%s) >= deadline )); then
      echo ""
      echo "Error: jwtlet did not become ready within 300s"
      echo ""
      echo "--- pod status ---"
      kubectl get pods -l app=jwtlet -n "$E2E_NAMESPACE" || true
      echo ""
      echo "--- vault-agent logs ---"
      kubectl logs -l app=jwtlet -n "$E2E_NAMESPACE" -c vault-agent --tail=50 2>/dev/null || true
      echo ""
      echo "--- jwtlet logs ---"
      kubectl logs -l app=jwtlet -n "$E2E_NAMESPACE" -c jwtlet --tail=50 2>/dev/null || true
      exit 1
    fi

    echo "  still waiting... $(kubectl get pods -l app=jwtlet -n "$E2E_NAMESPACE" \
      --no-headers 2>/dev/null | awk '{print $1, $3}')"
    sleep 10
  done
}

PLATFORM="$(detect_platform)"

echo "Building jwtlet image for platform: $PLATFORM..."
DOCKER_BUILDKIT=1 docker build \
  --platform "$PLATFORM" \
  --build-arg "CACHE_INVALIDATE=$(date +%s)" \
  -f "${WORKSPACE_ROOT}/crates/jwtlet-server/Dockerfile.test" \
  -t jwtlet:local \
  "$WORKSPACE_ROOT"

echo "Loading image into Kind cluster..."
kind load docker-image jwtlet:local --name "$KIND_CLUSTER_NAME"

# If jwtlet is already deployed, re-apply manifests, reconfigure Vault, and roll it
if kubectl get deployment jwtlet -n "$E2E_NAMESPACE" &>/dev/null; then
  echo "Applying updated jwtlet manifests..."
  kubectl apply --server-side --force-conflicts -f "${E2E_DIR}/manifests/jwtlet-config.yaml"
  kubectl apply --server-side --force-conflicts -f "${E2E_DIR}/manifests/jwtlet-deployment.yaml"
  kubectl apply --server-side --force-conflicts -f "${E2E_DIR}/manifests/jwtlet-service.yaml"

  echo "Reconfiguring Vault (dev mode resets on pod restart)..."
  "${E2E_DIR}/scripts/configure-vault.sh"

  echo "Restarting jwtlet deployment..."
  kubectl rollout restart deployment/jwtlet -n "$E2E_NAMESPACE"

  wait_for_jwtlet
fi

echo "Image loaded and deployed successfully"
