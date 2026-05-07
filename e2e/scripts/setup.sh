#!/bin/bash
#  Copyright (c) 2026 Metaform Systems, Inc
#  SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-vault-e2e}"
E2E_NAMESPACE="${E2E_NAMESPACE:-vault-e2e-test}"

echo "Setting up E2E environment..."
echo "Cluster:   $KIND_CLUSTER_NAME"
echo "Namespace: $E2E_NAMESPACE"

# Prerequisites
command -v kind    >/dev/null 2>&1 || { echo "Error: kind is required";    exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "Error: kubectl is required"; exit 1; }
command -v docker  >/dev/null 2>&1 || { echo "Error: docker is required";  exit 1; }

# Create Kind cluster if missing
if ! kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
  echo "Creating Kind cluster..."
  kind create cluster --name "$KIND_CLUSTER_NAME" --wait 60s
else
  echo "Cluster $KIND_CLUSTER_NAME already exists"
fi

echo "Setting kubectl context..."
kubectl config use-context "kind-${KIND_CLUSTER_NAME}"

kubectl cluster-info --context "kind-${KIND_CLUSTER_NAME}"

echo "Creating namespace..."
kubectl apply -f "${E2E_DIR}/manifests/namespace.yaml"

echo "Creating service accounts and RBAC..."
# ClusterRoleBinding.roleRef is immutable — delete stale bindings before applying
kubectl delete clusterrolebinding vault-token-reviewer-binding jwtlet-token-reviewer-binding \
  --ignore-not-found
kubectl apply -f "${E2E_DIR}/manifests/service-accounts.yaml"

echo "Deploying Vault..."
kubectl apply -f "${E2E_DIR}/manifests/vault-deployment.yaml"
kubectl wait --for=condition=Available deployment/vault -n "$E2E_NAMESPACE" --timeout=120s

echo "Configuring Vault..."
"${E2E_DIR}/scripts/configure-vault.sh"

echo "Applying Vault agent config..."
kubectl apply -f "${E2E_DIR}/manifests/vault-agent-config.yaml"

echo "Deploying PostgreSQL..."
kubectl apply -f "${E2E_DIR}/manifests/postgres-deployment.yaml"
kubectl wait --for=condition=Available deployment/postgres -n "$E2E_NAMESPACE" --timeout=120s

echo "Building and loading jwtlet image..."
"${E2E_DIR}/scripts/build-and-load-jwtlet.sh"

echo ""
echo "Setup complete!"
echo ""
echo "Run tests: make e2e-test"
echo "Cleanup:   make e2e-cleanup"
