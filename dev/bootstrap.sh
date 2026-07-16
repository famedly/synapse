#!/usr/bin/env bash
# One-time setup for the dev harness: kind cluster + Gateway API CRDs + Istio.
# DEV ONLY. Run inside `nix develop --impure`. Safe to re-run.
set -euo pipefail

CLUSTER="synapse-dev"
GATEWAY_API_VERSION="v1.2.1"

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "kind cluster '$CLUSTER' already exists."
else
  kind create cluster --config "$(dirname "$0")/kind.yaml"
fi

kubectl config use-context "kind-$CLUSTER"

echo "Installing Gateway API CRDs ($GATEWAY_API_VERSION, standard channel)..."
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

echo "Installing Istio (minimal profile)..."
istioctl install -y --set profile=minimal

echo "Bootstrap complete. Next: run 'tilt up' from the repo root."
