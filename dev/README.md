# Dev harness for the Synapse Helm chart

**Dev-only. Not part of the chart.** Everything here uses throwaway, insecure
credentials and ephemeral storage — never use it for anything real. It exists so
the production chart under `charts/synapse` can be iterated on locally against a
real Gateway API implementation (Istio).

The production chart ships no dependencies; this harness provides throwaway
stand-ins (Postgres, Redis, MinIO) plus a Gateway, mirroring what the real
umbrella/dev chart will supply.

## Prerequisites

Everything is provided by the flake dev shell:

```sh
nix develop --impure    # provides kind, istioctl, tilt, helm, kubectl
```

## Usage

```sh
# 1. One-time: create the kind cluster, install Gateway API CRDs + Istio.
bash dev/bootstrap.sh

# 2. Bring up deps + chart with live reload.
tilt up

# 3. Reach the homeserver through the Istio gateway:
kubectl -n default port-forward svc/matrix-gateway-istio 8080:80
curl -H 'Host: matrix.localhost' http://localhost:8080/_matrix/client/versions
```

Editing files under `charts/synapse` re-renders and re-applies automatically.

## What it deploys

- `dev/deps/` — throwaway Postgres, Redis, MinIO (+ a bucket-creation Job), and a
  Gateway API `Gateway` backed by Istio.
- `dev/secrets.sh` — generates the `synapse-secrets` Secret (a valid ed25519
  signing key, random secrets, a libpq `pgpass` matching the throwaway Postgres,
  and the Redis password).
- `dev/values-dev.yaml` — layered on `charts/synapse/values-k8s.yaml`; enables a
  small worker topology (synchrotron, a merged stream-writers pod, an event
  persister, and a media worker) to exercise routing and the replication config.

## Teardown

```sh
kind delete cluster --name synapse-dev
```
