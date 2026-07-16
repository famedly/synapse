# Dev harness for iterating on the Synapse Helm chart (charts/synapse).
# DEV ONLY. Requires the kind cluster + Istio from dev/bootstrap.sh.
# Run inside `nix develop --impure`, then `tilt up`.

allow_k8s_contexts('kind-synapse-dev')

# --- Throwaway dependencies (Postgres, Redis, MinIO) and the dev Gateway ---
k8s_yaml([
    'dev/deps/postgres.yaml',
    'dev/deps/redis.yaml',
    'dev/deps/minio.yaml',
    'dev/deps/gateway.yaml',
])
k8s_resource('postgres', labels=['deps'])
k8s_resource('redis', labels=['deps'])
k8s_resource('minio', labels=['deps'])

# --- Dev Secret (generated once by dev/secrets.sh) ---
local_resource(
    'synapse-secret',
    cmd='bash dev/secrets.sh default',
    labels=['deps'],
)

# --- The chart itself ---
# Rendered with `helm template` so we control --kube-version (the chart floor is
# 1.36, above helm's compiled default). Tilt re-runs the Tiltfile when the chart
# files change, re-rendering live.
watch_file('charts/synapse')
chart_yaml = local(
    'helm template synapse charts/synapse ' +
    '--namespace default --kube-version 1.36.0 ' +
    '-f charts/synapse/values-k8s.yaml -f dev/values-dev.yaml',
    quiet=True,
)
k8s_yaml(chart_yaml)

# Group the workloads under a readable label and depend on deps + secret.
for res in ['synapse-main', 'synapse-synchrotron', 'synapse-stream-writers',
            'synapse-event-persister', 'synapse-media']:
    k8s_resource(res, labels=['synapse'],
                 resource_deps=['postgres', 'redis', 'minio', 'synapse-secret'])

print("""
Synapse dev harness up.
Reach the homeserver through the Istio gateway:
  kubectl -n default port-forward svc/matrix-gateway-istio 8080:80
  curl -H 'Host: matrix.localhost' http://localhost:8080/_matrix/client/versions
""")
