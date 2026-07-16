#!/usr/bin/env bash
# Generate the throwaway dev Secret consumed by the chart. Idempotent.
# DEV ONLY — insecure, ephemeral credentials. Run inside `nix develop --impure`.
set -euo pipefail

NS="${1:-default}"
SECRET="synapse-secrets"

# Match the throwaway Postgres/Redis deployments in dev/deps.
PG_PASSWORD="devpassword"
REDIS_PASSWORD="devredis"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# A valid ed25519 Synapse signing key: "ed25519 <key_id> <unpadded-base64-seed>".
python3 - > "$tmp/signing.key" <<'PY'
import base64, os, secrets, string
kid = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(6))
seed = base64.b64encode(os.urandom(32)).decode().rstrip('=')
print(f"ed25519 a_{kid} {seed}")
PY

rand() { python3 -c "import secrets;print(secrets.token_hex(32))"; }

printf '%s' "$(rand)" > "$tmp/macaroon_secret_key"
printf '%s' "$(rand)" > "$tmp/form_secret"
printf '%s' "$(rand)" > "$tmp/registration_shared_secret"
printf '%s' "$(rand)" > "$tmp/worker_replication_secret"
printf '%s' "$REDIS_PASSWORD" > "$tmp/redis-password"
# libpq passfile line: host:port:database:user:password
printf 'postgres:5432:synapse:synapse:%s' "$PG_PASSWORD" > "$tmp/pgpass"

kubectl create secret generic "$SECRET" -n "$NS" \
  --from-file=signing.key="$tmp/signing.key" \
  --from-file=macaroon_secret_key="$tmp/macaroon_secret_key" \
  --from-file=form_secret="$tmp/form_secret" \
  --from-file=registration_shared_secret="$tmp/registration_shared_secret" \
  --from-file=worker_replication_secret="$tmp/worker_replication_secret" \
  --from-file=redis-password="$tmp/redis-password" \
  --from-file=pgpass="$tmp/pgpass" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Created/updated Secret $SECRET in namespace $NS."
