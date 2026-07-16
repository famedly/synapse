# Synapse Helm chart

Lean, production-oriented Helm chart for Famedly's [Synapse](https://github.com/famedly/synapse)
(a Matrix homeserver). It is designed to be consumed as a **dependency** by an
umbrella chart and therefore ships **no dependencies** and **no dev helpers**:
Postgres, Redis, object storage, the Gateway, and (optionally) Stakater Reloader
must already exist on the cluster. It supports the workerless default (a single
main process) and arbitrary worker topologies.

## Requirements

- **Kubernetes 1.36+ / OpenShift 4.22+.**
- **Gateway API v1** with an implementation that supports `RegularExpression`
  path matches (tested against Istio / OpenShift Service Mesh). The chart
  references an existing `Gateway`; it never creates one.
- **External Postgres.** Connection details go in your base config; the password
  is supplied out-of-band as a libpq passfile (see below).
- **External Redis** — required whenever workers are enabled (the replication
  bus). Not needed in workerless mode.
- **External object storage** for media (via the fork's bundled
  `synapse-s3-storage-provider`). No PVCs are used.
- Pre-created **Secrets** (see [Secrets](#secrets)).

## Config model

You own the bulk of `homeserver.yaml`; the chart layers Kubernetes-specific
fragments on top. Provide your config either inline via `config.settings`
(rendered to a ConfigMap) or as an existing ConfigMap via `config.existingConfigMap`.

Synapse reads an ordered list of `--config-path` directories and merges them with
a **shallow, top-level, last-wins** strategy. The chart mounts, in order:

1. `/config/base` — your config.
2. `/config/shared` — chart-owned shared fragments.
3. `/config/component` — per-process listeners / worker config.
4. `/config/dynamic` — per-pod `worker_name` (workers only).

### Reserved config keys

The chart owns these top-level keys — **do not set them** in your base config, or
they will collide with (and be overridden by) the chart's fragments:

`listeners`, `worker_app`, `worker_name`, `worker_listeners`, `instance_map`,
`stream_writers`, `redis`, `run_background_tasks_on`, `pusher_instances`,
`federation_sender_instances`, `notify_appservices_from_worker`,
`update_user_directory_from_worker`, `enable_media_repo`,
`media_instance_running_background_jobs`, and every `*_path` secret option.

### Required base-config settings

Your base config **must** set:

- `server_name`, `report_stats`.
- The `database:` block (`name`, `args.user/database/host/port`) plus
  **`database.args.passfile: /run/db/pgpass`** (the password is injected via the
  passfile — see below).
- Optionally `log_config` (a path to a log-config file you include via
  `config.existingConfigMap`). If omitted, Synapse logs to stdout — the
  Kubernetes-friendly default.
- For media: `media_store_path: /media` and your S3 storage-provider config. The
  chart provides a writable `emptyDir` at `/media` for the S3 provider's local
  staging on whichever process serves media (main in workerless mode, the media
  workers otherwise).

## Secrets

The chart consumes **existing** Secrets only, mounts them as files, and points
Synapse at them via its `*_path` options. Each credential takes
`{secretName?, key}`; `secretName` defaults to `secrets.existingSecret`.

| Credential | values path | Synapse option |
|---|---|---|
| Signing key | `secrets.signingKey` | `signing_key_path` |
| Macaroon secret | `secrets.macaroonSecretKey` | `macaroon_secret_key_path` |
| Form secret | `secrets.formSecret` | `form_secret_path` |
| Registration shared secret | `secrets.registrationSharedSecret` | `registration_shared_secret_path` |
| Worker replication secret | `secrets.workerReplicationSecret` | `worker_replication_secret_path` (required with workers) |
| Redis password | `redis.passwordSecret` | `redis.password_path` |
| Postgres password | `database.passfileSecret` | libpq passfile (see below) |

All identity secrets must be **byte-identical across every pod** — reference the
same Secret everywhere; never generate per-pod.

### Postgres password (passfile)

Synapse has no `password_path` for the database, so the chart uses a libpq
passfile. Supply a Secret key containing a single `.pgpass` line
(`host:port:database:user:password`); the chart copies it to a `0600` file at
`/run/db/pgpass` via an init container (libpq refuses a group/world-readable
passfile). Your base config references it through `database.args.passfile`.
CloudNativePG-style Secrets already ship a ready-made `pgpass` key.

## Security context

`podSecurityContext` and `containerSecurityContext` are plain values maps (global,
with per-component deep-merge overrides) — not a toggle. Two example files are
provided:

- **`values-k8s.yaml`** — pins `runAsUser/runAsGroup/fsGroup: 991`.
- **`values-openshift.yaml`** — omits them so the SCC assigns IDs from the
  namespace range.

`fsGroup` (set explicitly on k8s, assigned by the SCC on OpenShift) is required so
the projected Secret files (mode `0440`) are readable by the runtime UID.

## Workers

Workerless by default. Enable workers with `workers.enabled: true` and define
`workers.groups[]`. Each group becomes one StatefulSet + one headless Service and
selects one or more **presets** (merged into a single worker process, mirroring
the image's `type+type` grouping). Anything a preset does not match falls through
to the main process via the HTTPRoute catch-all.

Presets are ported from `docker/configure_workers_and_start.py`. Singleton-only
presets (the template fails if `replicas > 1`): `background_worker`, `appservice`,
and the single-writer streams `account_data`, `presence`, `receipts`, `typing`,
`to_device`, `push_rules`. `event_persister` (events), `federation_sender`,
`pusher`, `media_repository`, and the reader roles scale freely.

```yaml
workers:
  enabled: true
  groups:
    - { name: synchrotron, types: [synchrotron], replicas: 3 }
    - { name: client-reader, types: [client_reader], replicas: 2 }
    - { name: stream-writers, replicas: 1,
        types: [account_data, presence, receipts, typing, to_device, push_rules] }
    - { name: event-persister, types: [event_persister], replicas: 2 }
    - { name: media, types: [media_repository], replicas: 2 }
    - { name: background, types: [background_worker], replicas: 1 }
    - { name: senders, types: [federation_sender, pusher], replicas: 2 }
```

## Routing

`gateway.parentRef` (name/namespace/sectionName) attaches a single `HTTPRoute` to
your existing Gateway. Worker groups with client/federation/media endpoints get
regex rules (transformed to Envoy full-match semantics); the main process gets a
`PathPrefix: /` catch-all that is always evaluated last.

## Coordinated restarts

Synapse breaks if main and workers are restarted independently. The chart:

- stamps a `checksum/config` annotation on every pod so any config change rolls
  the whole fleet in one `helm upgrade`;
- exposes `restartNonce` — bump it to force-roll everything together (also needed
  when changing a sharded writer set, which re-partitions streams);
- optionally emits Stakater Reloader annotations (`reloader.enabled`) to roll on
  out-of-band Secret/ConfigMap rotation.

## Startup ordering

Only the main process runs DB schema migrations, and Kubernetes does not order
separate StatefulSets. Workers may `CrashLoopBackOff` briefly on a first rollout
until main has migrated; the generous `startupProbe` absorbs this.
