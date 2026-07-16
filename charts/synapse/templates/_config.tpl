{{/*
Config-directory layout, secret wiring, listeners, and pod plumbing shared by
the main and worker StatefulSets.

Config is assembled from an ordered list of --config-path directories. Synapse
merges *.yaml per directory with a shallow, top-level, last-wins strategy, so
each directory owns disjoint top-level keys and later directories win on the few
that could collide (e.g. media's enable_media_repo overriding the shared false):

  /config/base      user-provided base config (ConfigMap)
  /config/shared    chart-owned shared fragments (secrets *_path, redis,
                    instance_map, stream_writers, duties, enable_metrics)
  /config/component per-process listeners + worker_app + worker_extra_conf
  /config/dynamic   per-pod worker_name (workers only; written by initContainer)

Non-config secret material lives outside the config dirs:
  /secrets          projected Secret files referenced by *_path options (RO)
  /run/db/pgpass    libpq passfile (0600 copy made by the initContainer)
*/}}

{{- define "synapse.paths.base" -}}/config/base{{- end -}}
{{- define "synapse.paths.shared" -}}/config/shared{{- end -}}
{{- define "synapse.paths.component" -}}/config/component{{- end -}}
{{- define "synapse.paths.dynamic" -}}/config/dynamic{{- end -}}
{{- define "synapse.paths.secrets" -}}/secrets{{- end -}}
{{- define "synapse.paths.pgpass" -}}/run/db/pgpass{{- end -}}
{{- define "synapse.paths.media" -}}/media{{- end -}}

{{/*
Static description of the file-path secrets. Each maps a values.secrets.<key> to
a filename under /secrets and the Synapse *_path option that references it.
Redis password and the Postgres passfile are handled separately (nested option /
non-config passfile respectively).
*/}}
{{- define "synapse.secretSpecs" -}}
- key: signingKey
  file: signing.key
  option: signing_key_path
- key: macaroonSecretKey
  file: macaroon_secret_key
  option: macaroon_secret_key_path
- key: formSecret
  file: form_secret
  option: form_secret_path
- key: registrationSharedSecret
  file: registration_shared_secret
  option: registration_shared_secret_path
- key: workerReplicationSecret
  file: worker_replication_secret
  option: worker_replication_secret_path
  workersOnly: true
{{- end -}}

{{/*
Is Redis effectively enabled? Redis is a hard dependency in worker mode, so it is
forced on whenever workers are enabled, regardless of redis.enabled.
*/}}
{{- define "synapse.redisEnabled" -}}
{{- if or .Values.redis.enabled .Values.workers.enabled -}}true{{- end -}}
{{- end -}}

{{/*
Render a listeners block. Ctx: root, key ("listeners" or "worker_listeners"),
httpResources (list of client/federation/media), hasReplication (bool).
*/}}
{{- define "synapse.listenersYaml" -}}
{{- $root := .root -}}
{{ .key }}:
{{- if .httpResources }}
  - port: 8008
    type: http
    tls: false
    bind_addresses: ['0.0.0.0']
    x_forwarded: true
    resources:
      - names: [{{ join ", " .httpResources }}]
        compress: false
{{- end }}
{{- if .hasReplication }}
  - port: 9093
    type: http
    tls: false
    bind_addresses: ['0.0.0.0']
    resources:
      - names: [replication]
{{- end }}
{{- if $root.Values.metrics.enabled }}
  - port: 9090
    type: metrics
    bind_addresses: ['0.0.0.0']
{{- end }}
{{- end -}}

{{/*
The pod volumes shared by every component. Ctx: root, isWorker, mediaWritable,
componentConfigMap (name of the per-component ConfigMap).
*/}}
{{- define "synapse.volumes" -}}
{{- $root := .root -}}
- name: config-base
  configMap:
    name: {{ .root.Values.config.existingConfigMap | default (printf "%s-base" (include "synapse.fullname" .root)) }}
- name: config-shared
  configMap:
    name: {{ include "synapse.fullname" .root }}-shared
- name: config-component
  configMap:
    name: {{ .componentConfigMap }}
{{- if .isWorker }}
- name: config-dynamic
  emptyDir: {}
{{- end }}
- name: db-creds
  emptyDir: {}
- name: tmp
  emptyDir: {}
{{- if .mediaWritable }}
- name: media
  emptyDir: {}
{{- end }}
- name: secrets
  projected:
    defaultMode: 0440
    sources:
      {{- range $spec := (fromYamlArray (include "synapse.secretSpecs" $root)) }}
      {{- if and $spec.workersOnly (not $root.Values.workers.enabled) }}{{- else }}
      {{- $name := include "synapse.resolveSecretName" (dict "ref" (index $root.Values.secrets $spec.key) "default" $root.Values.secrets.existingSecret) }}
      {{- if $name }}
      - secret:
          name: {{ $name }}
          items:
            - key: {{ (index $root.Values.secrets $spec.key).key }}
              path: {{ $spec.file }}
      {{- end }}
      {{- end }}
      {{- end }}
      {{- $redisName := include "synapse.resolveSecretName" (dict "ref" $root.Values.redis.passwordSecret "default" $root.Values.secrets.existingSecret) }}
      {{- if and (include "synapse.redisEnabled" $root) $redisName }}
      - secret:
          name: {{ $redisName }}
          items:
            - key: {{ $root.Values.redis.passwordSecret.key }}
              path: redis_password
      {{- end }}
      {{- $pgName := include "synapse.resolveSecretName" (dict "ref" $root.Values.database.passfileSecret "default" $root.Values.secrets.existingSecret) }}
      {{- if $pgName }}
      - secret:
          name: {{ $pgName }}
          items:
            - key: {{ $root.Values.database.passfileSecret.key }}
              path: pgpass
      {{- end }}
{{- end -}}

{{/*
Volume mounts for the main Synapse container. Config dirs and secrets are
read-only; writable emptyDirs cover the RO root filesystem's write needs.
Ctx: root, isWorker, mediaWritable.
*/}}
{{- define "synapse.volumeMounts" -}}
- name: config-base
  mountPath: {{ include "synapse.paths.base" . }}
  readOnly: true
- name: config-shared
  mountPath: {{ include "synapse.paths.shared" . }}
  readOnly: true
- name: config-component
  mountPath: {{ include "synapse.paths.component" . }}
  readOnly: true
{{- if .isWorker }}
- name: config-dynamic
  mountPath: {{ include "synapse.paths.dynamic" . }}
  readOnly: true
{{- end }}
- name: secrets
  mountPath: {{ include "synapse.paths.secrets" . }}
  readOnly: true
- name: db-creds
  mountPath: /run/db
  readOnly: true
- name: tmp
  mountPath: /tmp
{{- if .mediaWritable }}
- name: media
  mountPath: {{ include "synapse.paths.media" . }}
{{- end }}
{{- end -}}

{{/*
The --config-path arguments, in merge order. Ctx: isWorker.
*/}}
{{- define "synapse.configPathArgs" -}}
- --config-path
- {{ include "synapse.paths.base" . }}
- --config-path
- {{ include "synapse.paths.shared" . }}
- --config-path
- {{ include "synapse.paths.component" . }}
{{- if .isWorker }}
- --config-path
- {{ include "synapse.paths.dynamic" . }}
{{- end }}
{{- end -}}

{{/*
The init container: makes a 0600 copy of the passfile (libpq refuses a
group/world-readable .pgpass) and, for workers, writes the per-pod worker_name.
Ctx: root, isWorker, mediaWritable.
*/}}
{{- define "synapse.initContainer" -}}
- name: config-init
  image: {{ include "synapse.image" .root }}
  imagePullPolicy: {{ .root.Values.image.pullPolicy }}
  command:
    - /bin/sh
    - -c
    - |
      set -eu
      if [ -f {{ include "synapse.paths.secrets" . }}/pgpass ]; then
        cp {{ include "synapse.paths.secrets" . }}/pgpass {{ include "synapse.paths.pgpass" . }}
        chmod 0600 {{ include "synapse.paths.pgpass" . }}
      fi
      {{- if .isWorker }}
      printf 'worker_name: %s\n' "$POD_NAME" > {{ include "synapse.paths.dynamic" . }}/00-worker-name.yaml
      {{- end }}
  env:
    - name: POD_NAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.name
  securityContext:
    {{- include "synapse.containerSecurityContext" (dict "root" .root "overrides" dict) | nindent 4 }}
  volumeMounts:
    - name: secrets
      mountPath: {{ include "synapse.paths.secrets" . }}
      readOnly: true
    - name: db-creds
      mountPath: /run/db
    {{- if .isWorker }}
    - name: config-dynamic
      mountPath: {{ include "synapse.paths.dynamic" . }}
    {{- end }}
{{- end -}}

{{/*
Merged pod/container security contexts (global deep-merged with per-component
overrides). Ctx: root, overrides.
*/}}
{{- define "synapse.podSecurityContext" -}}
{{- $merged := mergeOverwrite (deepCopy .root.Values.podSecurityContext) (.overrides | default dict) -}}
{{- toYaml $merged -}}
{{- end -}}

{{- define "synapse.containerSecurityContext" -}}
{{- $merged := mergeOverwrite (deepCopy .root.Values.containerSecurityContext) (.overrides | default dict) -}}
{{- toYaml $merged -}}
{{- end -}}
