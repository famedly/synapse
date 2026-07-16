{{/*
The pod spec shared by the main and worker StatefulSets.
Ctx: root, component, module ("homeserver"|"generic_worker"), isWorker,
     httpResources (list), hasReplication (bool), mediaWritable (bool),
     componentConfigMap (name), values (per-component overrides map).
*/}}
{{- define "synapse.podSpec" -}}
{{- $root := .root -}}
{{- $v := .values -}}
{{- $probePort := 9093 -}}
{{- if .httpResources }}{{- $probePort = 8008 }}{{- end }}
{{- with $root.Values.image.pullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
terminationGracePeriodSeconds: {{ $v.terminationGracePeriodSeconds | default 60 }}
securityContext:
  {{- include "synapse.podSecurityContext" (dict "root" $root "overrides" ($v.podSecurityContext | default dict)) | nindent 2 }}
{{- with $v.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $v.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $v.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $v.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
initContainers:
  {{- include "synapse.initContainer" (dict "root" $root "isWorker" .isWorker "mediaWritable" .mediaWritable) | nindent 2 }}
containers:
  - name: synapse
    image: {{ include "synapse.image" $root }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    command: ["python", "-m", "synapse.app.{{ .module }}"]
    args:
      {{- include "synapse.configPathArgs" (dict "isWorker" .isWorker) | nindent 6 }}
    ports:
      {{- if .httpResources }}
      - name: http
        containerPort: 8008
      {{- end }}
      {{- if .hasReplication }}
      - name: replication
        containerPort: 9093
      {{- end }}
      {{- if $root.Values.metrics.enabled }}
      - name: metrics
        containerPort: 9090
      {{- end }}
    startupProbe:
      httpGet:
        path: /health
        port: {{ $probePort }}
      periodSeconds: 10
      failureThreshold: 60
      {{- with $v.probes }}{{- with .startup }}
      {{- toYaml . | nindent 6 }}
      {{- end }}{{- end }}
    livenessProbe:
      httpGet:
        path: /health
        port: {{ $probePort }}
      periodSeconds: 10
      failureThreshold: 3
      {{- with $v.probes }}{{- with .liveness }}
      {{- toYaml . | nindent 6 }}
      {{- end }}{{- end }}
    readinessProbe:
      httpGet:
        path: /health
        port: {{ $probePort }}
      periodSeconds: 10
      failureThreshold: 3
      {{- with $v.probes }}{{- with .readiness }}
      {{- toYaml . | nindent 6 }}
      {{- end }}{{- end }}
    securityContext:
      {{- include "synapse.containerSecurityContext" (dict "root" $root "overrides" ($v.containerSecurityContext | default dict)) | nindent 6 }}
    {{- with $v.resources }}
    resources:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    volumeMounts:
      {{- include "synapse.volumeMounts" (dict "root" $root "isWorker" .isWorker "mediaWritable" .mediaWritable) | nindent 6 }}
volumes:
  {{- include "synapse.volumes" (dict "root" $root "isWorker" .isWorker "mediaWritable" .mediaWritable "componentConfigMap" .componentConfigMap) | nindent 2 }}
{{- end -}}

{{/*
The checksum used to roll pods together on any config change, plus the manual
restartNonce. Ctx: root, component, isWorker, group (for workers).
*/}}
{{- define "synapse.configChecksum" -}}
{{- $root := .root -}}
{{- $base := "" -}}
{{- if $root.Values.config.existingConfigMap -}}
{{- $base = $root.Values.config.existingConfigMap -}}
{{- else -}}
{{- $base = toYaml $root.Values.config.settings -}}
{{- end -}}
{{- $shared := include "synapse.sharedConfigYaml" $root -}}
{{- $component := "" -}}
{{- if .isWorker -}}
{{- $component = include "synapse.componentConfigYaml" (dict "root" $root "isWorker" true "group" .group) -}}
{{- else -}}
{{- $component = include "synapse.componentConfigYaml" (dict "root" $root "isWorker" false) -}}
{{- end -}}
{{- printf "%s|%s|%s|%s" $base $shared $component ($root.Values.restartNonce | toString) | sha256sum -}}
{{- end -}}
