{{/*
The chart-owned shared config fragment, identical on every pod. Emits the
secrets *_path options, redis, enable_metrics, and — in worker mode — the
replication topology (instance_map, stream_writers, *_instances, single-instance
duties) computed from workers.groups and the worker presets.

Returns YAML. Consumed by configmap-shared.yaml and the pod checksum.
*/}}
{{- define "synapse.sharedConfigYaml" -}}
{{- $root := . -}}
{{- $fullname := include "synapse.fullname" $root -}}
{{- $ns := $root.Release.Namespace -}}
{{/* ---- secrets *_path ---- */}}
{{- range $spec := (fromYamlArray (include "synapse.secretSpecs" $root)) }}
{{- if and $spec.workersOnly (not $root.Values.workers.enabled) }}{{- else }}
{{- $name := include "synapse.resolveSecretName" (dict "ref" (index $root.Values.secrets $spec.key) "default" $root.Values.secrets.existingSecret) }}
{{- if $name }}
{{ $spec.option }}: {{ include "synapse.paths.secrets" $root }}/{{ $spec.file }}
{{- end }}
{{- end }}
{{- end }}
{{/* ---- redis ---- */}}
{{- if include "synapse.redisEnabled" $root }}
redis:
  enabled: true
  host: {{ required "redis.host is required when workers are enabled" $root.Values.redis.host | quote }}
  port: {{ $root.Values.redis.port }}
  {{- $redisName := include "synapse.resolveSecretName" (dict "ref" $root.Values.redis.passwordSecret "default" $root.Values.secrets.existingSecret) }}
  {{- if $redisName }}
  password_path: {{ include "synapse.paths.secrets" $root }}/redis_password
  {{- end }}
{{- end }}
{{/* ---- metrics ---- */}}
{{- if $root.Values.metrics.enabled }}
enable_metrics: true
{{- end }}
{{/* ---- worker replication topology ---- */}}
{{- if $root.Values.workers.enabled }}
{{- $presets := fromYaml (include "synapse.presets" $root) }}
{{- $instanceMap := dict }}
{{- $streamWriters := dict }}
{{- $pusher := list }}
{{- $fedSender := list }}
{{- $single := dict }}
{{- $anyMedia := false }}
{{- range $g := $root.Values.workers.groups }}
{{- $sts := printf "%s-%s" $fullname $g.name }}
{{- $replicas := int ($g.replicas | default 1) }}
{{- $streams := list }}
{{- $dutiesList := list }}
{{- $dutiesSingle := list }}
{{- range $t := $g.types }}
{{- $p := index $presets $t }}
{{- if not $p }}{{- fail (printf "worker group %q references unknown preset %q" $g.name $t) }}{{- end }}
{{- with $p.streams }}{{- $streams = concat $streams . }}{{- end }}
{{- with $p.dutiesList }}{{- $dutiesList = concat $dutiesList . }}{{- end }}
{{- with $p.dutiesSingle }}{{- $dutiesSingle = concat $dutiesSingle . }}{{- end }}
{{- if eq $t "media_repository" }}{{- $anyMedia = true }}{{- end }}
{{- end }}
{{- range $i := until $replicas }}
{{- $inst := printf "%s-%d" $sts $i }}
{{- $dns := printf "%s.%s.%s.svc.cluster.local" $inst $sts $ns }}
{{- range $s := $streams }}
{{- $_ := set $streamWriters $s (append (index $streamWriters $s | default list) $inst) }}
{{- $_ := set $instanceMap $inst (dict "host" $dns "port" 9093) }}
{{- end }}
{{- if has "pusher_instances" $dutiesList }}{{- $pusher = append $pusher $inst }}{{- end }}
{{- if has "federation_sender_instances" $dutiesList }}{{- $fedSender = append $fedSender $inst }}{{- end }}
{{- end }}
{{- $inst0 := printf "%s-0" $sts }}
{{- range $d := $dutiesSingle }}{{- $_ := set $single $d $inst0 }}{{- end }}
{{- end }}
{{- $_ := set $instanceMap "main" (dict "host" (printf "%s-main-0.%s-main.%s.svc.cluster.local" $fullname $fullname $ns) "port" 9093) }}
instance_map:
{{ toYaml $instanceMap | indent 2 }}
{{- if $streamWriters }}
stream_writers:
{{ toYaml $streamWriters | indent 2 }}
{{- end }}
{{- if $pusher }}
pusher_instances:
{{ toYaml $pusher | indent 2 }}
{{- end }}
{{- if $fedSender }}
federation_sender_instances:
{{ toYaml $fedSender | indent 2 }}
{{- end }}
{{- range $d, $inst := $single }}
{{ $d }}: {{ $inst }}
{{- end }}
{{- if $anyMedia }}
enable_media_repo: false
{{- end }}
{{- end }}
{{- end -}}
