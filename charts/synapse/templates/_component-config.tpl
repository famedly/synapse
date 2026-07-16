{{/*
Per-component chart config fragment: listeners for the main process, or
worker_app + worker_listeners + per-worker extra config for a worker group.
Ctx: root, isWorker, group (the worker group map; omitted for main).
Returns YAML. Consumed by configmap-component.yaml and the pod checksum.
*/}}
{{- define "synapse.componentConfigYaml" -}}
{{- $root := .root -}}
{{- if .isWorker -}}
{{- $info := fromYaml (include "synapse.groupInfo" (dict "root" $root "group" .group)) -}}
worker_app: synapse.app.generic_worker
{{ include "synapse.listenersYaml" (dict "root" $root "key" "worker_listeners" "httpResources" $info.httpResources "hasReplication" $info.hasReplication) }}
{{- $presets := fromYaml (include "synapse.presets" $root) -}}
{{- $workerConf := dict -}}
{{- range $t := .group.types -}}
{{- $p := index $presets $t -}}
{{- with $p.workerConf }}{{- $workerConf = mergeOverwrite $workerConf (deepCopy .) }}{{- end -}}
{{- end -}}
{{- if $workerConf }}
{{ toYaml $workerConf }}
{{- end -}}
{{- else -}}
{{ include "synapse.listenersYaml" (dict "root" $root "key" "listeners" "httpResources" (list "client" "federation") "hasReplication" $root.Values.workers.enabled) }}
{{- end -}}
{{- end -}}
