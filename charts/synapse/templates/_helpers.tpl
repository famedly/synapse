{{/*
Common naming and label helpers.
*/}}

{{- define "synapse.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Base fullname for the release (used as the prefix for every component).
*/}}
{{- define "synapse.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "synapse.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Component fullname: "<release-fullname>-<component>". Callers pass the component
name (e.g. "main" or a worker group name) as .component alongside the root ctx.
Usage: include "synapse.componentFullname" (dict "root" $ "component" "main")
*/}}
{{- define "synapse.componentFullname" -}}
{{- printf "%s-%s" (include "synapse.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Chart-wide labels applied to every object.
*/}}
{{- define "synapse.labels" -}}
helm.sh/chart: {{ include "synapse.chart" . }}
{{ include "synapse.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: synapse
{{- end -}}

{{- define "synapse.selectorLabels" -}}
app.kubernetes.io/name: {{ include "synapse.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Component-scoped labels/selector. Adds app.kubernetes.io/component so each
StatefulSet/Service selects only its own pods.
Usage: include "synapse.componentLabels" (dict "root" $ "component" "main")
*/}}
{{- define "synapse.componentLabels" -}}
{{ include "synapse.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "synapse.componentSelectorLabels" -}}
{{ include "synapse.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Image reference, defaulting the tag to the chart appVersion.
*/}}
{{- define "synapse.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Resolve a secret reference. Given a ref dict {secretName, key} and a default
secret name, returns the effective secret name (ref.secretName or the default).
Fails if neither is set.
Usage: include "synapse.secretName" (dict "ref" .Values.secrets.signingKey "default" .Values.secrets.existingSecret "what" "signingKey")
*/}}
{{- define "synapse.secretName" -}}
{{- $name := .ref.secretName | default .default -}}
{{- if not $name -}}
{{- fail (printf "secret reference %q must set secretName or secrets.existingSecret must be set" .what) -}}
{{- end -}}
{{- $name -}}
{{- end -}}
