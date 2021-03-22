{{/*
Expand the name of the chart.
*/}}
{{- define "source-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "source-controller.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "source-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "source-controller.rbac.fullname" -}}
{{- (include "source-controller.fullname" .) | replace "-" ":" }}
{{- end }}

{{/*
Create common labels to all resources.
*/}}
{{- define "source-controller.labels" -}}
helm.sh/chart: {{ include "source-controller.chart" . }}
{{ include "source-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: fluxcd
app.kubernetes.io/component: source-controller
control-plane: controller
{{- end }}

{{/*
Create selector labels.
*/}}
{{- define "source-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "source-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "source-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "source-controller.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the appropriate apiVersion for deployments.
*/}}
{{- define "source-controller.deployment.apiVersion" -}}
{{- print "apps/v1" -}}
{{- end -}}

{{/*
Create the appropriate apiVersion for rbac.
*/}}
{{- define "source-controller.rbac.apiVersion" -}}
{{- if .Capabilities.APIVersions.Has "rbac.authorization.k8s.io/v1" }}
{{- print "rbac.authorization.k8s.io/v1" -}}
{{- else -}}
{{- print "rbac.authorization.k8s.io/v1beta1" -}}
{{- end -}}
{{- end -}}
