{{/*
Expand the name of the chart.
*/}}
{{- define "unifi-network-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "unifi-network-operator.fullname" -}}
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
{{- define "unifi-network-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "unifi-network-operator.labels" -}}
helm.sh/chart: {{ include "unifi-network-operator.chart" . }}
{{ include "unifi-network-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "unifi-network-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "unifi-network-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
control-plane: controller-manager
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "unifi-network-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "unifi-network-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the secret to use
*/}}
{{- define "unifi-network-operator.secretName" -}}
{{- if .Values.unifi.existingSecret }}
{{- .Values.unifi.existingSecret }}
{{- else }}
{{- include "unifi-network-operator.fullname" . }}-unifi
{{- end }}
{{- end }}

{{/*
Create the name of the configmap to use
*/}}
{{- define "unifi-network-operator.configMapName" -}}
{{- if .Values.config.existingConfigMap }}
{{- .Values.config.existingConfigMap }}
{{- else }}
{{- include "unifi-network-operator.fullname" . }}-config
{{- end }}
{{- end }}
