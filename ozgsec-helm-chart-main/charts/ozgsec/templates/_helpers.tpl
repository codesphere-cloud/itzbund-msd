{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ozgsec.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ozgsec.labels" -}}
helm.sh/chart: {{ include "ozgsec.chart" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "keycloak.hostname" -}}
{{- if and .Values.keycloak.ingress.enabled .Values.keycloak.ingress.hosts -}}
  {{- get (index .Values.keycloak.ingress.hosts 0 | default dict) "host" -}}
{{- else -}}
  keycloak.{{ .Release.Namespace }}.svc.cluster.local:8080
{{- end -}}
{{- end -}}

{{- define "keycloak.hostnameAndProtocol" -}}
{{- if and .Values.keycloak.ingress.enabled .Values.keycloak.ingress.tls -}}
    https://{{ include "keycloak.hostname" . }}
{{- else -}}
    http://{{ include "keycloak.hostname" . }}
{{- end -}}
{{- end -}}

{{- define "webFrontend.hostname" -}}
{{- if and .Values.webFrontend.ingress.enabled .Values.webFrontend.ingress.hosts -}}
  {{- get (index .Values.webFrontend.ingress.hosts 0 | default dict ) "host" -}}
{{- else -}}
  web-frontend-service.{{ .Release.Namespace }}.svc.cluster.local:3000
{{- end -}}
{{- end -}}

{{- define "webFrontend.hostnameAndProtocol" -}}
{{- if and .Values.webFrontend.ingress.enabled .Values.webFrontend.ingress.tls -}}
    https://{{ include "webFrontend.hostname" . }}
{{- else -}}
    http://{{ include "webFrontend.hostname" . }}
{{- end -}}
{{- end -}}
