{{/*
Name of the chart, unless overridden.
*/}}
{{- define "tsigoat.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Name of the resources: the release name, prefixed to the chart name unless it
contains it already. Truncated to 57 characters, so that suffixes such as
"-admin" keep the names within the 63 characters of a DNS label.
*/}}
{{- define "tsigoat.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 57 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 57 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 57 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "tsigoat.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride -}}
{{- end -}}

{{- define "tsigoat.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tsigoat.labels" -}}
helm.sh/chart: {{ include "tsigoat.chart" . }}
{{ include "tsigoat.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.extraLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "tsigoat.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tsigoat.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tsigoat.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tsigoat.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret mounted in /run/secrets/tsigoat, empty when there is none.
*/}}
{{- define "tsigoat.secretName" -}}
{{- if .Values.secret.existingSecret -}}
{{- .Values.secret.existingSecret -}}
{{- else if .Values.secret.files -}}
{{- include "tsigoat.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
Image reference: the digest takes precedence over the tag, which defaults to
the appVersion; global.imageRegistry overrides image.registry, and an empty
registry leaves the reference without one.
*/}}
{{- define "tsigoat.image" -}}
{{- $registry := .Values.image.registry -}}
{{- if and .Values.global .Values.global.imageRegistry -}}
{{- $registry = .Values.global.imageRegistry -}}
{{- end -}}
{{- $repository := .Values.image.repository -}}
{{- if $registry -}}
{{- $repository = printf "%s/%s" $registry $repository -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s%s" $repository (default .Chart.AppVersion .Values.image.tag | toString) (.Values.image.tagSuffix | toString) -}}
{{- end -}}
{{- end -}}

{{/*
Listen addresses inside the pod.
*/}}
{{- define "tsigoat.dnsListen" -}}
{{- printf "%s:5353" .Values.listenHost -}}
{{- end -}}

{{- define "tsigoat.adminListen" -}}
{{- printf "%s:%d" .Values.listenHost (int .Values.admin.port) -}}
{{- end -}}

{{/*
Configuration file of tsigoat. The chart owns the listen addresses, and keeps
the secrets out of the ConfigMap: they belong in the Secret mounted in
/run/secrets/tsigoat, or in environment variables.
*/}}
{{- define "tsigoat.config" -}}
{{- $config := .Values.config -}}
{{- if not $config.zones -}}
{{- fail "config.zones is empty: configure the zones that tsigoat serves, see https://github.com/enix/tsigoat/blob/main/docs/configuration.md" -}}
{{- end -}}
{{- if not $config.backends -}}
{{- fail "config.backends is empty: configure the backend that holds the zones, see https://github.com/enix/tsigoat/blob/main/docs/configuration.md" -}}
{{- end -}}
{{- if hasKey $config "listen" -}}
{{- fail "config.listen is set by the chart: change listenHost or service.port instead" -}}
{{- end -}}
{{- if hasKey $config "admin" -}}
{{- fail "config.admin is set by the chart: change listenHost or admin.port instead" -}}
{{- end -}}
{{- range $i, $key := $config.keys -}}
{{- if and (kindIs "map" $key) (hasKey $key "secret") -}}
{{- fail (printf "config.keys[%d].secret would store a TSIG secret in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with secretFile" $i) -}}
{{- end -}}
{{- end -}}
{{- range $i, $backend := $config.backends -}}
{{- if and (kindIs "map" $backend) (kindIs "map" $backend.powerdns) (hasKey $backend.powerdns "apiKey") -}}
{{- fail (printf "config.backends[%d].powerdns.apiKey would store an API key in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with apiKeyFile" $i) -}}
{{- end -}}
{{- if and (kindIs "map" $backend) (kindIs "map" $backend.rfc2136) (kindIs "map" $backend.rfc2136.key) (hasKey $backend.rfc2136.key "secret") -}}
{{- fail (printf "config.backends[%d].rfc2136.key.secret would store a TSIG secret in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with secretFile" $i) -}}
{{- end -}}
{{- if and (kindIs "map" $backend) (kindIs "map" $backend.webhook) -}}
{{- range $setting := list "signature.secret" "basicAuth.password" "bearer.token" -}}
{{- $section := index (splitList "." $setting) 0 -}}
{{- $field := index (splitList "." $setting) 1 -}}
{{- $settings := index $backend.webhook $section -}}
{{- if and (kindIs "map" $settings) (hasKey $settings $field) -}}
{{- fail (printf "config.backends[%d].webhook.%s would store a secret in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with %sFile" $i $setting $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- toYaml $config -}}
{{- end -}}
