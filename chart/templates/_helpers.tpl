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

{{/*
Labels of an object, from a dict: "root", the context of the chart, and
optionally "component", the component of the object, and "extra", the labels
of the object that the values give, which win over extraLabels. The labels of
the chart win over both: its selectors rely on them.
*/}}
{{- define "tsigoat.objectLabels" -}}
{{- $root := .root -}}
helm.sh/chart: {{ include "tsigoat.chart" $root }}
{{ include "tsigoat.selectorLabels" $root }}
app.kubernetes.io/version: {{ $root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ $root.Release.Service }}
{{- with .component }}
app.kubernetes.io/component: {{ . }}
{{- end }}
{{- $extra := merge (deepCopy (.extra | default dict)) ($root.Values.extraLabels | default dict) }}
{{- with omit $extra "helm.sh/chart" "app.kubernetes.io/name" "app.kubernetes.io/instance" "app.kubernetes.io/version" "app.kubernetes.io/managed-by" "app.kubernetes.io/component" }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Labels of an object with neither a component nor labels of its own.
*/}}
{{- define "tsigoat.labels" -}}
{{- include "tsigoat.objectLabels" (dict "root" .) -}}
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
registry leaves the reference without one. A tag that image.digests holds,
as the release writes the digests of its tags, is pulled by that digest: the
digest of a multi-platform image, the same on every registry.
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
{{- $tag := printf "%s%s" (default .Chart.AppVersion .Values.image.tag | toString) (.Values.image.tagSuffix | toString) -}}
{{- $digest := "" -}}
{{- if .Values.image.pinDigest -}}
{{- $digest = get (.Values.image.digests | default dict) $tag -}}
{{- end -}}
{{- if $digest -}}
{{- printf "%s:%s@%s" $repository $tag $digest -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Listen addresses inside the pod, an IPv6 host in brackets. The DNS server
listens on 5353, which the administration server cannot take.
*/}}
{{- define "tsigoat.listenHost" -}}
{{- $host := .Values.listenHost -}}
{{- if and (contains ":" $host) (not (hasPrefix "[" $host)) -}}
{{- printf "[%s]" $host -}}
{{- else -}}
{{- $host -}}
{{- end -}}
{{- end -}}

{{- define "tsigoat.dnsListen" -}}
{{- printf "%s:5353" (include "tsigoat.listenHost" .) -}}
{{- end -}}

{{- define "tsigoat.adminListen" -}}
{{- if eq (int .Values.admin.port) 5353 -}}
{{- fail "admin.port is 5353, the DNS port of the container: choose another port" -}}
{{- end -}}
{{- printf "%s:%d" (include "tsigoat.listenHost" .) (int .Values.admin.port) -}}
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
{{- fail (printf "config.keys[%v].secret would store a TSIG secret in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with secretFile" $i) -}}
{{- end -}}
{{- end -}}
{{- range $i, $backend := $config.backends -}}
{{- if and (kindIs "map" $backend) (kindIs "map" $backend.powerdns) (hasKey $backend.powerdns "apiKey") -}}
{{- fail (printf "config.backends[%v].powerdns.apiKey would store an API key in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with apiKeyFile" $i) -}}
{{- end -}}
{{- if and (kindIs "map" $backend) (kindIs "map" $backend.rfc2136) (kindIs "map" $backend.rfc2136.key) (hasKey $backend.rfc2136.key "secret") -}}
{{- fail (printf "config.backends[%v].rfc2136.key.secret would store a TSIG secret in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with secretFile" $i) -}}
{{- end -}}
{{- range $setting := list "cloudflare.apiToken" "ovh.applicationSecret" "ovh.consumerKey" "scaleway.secretKey" -}}
{{- $section := index (splitList "." $setting) 0 -}}
{{- $field := index (splitList "." $setting) 1 -}}
{{- if and (kindIs "map" $backend) (kindIs "map" (index $backend $section)) (hasKey (index $backend $section) $field) -}}
{{- fail (printf "config.backends[%v].%s would store a secret in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with %sFile" $i $setting $field) -}}
{{- end -}}
{{- end -}}
{{- if and (kindIs "map" $backend) (kindIs "map" $backend.ovh) (kindIs "map" $backend.ovh.oauth2) (hasKey $backend.ovh.oauth2 "clientSecret") -}}
{{- fail (printf "config.backends[%v].ovh.oauth2.clientSecret would store a secret in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with clientSecretFile" $i) -}}
{{- end -}}
{{- if and (kindIs "map" $backend) (kindIs "map" $backend.webhook) -}}
{{- range $j, $header := $backend.webhook.headers -}}
{{- if and (kindIs "map" $header) (hasKey $header "value") -}}
{{- fail (printf "config.backends[%v].webhook.headers[%v].value would store a header in a ConfigMap, where the chart cannot tell a secret header from another: put it in the Secret, see secret.files and secret.existingSecret, and read it with valueFile" $i $j) -}}
{{- end -}}
{{- end -}}
{{- range $setting := list "signature.secret" "basicAuth.password" "bearer.token" -}}
{{- $section := index (splitList "." $setting) 0 -}}
{{- $field := index (splitList "." $setting) 1 -}}
{{- $settings := index $backend.webhook $section -}}
{{- if and (kindIs "map" $settings) (hasKey $settings $field) -}}
{{- fail (printf "config.backends[%v].webhook.%s would store a secret in a ConfigMap: put it in the Secret, see secret.files and secret.existingSecret, and read it with %sFile" $i $setting $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- toYaml $config -}}
{{- end -}}
