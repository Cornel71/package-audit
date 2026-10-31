{{- define "pkgaudit.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 50 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "pkgaudit.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "pkgaudit.webSelector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: web
{{- end -}}

{{- define "pkgaudit.dbSelector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "pkgaudit.secretName" -}}
{{ default (printf "%s-secrets" (include "pkgaudit.fullname" .)) .Values.secrets.existingSecret }}
{{- end -}}

{{- define "pkgaudit.tlsSecret" -}}
{{ default (printf "%s-tls" (include "pkgaudit.fullname" .)) .Values.tls.secretName }}
{{- end -}}

{{- define "pkgaudit.image" -}}
{{ printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end -}}

{{- define "pkgaudit.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- range . }}
  - name: {{ .name }}
  {{- end }}
{{- end }}
{{- end -}}

{{/* Secret environment for the init container and the web container. Empty with Vault: the agent writes /vault/secrets/app.env instead. */}}
{{- define "pkgaudit.env" -}}
{{- if not .Values.vault.enabled }}
{{- $sec := include "pkgaudit.secretName" . -}}
{{- if .Values.postgres.enabled }}
- name: POSTGRES_PASSWORD
  valueFrom: {secretKeyRef: {name: {{ $sec }}, key: POSTGRES_PASSWORD}}
- name: DATABASE_URL
  value: "postgresql+psycopg://pkgaudit:$(POSTGRES_PASSWORD)@{{ include "pkgaudit.fullname" . }}-postgres:5432/pkgaudit"
{{- else }}
- name: DATABASE_URL
  valueFrom: {secretKeyRef: {name: {{ $sec }}, key: DATABASE_URL}}
{{- end }}
- name: SECRET_KEY
  valueFrom: {secretKeyRef: {name: {{ $sec }}, key: SECRET_KEY}}
- name: FERNET_KEY
  valueFrom: {secretKeyRef: {name: {{ $sec }}, key: FERNET_KEY}}
{{- if .Values.ldap.enabled }}
- name: LDAP_BIND_PASSWORD
  valueFrom: {secretKeyRef: {name: {{ $sec }}, key: LDAP_BIND_PASSWORD}}
{{- end }}
{{- end }}
{{- end -}}

{{/* ---- Vault Agent Injector ----
     Vault templates contain {{ }} themselves, so they are written as raw strings that Helm does not evaluate. */}}
{{- define "pkgaudit.vaultAppTemplate" -}}
{{- $path := printf "%s/data/%s" .Values.vault.mount .Values.vault.paths.app -}}
{{- $db := `DATABASE_URL="{{ .Data.data.DATABASE_URL }}"` -}}
{{- if .Values.postgres.enabled -}}
{{- $db = `DATABASE_URL="postgresql+psycopg://pkgaudit:{{ .Data.data.POSTGRES_PASSWORD }}@HOST:5432/pkgaudit"` | replace "HOST" (printf "%s-postgres" (include "pkgaudit.fullname" .)) -}}
{{- end -}}
{{- $ldap := "" -}}
{{- if .Values.ldap.enabled -}}
{{- $ldap = `{{ with .Data.data.LDAP_BIND_PASSWORD }}LDAP_BIND_PASSWORD="{{ . }}"{{ end }}` -}}
{{- end -}}
{{- `{{- with secret "PATH" -}}
SECRET_KEY="{{ .Data.data.SECRET_KEY }}"
FERNET_KEY="{{ .Data.data.FERNET_KEY }}"
DBLINE
LDAPLINE
{{- end }}` | replace "PATH" $path | replace "DBLINE" $db | replace "LDAPLINE" $ldap -}}
{{- end -}}

{{- define "pkgaudit.vaultCommon" -}}
vault.hashicorp.com/agent-inject: "true"
vault.hashicorp.com/agent-pre-populate-only: "true"
vault.hashicorp.com/role: {{ .Values.vault.role | quote }}
vault.hashicorp.com/auth-path: {{ .Values.vault.authPath | quote }}
{{- with .Values.vault.address }}
vault.hashicorp.com/service: {{ . | quote }}
{{- end }}
{{- with .Values.vault.extraAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "pkgaudit.vaultWebAnnotations" -}}
{{ include "pkgaudit.vaultCommon" . }}
vault.hashicorp.com/agent-init-first: "true"
vault.hashicorp.com/agent-inject-secret-app.env: {{ printf "%s/data/%s" .Values.vault.mount .Values.vault.paths.app | quote }}
vault.hashicorp.com/agent-inject-template-app.env: |
{{ include "pkgaudit.vaultAppTemplate" . | indent 2 }}
{{- end -}}

{{- define "pkgaudit.vaultDbAnnotations" -}}
{{ include "pkgaudit.vaultCommon" . }}
vault.hashicorp.com/agent-inject-secret-pgpass: {{ printf "%s/data/%s" .Values.vault.mount .Values.vault.paths.app | quote }}
vault.hashicorp.com/agent-inject-template-pgpass: |
{{ `{{- with secret "` | indent 2 }}{{ printf "%s/data/%s" .Values.vault.mount .Values.vault.paths.app }}{{ `" -}}{{ .Data.data.POSTGRES_PASSWORD }}{{- end -}}` }}
{{- end -}}
