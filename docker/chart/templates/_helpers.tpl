{{- define "extractGrpcPortFromMultiaddr" -}}
{{- $parts := splitList "/" .Values.node.grpc_multiaddr -}}
{{- $port := last $parts -}}
{{- if and ($port) (regexMatch "^\\d+$" $port) -}}
{{- $port -}}
{{- else -}}
{{- fail "Invalid grpc_multiaddr format. Expected /ip4/<ADDRESS>/<PROTOCOL>/<PORT>" -}}
{{- end -}}
{{- end -}}

{{- define "extractRestPortFromMultiaddr" -}}
{{- $parts := splitList "/" .Values.node.rest_multiaddr -}}
{{- $port := last $parts -}}
{{- if and ($port) (regexMatch "^\\d+$" $port) -}}
{{- $port -}}
{{- else -}}
{{- fail "Invalid rest_multiaddr format. Expected /ip4/<ADDRESS>/<PROTOCOL>/<PORT>" -}}
{{- end -}}
{{- end -}}
