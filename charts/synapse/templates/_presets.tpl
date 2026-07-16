{{/*
Worker presets, ported verbatim from the fork's
docker/configure_workers_and_start.py WORKERS_CONFIG, augmented with the
singleton rules enforced at runtime in synapse/config/workers.py.

Per preset:
  listeners:  subset of [client, federation, media, replication]
  endpoints:  raw upstream regexes (transformed for full-match at render time)
  streams:    stream_writers streams this type writes (adds instance_map entry)
  dutiesList: shared-config list duties (worker appended to the list)
  dutiesSingle: shared-config single-instance duties (pinned to ordinal 0)
  sharedConf: extra shared config contributed by this type
  workerConf: per-worker config for pods of this type
  singleton:  true => template fails if the owning group has replicas > 1
              (matches `!= 1` checks in workers.py + single-instance duties)

Consume with: $presets := fromYaml (include "synapse.presets" .)
*/}}
{{- define "synapse.presets" -}}
pusher:
  listeners: []
  endpoints: []
  dutiesList: [pusher_instances]
  singleton: false
user_dir:
  listeners: [client]
  endpoints:
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/user_directory/search$'
  dutiesSingle: [update_user_directory_from_worker]
  singleton: false
media_repository:
  listeners: [media, client, replication]
  endpoints:
    - '^/_matrix/media/'
    - '^/_synapse/admin/v1/purge_media_cache$'
    - '^/_synapse/admin/v1/room/.*/media.*$'
    - '^/_synapse/admin/v1/user/.*/media.*$'
    - '^/_synapse/admin/v1/media/.*$'
    - '^/_synapse/admin/v1/quarantine_media/.*$'
    - '^/_matrix/client/v1/media/.*$'
    - '^/_matrix/federation/v1/media/.*$'
  dutiesSingle: [media_instance_running_background_jobs]
  sharedConf:
    enable_media_repo: false
  workerConf:
    enable_media_repo: true
  singleton: false
appservice:
  listeners: []
  endpoints: []
  dutiesSingle: [notify_appservices_from_worker]
  singleton: true
federation_sender:
  listeners: []
  endpoints: []
  dutiesList: [federation_sender_instances]
  singleton: false
synchrotron:
  listeners: [client]
  endpoints:
    - '^/_matrix/client/(v2_alpha|r0|v3)/sync$'
    - '^/_matrix/client/(api/v1|v2_alpha|r0|v3)/events$'
    - '^/_matrix/client/(api/v1|r0|v3)/initialSync$'
    - '^/_matrix/client/(api/v1|r0|v3)/rooms/[^/]+/initialSync$'
  singleton: false
client_reader:
  listeners: [client]
  endpoints:
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/publicRooms$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/joined_members$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/context/.*$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/members$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/state$'
    - '^/_matrix/client/v1/rooms/.*/hierarchy$'
    - '^/_matrix/client/(v1|unstable)/rooms/.*/relations/'
    - '^/_matrix/client/v1/rooms/.*/threads$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/login$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/account/3pid$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/account/whoami$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/account/deactivate$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/devices(/|$)'
    - '^/_matrix/client/(r0|v3)/delete_devices$'
    - '^/_matrix/client/versions$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/voip/turnServer$'
    - '^/_matrix/client/(r0|v3|unstable)/register$'
    - '^/_matrix/client/(r0|v3|unstable)/register/available$'
    - '^/_matrix/client/(r0|v3|unstable)/auth/.*/fallback/web$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/messages$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/event'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/joined_rooms'
    - '^/_matrix/client/(api/v1|r0|v3|unstable/.*)/rooms/.*/aliases'
    - '^/_matrix/client/v1/rooms/.*/timestamp_to_event$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/search'
    - '^/_matrix/client/(r0|v3|unstable)/user/.*/filter(/|$)'
    - '^/_matrix/client/(r0|v3|unstable)/password_policy$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/directory/room/.*$'
    - '^/_matrix/client/(r0|v3|unstable)/capabilities$'
    - '^/_matrix/client/(r0|v3|unstable)/notifications$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/keys/upload'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/keys/device_signing/upload$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/keys/signatures/upload$'
    - '^/_matrix/client/unstable/org.matrix.msc4140/delayed_events(/.*/restart)?$'
  singleton: false
federation_reader:
  listeners: [federation]
  endpoints:
    - '^/_matrix/federation/v1/version$'
    - '^/_matrix/federation/(v1|v2)/event/'
    - '^/_matrix/federation/(v1|v2)/state/'
    - '^/_matrix/federation/(v1|v2)/state_ids/'
    - '^/_matrix/federation/(v1|v2)/backfill/'
    - '^/_matrix/federation/(v1|v2)/get_missing_events/'
    - '^/_matrix/federation/(v1|v2)/publicRooms'
    - '^/_matrix/federation/(v1|v2)/query/'
    - '^/_matrix/federation/(v1|v2)/make_join/'
    - '^/_matrix/federation/(v1|v2)/make_leave/'
    - '^/_matrix/federation/(v1|v2)/send_join/'
    - '^/_matrix/federation/(v1|v2)/send_leave/'
    - '^/_matrix/federation/v1/make_knock/'
    - '^/_matrix/federation/v1/send_knock/'
    - '^/_matrix/federation/(v1|v2)/invite/'
    - '^/_matrix/federation/(v1|v2)/query_auth/'
    - '^/_matrix/federation/(v1|v2)/event_auth/'
    - '^/_matrix/federation/v1/timestamp_to_event/'
    - '^/_matrix/federation/(v1|v2)/exchange_third_party_invite/'
    - '^/_matrix/federation/(v1|v2)/user/devices/'
    - '^/_matrix/federation/(v1|v2)/get_groups_publicised$'
    - '^/_matrix/key/v2/query'
  singleton: false
federation_inbound:
  listeners: [federation]
  endpoints:
    - '/_matrix/federation/(v1|v2)/send/'
  singleton: false
event_persister:
  listeners: [replication]
  endpoints: []
  streams: [events]
  singleton: false
background_worker:
  listeners: []
  endpoints: []
  dutiesSingle: [run_background_tasks_on]
  singleton: true
event_creator:
  listeners: [client]
  endpoints:
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/redact'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/send'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/(join|invite|leave|ban|unban|kick)$'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/join/'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/knock/'
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/profile/'
  singleton: false
account_data:
  listeners: [client, replication]
  endpoints:
    - '^/_matrix/client/(r0|v3|unstable)/.*/tags'
    - '^/_matrix/client/(r0|v3|unstable)/.*/account_data'
  streams: [account_data]
  singleton: true
presence:
  listeners: [client, replication]
  endpoints:
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/presence/'
  streams: [presence]
  singleton: true
receipts:
  listeners: [client, replication]
  endpoints:
    - '^/_matrix/client/(r0|v3|unstable)/rooms/.*/receipt'
    - '^/_matrix/client/(r0|v3|unstable)/rooms/.*/read_markers'
  streams: [receipts]
  singleton: false
to_device:
  listeners: [client, replication]
  endpoints:
    - '^/_matrix/client/(r0|v3|unstable)/sendToDevice/'
  streams: [to_device]
  singleton: true
device_lists:
  listeners: [client, replication]
  endpoints: []
  streams: [device_lists]
  singleton: false
typing:
  listeners: [client, replication]
  endpoints:
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/rooms/.*/typing'
  streams: [typing]
  singleton: true
push_rules:
  listeners: [client, replication]
  endpoints:
    - '^/_matrix/client/(api/v1|r0|v3|unstable)/pushrules/'
  streams: [push_rules]
  singleton: true
thread_subscriptions:
  listeners: [client, replication]
  endpoints:
    - '^/_matrix/client/unstable/io.element.msc4306/.*'
  streams: [thread_subscriptions]
  singleton: false
{{- end -}}

{{/*
Transform a raw upstream regex into a full-match regex for Gateway API
RegularExpression matches (Envoy safe_regex / RE2 matches the entire :path).
Upstream patterns are nginx partial matches, so append `.*` unless the pattern
already ends with `$` (anchored) or `.*` (already open-ended).
*/}}
{{- define "synapse.pathRegex" -}}
{{- $p := . -}}
{{- if or (hasSuffix "$" $p) (hasSuffix ".*" $p) -}}
{{- $p -}}
{{- else -}}
{{- printf "%s.*" $p -}}
{{- end -}}
{{- end -}}

{{/*
Derive the merged facts for a worker group from its presets.
Ctx: root, group. Returns YAML:
  httpResources: subset of [client, federation, media] (fixed order)
  hasReplication: bool
  routed: bool            # has any endpoint => gets an HTTPRoute rule
  singleton: bool         # any preset is singleton-only => replicas must be 1
  probePort: 8008 | 9093
  mediaWritable: bool
  streams: [..]
  endpoints: [..]         # merged raw upstream regexes
*/}}
{{- define "synapse.groupInfo" -}}
{{- $presets := fromYaml (include "synapse.presets" .root) -}}
{{- $listeners := list -}}
{{- $endpoints := list -}}
{{- $streams := list -}}
{{- $singleton := false -}}
{{- $media := false -}}
{{- range $t := .group.types -}}
{{- $p := index $presets $t -}}
{{- if not $p }}{{- fail (printf "worker group %q references unknown preset %q" $.group.name $t) }}{{- end -}}
{{- with $p.listeners }}{{- $listeners = concat $listeners . }}{{- end -}}
{{- with $p.endpoints }}{{- $endpoints = concat $endpoints . }}{{- end -}}
{{- with $p.streams }}{{- $streams = concat $streams . }}{{- end -}}
{{- if $p.singleton }}{{- $singleton = true }}{{- end -}}
{{- if eq $t "media_repository" }}{{- $media = true }}{{- end -}}
{{- end -}}
{{- $http := list -}}
{{- range $r := (list "client" "federation" "media") -}}
{{- if has $r $listeners }}{{- $http = append $http $r }}{{- end -}}
{{- end -}}
{{- $hasRepl := has "replication" $listeners -}}
{{- $probePort := 9093 -}}
{{- if $http }}{{- $probePort = 8008 }}{{- end -}}
httpResources: {{ $http | toJson }}
hasReplication: {{ $hasRepl }}
routed: {{ gt (len $endpoints) 0 }}
singleton: {{ $singleton }}
probePort: {{ $probePort }}
mediaWritable: {{ $media }}
streams: {{ $streams | toJson }}
endpoints: {{ $endpoints | toJson }}
{{- end -}}
