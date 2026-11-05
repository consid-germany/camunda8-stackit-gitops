# PROD-only assertions (OpenSearch secondary storage, 3-AZ, monitoring on, Optimize on).
package prod

import data.lib
import rego.v1

storage := lib.orchestration_config.camunda.data["secondary-storage"]

# --- secondary storage = OpenSearch ---
deny contains msg if {
	storage.type != "opensearch"
	msg := sprintf("[prod][camunda] secondary-storage type = %q, want \"opensearch\"", [storage.type])
}

deny contains msg if {
	storage["autoconfigure-camunda-exporter"] != true
	msg := sprintf("[prod][camunda] autoconfigure-camunda-exporter = %v, want true", [storage["autoconfigure-camunda-exporter"]])
}

# --- Optimize enabled + its backup repository env ---
deny contains msg if {
	not lib.svc_exists("prod-camunda-optimize")
	msg := "[prod][camunda] Optimize Service missing; must be enabled in the OpenSearch profile"
}

deny contains msg if {
	got := object.get(lib.optimize_env, "CAMUNDA_OPTIMIZE_BACKUP_REPOSITORY_NAME", "<missing>")
	got != "camunda-backup"
	msg := sprintf("[prod][camunda] optimize env CAMUNDA_OPTIMIZE_BACKUP_REPOSITORY_NAME = %q, want camunda-backup", [got])
}

# --- monitoring on: Camunda ServiceMonitors rendered ---
deny contains msg if {
	count(lib.kinds("ServiceMonitor")) == 0
	msg := "[prod][camunda] no ServiceMonitor rendered; monitoring is on in prod"
}

# --- 3-AZ sizing + disruption budget ---
deny contains msg if {
	r := lib.get("StatefulSet", "prod-camunda-zeebe").spec.replicas
	r != 3
	msg := sprintf("[prod][camunda] zeebe replicas = %v, want 3", [r])
}

deny contains msg if {
	not lib.has("PodDisruptionBudget", "prod-camunda-zeebe")
	msg := "[prod][camunda] zeebe PodDisruptionBudget missing"
}

deny contains msg if {
	pdb := lib.get("PodDisruptionBudget", "prod-camunda-zeebe")
	pdb.spec.maxUnavailable != 1
	msg := sprintf("[prod][camunda] zeebe PDB maxUnavailable = %v, want 1", [pdb.spec.maxUnavailable])
}

deny contains msg if {
	inst := lib.get("PodDisruptionBudget", "prod-camunda-zeebe").spec.selector.matchLabels["app.kubernetes.io/instance"]
	inst != "prod-camunda"
	msg := sprintf("[prod][camunda] zeebe PDB selector instance = %q, want prod-camunda", [inst])
}

deny contains msg if {
	r := lib.get("Deployment", "prod-camunda-connectors").spec.replicas
	r != 2
	msg := sprintf("[prod][camunda] connectors replicas = %v, want 2", [r])
}

# --- external-secrets: OpenSearch profile + monitoring ---
deny contains msg if {
	some name in {"opensearch-credentials", "opensearch-backup-credentials", "grafana-entra-secret", "teams-webhook-url"}
	not name in lib.external_secret_targets
	msg := sprintf("[prod][external-secrets] missing ExternalSecret producing %q", [name])
}

# --- OpenSearch egress policy (ports 53091-53098, NOT 9200) ---
deny contains msg if {
	not lib.has("NetworkPolicy", "allow-egress-opensearch")
	msg := "[prod][network-policies] allow-egress-opensearch missing"
}

deny contains msg if {
	port := lib.get("NetworkPolicy", "allow-egress-opensearch").spec.egress[0].ports[0]
	not port_range_ok(port)
	msg := sprintf("[prod][network-policies] allow-egress-opensearch port range = %v-%v, want 53091-53098", [object.get(port, "port", "?"), object.get(port, "endPort", "?")])
}

port_range_ok(p) if {
	p.port == 53091
	p.endPort == 53098
}

# --- monitoring namespace policies ---
deny contains msg if {
	not lib.has_ns("NetworkPolicy", "monitoring", "default-deny-ingress")
	msg := "[prod][network-policies] monitoring default-deny-ingress missing"
}

# --- prod hostnames land on the Ingresses ---
prod_hosts := {"my-camunda-prod.stackit.gg", "zeebe.my-camunda-prod.stackit.gg"}

deny contains msg if {
	some host in prod_hosts
	not host in lib.ingress_hosts
	msg := sprintf("[prod][ingress] expected host %q not found in rendered Ingresses", [host])
}

# --- camunda-backup CronJob config (prod variant) ---
backup_cfg_expect := {
	"MGMT_BASE_URL": "http://prod-camunda-zeebe-gateway:9600",
	"OPTIMIZE_MANAGEMENT_API": "http://prod-camunda-optimize:8092",
	"BACKUP_RETENTION_DAYS": "7",
}

deny contains msg if {
	some k, want in backup_cfg_expect
	got := object.get(lib.configmap_data("camunda-backup-config"), k, "<missing>")
	got != want
	msg := sprintf("[prod][camunda-backup] %s = %q, want %q", [k, got, want])
}

# --- opensearch-retention CronJob (prod only) ---
deny contains msg if {
	not lib.has("CronJob", "opensearch-retention")
	msg := "[prod] opensearch-retention CronJob missing"
}

deny contains msg if {
	got := object.get(lib.configmap_data("opensearch-retention-config"), "INDEX_RETENTION_DAYS", "<missing>")
	got != "60"
	msg := sprintf("[prod] opensearch-retention INDEX_RETENTION_DAYS = %q, want 60", [got])
}

# --- ingress-nginx: 2 controller replicas (externalTrafficPolicy=Local floor) ---
deny contains msg if {
	r := lib.ingress_nginx_controller.spec.replicas
	r != 2
	msg := sprintf("[prod][ingress-nginx] controller replicas = %v, want 2", [r])
}

# --- monitoring RBAC: no cluster-wide secrets read beyond the accepted set ---
# Accepted: kube-state-metrics (emits Secret metadata only), the prometheus-operator
# (chart offers no namespaced mode; watch scope is narrowed via prometheusOperator.namespaces),
# and the ingress-nginx controller (serves TLS secrets in camunda/argocd/monitoring,
# no single-namespace watch possible; compensated by the ingress-nginx NetworkPolicies).
secrets_clusterrole_allowed(name) if endswith(name, "-kube-state-metrics")

secrets_clusterrole_allowed(name) if endswith(name, "-operator")

deny contains msg if {
	some d in lib.docs
	d.kind == "ClusterRole"
	some rule in d.rules
	"secrets" in rule.resources
	not secrets_clusterrole_allowed(d.metadata.name)
	not startswith(d.metadata.name, "cert-manager")
	not d.metadata.name in {"prod-ingress-nginx"}
	msg := sprintf("[prod][rbac] ClusterRole %q grants cluster-wide secrets access", [d.metadata.name])
}

# --- monitoring namespace: egress default-deny ---
deny contains msg if {
	some np in {"default-deny-egress", "allow-egress-dns", "allow-egress-scrape-camunda", "allow-egress-nodes"}
	not lib.has_ns("NetworkPolicy", "monitoring", np)
	msg := sprintf("[prod][network-policies] monitoring NetworkPolicy %q missing", [np])
}

# --- Prometheus scrape allow into camunda, pod-scoped ---
deny contains msg if {
	not lib.has_ns("NetworkPolicy", "camunda", "allow-from-prometheus")
	msg := "[prod][network-policies] camunda allow-from-prometheus missing"
}

# --- PDBs on every multi-replica component ---
# Zeebe's is chart-native; ingress-nginx renders its own at replicaCount 2.
deny contains msg if {
	some name in {"prod-camunda-connectors", "prod-camunda-console", "prod-camunda-web-modeler-restapi"}
	not lib.has_ns("PodDisruptionBudget", "camunda", name)
	msg := sprintf("[prod][pdb] PodDisruptionBudget %q missing", [name])
}

deny contains msg if {
	not lib.has("PodDisruptionBudget", "prod-ingress-nginx-controller")
	msg := "[prod][pdb] ingress-nginx controller PDB missing (renders only at replicaCount > 1)"
}

# Chart-native, renders only when alertmanager.podDisruptionBudget.enabled.
deny contains msg if {
	not lib.has_ns("PodDisruptionBudget", "monitoring", "prod-kube-prometheus-stack-alertmanager")
	msg := "[prod][pdb] alertmanager PDB missing"
}

deny contains msg if {
	not lib.has_ns("PodDisruptionBudget", "monitoring", "prod-kube-prometheus-stack-grafana")
	msg := "[prod][pdb] grafana PDB missing"
}

deny contains msg if {
	not lib.has_ns("PodDisruptionBudget", "monitoring", "prod-kube-prometheus-stack-prometheus")
	msg := "[prod][pdb] prometheus PDB missing"
}

# Loki renders none of its own; this one is ours in cluster-config.
deny contains msg if {
	not lib.has_ns("PodDisruptionBudget", "monitoring", "prod-loki")
	msg := "[prod][pdb] loki PDB missing"
}

# --- Loki's S3 credential must stay an env placeholder, never a rendered literal ---
# The chart writes its config to a ConfigMap. Credentials reach it only via
# -config.expand-env=true against the ESO-synced Secret, so the rendered text must
# still contain the placeholder.
deny contains msg if {
	some d in lib.docs
	d.kind == "ConfigMap"
	d.metadata.namespace == "monitoring"
	cfg := object.get(d, ["data", "config.yaml"], "")
	contains(cfg, "bucketnames:")
	not contains(cfg, "${LOKI_S3_SECRETKEY}")
	msg := "[prod][loki] rendered Loki config does not carry the ${LOKI_S3_SECRETKEY} placeholder -- a literal credential may have been inlined"
}

deny contains msg if {
	not lib.has_ns("ExternalSecret", "monitoring", "es-loki-storage")
	msg := "[prod][external-secrets] es-loki-storage ExternalSecret missing -- Loki has no S3 credential"
}

# --- ...and something must actually expand it ---
# The placeholder assertion above is not enough on its own: global.extraArgs and
# global.extraEnvFrom do NOT reach singleBinary (the chart's own scope list omits it),
# so the config shipped with literal ${...} and Loki died on "invalid character { in
# host name". Assert the wiring at the container, not just the text in the ConfigMap.
loki_container := c if {
	some c in lib.get("StatefulSet", "prod-loki").spec.template.spec.containers
	c.name == "loki"
}

deny contains msg if {
	not "-config.expand-env=true" in object.get(loki_container, "args", [])
	msg := "[prod][loki] loki container is missing -config.expand-env=true -- the ${LOKI_S3_*} placeholders reach the S3 client literally"
}

deny contains msg if {
	not loki_storage_env
	msg := "[prod][loki] loki container does not envFrom loki-storage-credentials -- no S3 credential at runtime"
}

loki_storage_env if {
	some ef in object.get(loki_container, "envFrom", [])
	ef.secretRef.name == "loki-storage-credentials"
}

# --- stateless multi-replica Grafana needs sticky sessions ---
# Each replica carries its own SQLite, so a grafana_session issued by one pod is not
# valid on the other. Without affinity a browser bounces between them and re-auths
# against Entra on roughly half its requests; XHR calls 401 instead of redirecting.
deny contains msg if {
	some d in lib.docs
	d.kind == "Ingress"
	d.metadata.name == "prod-kube-prometheus-stack-grafana"
	object.get(d.metadata, ["annotations", "nginx.ingress.kubernetes.io/affinity"], "") != "cookie"
	msg := "[prod][grafana] grafana Ingress needs cookie session affinity -- replicas do not share a session store"
}

# --- TLS: prod must never point at the staging issuer ---
deny contains msg if {
	some d in lib.docs
	d.kind == "Ingress"
	issuer := d.metadata.annotations["cert-manager.io/cluster-issuer"]
	issuer != "letsencrypt-production"
	msg := sprintf("[prod][ingress] %s cluster-issuer = %q, want letsencrypt-production", [d.metadata.name, issuer])
}

# --- connectors fail closed: secret envFrom must not be optional ---
deny contains msg if {
	d := lib.get("Deployment", "prod-camunda-connectors")
	some c in lib.main_containers(d)
	some ef in c.envFrom
	ef.secretRef.name == "connector-secrets"
	ef.secretRef.optional != false
	msg := "[prod][connectors] connector-secrets envFrom must set optional: false"
}

# --- orchestration CPU limit must cover cpu-thread-count (the CPU-bound pool) ---
# io-thread-count excluded on purpose: those threads are mostly blocked on IO.
orchestration_cpu_threads := lib.orchestration_config.camunda.system["cpu-thread-count"]

deny contains msg if {
	lim := lib.get("StatefulSet", "prod-camunda-zeebe").spec.template.spec.containers[0].resources.limits.cpu
	millicores(lim) < orchestration_cpu_threads * 1000
	msg := sprintf("[prod][camunda] orchestration cpu limit %v is below cpu-thread-count %v (needs >= %vm)", [lim, orchestration_cpu_threads, orchestration_cpu_threads * 1000])
}

millicores(v) := to_number(trim_suffix(v, "m")) if endswith(v, "m")

millicores(v) := to_number(v) * 1000 if not endswith(v, "m")

# --- multi-replica components need HARD hostname spreading ---
# preferred anti-affinity is a score, not a filter: it lost the scheduler's tie-break on
# every hibernation wake-up and co-located both replicas, leaving the PDB decorative.
# Prometheus and Alertmanager are CRs: the operator builds their StatefulSets at runtime,
# so the render carries spec.affinity directly and a Deployment/StatefulSet-only rule
# would pass them silently.
operator_cr_kinds := {"Prometheus", "Alertmanager"}

placement_spec(d) := d.spec.template.spec if d.kind in {"Deployment", "StatefulSet"}

placement_spec(d) := d.spec if d.kind in operator_cr_kinds

multi_replica_workloads := [d |
	some d in lib.docs
	d.kind in ({"Deployment", "StatefulSet"} | operator_cr_kinds)
	object.get(d.spec, "replicas", 1) > 1
]

hard_hostname_spread(d) if {
	some t in object.get(placement_spec(d), ["affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution"], [])
	t.topologyKey == "kubernetes.io/hostname"
}

hard_hostname_spread(d) if {
	some t in object.get(placement_spec(d), "topologySpreadConstraints", [])
	t.topologyKey == "kubernetes.io/hostname"
	t.whenUnsatisfiable == "DoNotSchedule"
}

deny contains msg if {
	some d in multi_replica_workloads
	not hard_hostname_spread(d)
	msg := sprintf("[prod][spread] %s/%s has %v replicas but no hard hostname spread (required podAntiAffinity or DoNotSchedule constraint) -- its PDB protects nothing", [d.kind, d.metadata.name, d.spec.replicas])
}

# --- minAvailable PDB on a 1-replica workload deadlocks node drains ---
deny contains msg if {
	some pdb in lib.kinds("PodDisruptionBudget")
	object.get(pdb.spec, "minAvailable", null) != null
	some d in lib.docs
	d.kind in {"Deployment", "StatefulSet"}
	object.get(d.spec, "replicas", 1) == 1
	matches_pdb(pdb, d)
	msg := sprintf("[prod][pdb] %s sets minAvailable against single-replica %s -- blocks every node drain", [pdb.metadata.name, d.metadata.name])
}

matches_pdb(pdb, d) if {
	sel := object.get(pdb.spec, ["selector", "matchLabels"], {})
	count(sel) > 0
	labels := object.get(d.spec.template, ["metadata", "labels"], {})
	every k, v in sel {
		labels[k] == v
	}
}

# --- a PDB whose selector matches nothing protects nothing ---
# The release-name trap: a bare `camunda-*` or a guessed component label silently
# selects zero pods, and the budget reads as healthy while protecting nothing.
# Prometheus and Alertmanager are exempt: the operator builds their StatefulSets at
# runtime, so no rendered workload carries those labels. Their spread is asserted on
# the CR instead.
operator_built_pdb(pdb) if {
	object.get(pdb.spec, ["selector", "matchLabels", "app.kubernetes.io/name"], "") in {"alertmanager", "prometheus"}
}

pdb_has_target(pdb) if {
	some d in lib.docs
	d.kind in {"Deployment", "StatefulSet"}
	matches_pdb(pdb, d)
}

deny contains msg if {
	some pdb in lib.kinds("PodDisruptionBudget")
	count(object.get(pdb.spec, ["selector", "matchLabels"], {})) > 0
	not operator_built_pdb(pdb)
	not pdb_has_target(pdb)
	msg := sprintf("[prod][pdb] %s selector matches no rendered workload -- it protects nothing", [pdb.metadata.name])
}

# --- alerts for components Gardener runs in the seed can never clear ---
unscrapeable_alerts := {"KubeControllerManagerDown", "KubeSchedulerDown"}

deny contains msg if {
	some a in unscrapeable_alerts
	a in lib.alert_names
	msg := sprintf("[prod][monitoring] %q fires forever: the component runs in the seed cluster, not the shoot", [a])
}

# kube-proxy is hostNetwork: discovery needs the selector AND egress to the node port.
deny contains msg if {
	"KubeProxyDown" in lib.alert_names
	ports := {p.port |
		some rule in lib.get("NetworkPolicy", "allow-egress-nodes").spec.egress
		some p in rule.ports
	}
	not 10249 in ports
	msg := "[prod][network-policies] allow-egress-nodes is missing port 10249; kube-proxy scrapes time out"
}

# kube-proxy DOES run here, so its alert stays -- but only if the Service can select it.
deny contains msg if {
	"KubeProxyDown" in lib.alert_names
	sel := lib.get("Service", "prod-kube-prometheus-stack-kube-proxy").spec.selector
	sel != {"app": "kubernetes", "role": "proxy"}
	msg := sprintf("[prod][monitoring] kube-proxy Service selector %v does not match Gardener's pod labels; the target will have no endpoints", [sel])
}

# --- restapi metrics live under the webModeler contextPath ---
deny contains msg if {
	some d in lib.docs
	d.kind == "ServiceMonitor"
	contains(d.metadata.name, "modeler")
	some e in d.spec.endpoints
	not startswith(e.path, "/modeler/")
	msg := sprintf("[prod][monitoring] modeler ServiceMonitor path %q misses the /modeler contextPath and will 404", [e.path])
}

# --- monitoring must not be blind: an alert needs the scrape that feeds it ---
scrape_backed_alerts := {
	"IngressHighErrorRate": "ingress-nginx",
	"CertificateExpiringSoon": "cert-manager",
}

deny contains msg if {
	some alert, ns in scrape_backed_alerts
	alert in lib.alert_names
	not ns in lib.servicemonitor_targets
	msg := sprintf("[prod][monitoring] alert %q needs a ServiceMonitor targeting namespace %q; without it the metric never exists", [alert, ns])
}

deny contains msg if {
	"LogIngestionStalled" in lib.alert_names
	not lib.has("ServiceMonitor", "prod-loki")
	msg := "[prod][monitoring] LogIngestionStalled needs the prod-loki ServiceMonitor for loki_distributor_lines_received_total"
}

# --- Alertmanager's routing is the teams-routing AlertmanagerConfig, not the chart's ---
# Without alertmanagerConfiguration the operator falls back to the chart's default routing,
# which notifies nothing.
teams_routing := lib.get("AlertmanagerConfig", "teams-routing")

deny contains msg if {
	spec := lib.get("Alertmanager", "prod-kube-prometheus-stack-alertmanager").spec
	object.get(spec, ["alertmanagerConfiguration", "name"], "") != "teams-routing"
	msg := "[prod][monitoring] Alertmanager spec.alertmanagerConfiguration must name teams-routing"
}

deny contains msg if {
	lib.has("Alertmanager", "prod-kube-prometheus-stack-alertmanager")
	not lib.has("AlertmanagerConfig", "teams-routing")
	msg := "[prod][monitoring] AlertmanagerConfig teams-routing not rendered"
}

# --- the Watchdog must reach a real receiver, or monitoring-down looks like all-healthy ---
deny contains msg if {
	some r in teams_routing.spec.route.routes
	some m in r.matchers
	m.value == "Watchdog"
	r.receiver == "null"
	msg := "[prod][monitoring] Watchdog routes to the null receiver -- the dead-man signal is discarded"
}

# --- the Teams webhook URL is a bearer credential: a secret ref, never inline ---
deny contains msg if {
	some r in teams_routing.spec.receivers
	some c in object.get(r, "msteamsv2Configs", [])
	not c.webhookURL.name
	msg := sprintf("[prod][monitoring] receiver %q must take its webhook URL from a secret ref (SM via ESO)", [r.name])
}

# --- a cross-namespace scrape needs egress from monitoring AND ingress at the target ---
deny contains msg if {
	some ns in {"ingress-nginx", "cert-manager"}
	ns in lib.servicemonitor_targets
	not lib.has_ns("NetworkPolicy", ns, "allow-from-prometheus")
	msg := sprintf("[prod][network-policies] scraping %q needs an allow-from-prometheus ingress policy there", [ns])
}

deny contains msg if {
	some ns in {"ingress-nginx", "cert-manager"}
	ns in lib.servicemonitor_targets
	not lib.has_ns("NetworkPolicy", "monitoring", sprintf("allow-egress-scrape-%s", [ns]))
	msg := sprintf("[prod][network-policies] scraping %q needs allow-egress-scrape-%s in monitoring", [ns, ns])
}

# --- perpetual-diff guards, prod-only Applications ---
deny contains msg if {
	missing := lib.externalsecret_defaulted_paths - lib.ignored_paths("prod-monitoring-secrets", "ExternalSecret")
	count(missing) > 0
	msg := sprintf("[prod][bootstrap] prod-monitoring-secrets ignoreDifferences missing ExternalSecret path(s): %v", [missing])
}

deny contains msg if {
	missing := lib.statefulset_defaulted_paths - lib.ignored_paths("prod-loki", "StatefulSet")
	count(missing) > 0
	msg := sprintf("[prod][bootstrap] prod-loki ignoreDifferences missing StatefulSet path(s): %v", [missing])
}

# --- bootstrap: prod pins this repo to a full commit SHA, never a movable ref ---
# The rendered chart carries the SHA the foundation root passes in (render.sh injects a
# dummy one); only the break-glass root-app-prod.yaml may carry the REPLACE_ME sentinel.
deny contains msg if {
	some d in lib.docs
	d.kind == "Application"
	some src in lib.app_sources(d)
	src.repoURL == lib.gitops_repo_url
	not regex.match(`^[0-9a-f]{40}$`, src.targetRevision)
	not break_glass_sentinel(d, src)
	msg := sprintf("[prod][bootstrap] Application %q targetRevision = %q on this repo; must be a full commit SHA", [d.metadata.name, src.targetRevision])
}

break_glass_sentinel(d, src) if {
	d.metadata.name == "root-prod"
	src.targetRevision == "REPLACE_ME_PROD_SHA"
}

# --- Grafana: no usable local admin ---
grafana_ini := ini if {
	some d in lib.docs
	d.kind == "ConfigMap"
	d.metadata.name == "prod-kube-prometheus-stack-grafana"
	ini := d.data["grafana.ini"]
}

# The chart drops both the Secret and the env only when
# grafana.env.GF_SECURITY_DISABLE_INITIAL_ADMIN_CREATION is set.
deny contains msg if {
	lib.has("Secret", "prod-kube-prometheus-stack-grafana")
	msg := "[prod][grafana] the chart's static admin Secret is rendered; it carries the admin/prom-operator default"
}

deny contains msg if {
	some c in lib.get("Deployment", "prod-kube-prometheus-stack-grafana").spec.template.spec.containers
	some e in c.env
	e.name in {"GF_SECURITY_ADMIN_USER", "GF_SECURITY_ADMIN_PASSWORD"}
	msg := sprintf("[prod][grafana] %q is injected; Grafana must carry no local admin credential", [e.name])
}

deny contains msg if {
	not contains(grafana_ini, "[auth.basic]")
	msg := "[prod][grafana] grafana.ini must disable basic auth"
}
