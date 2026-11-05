# Assertions expected to hold for BOTH dev and prod.
package common

import data.lib
import rego.v1

# --- render completeness: guards so a missing resource can't silently pass a check ---
deny contains msg if {
	not lib.orchestration_config
	msg := sprintf("[%s][camunda] orchestration ConfigMap (*-camunda-zeebe-configuration) not rendered", [lib.release])
}

deny contains msg if {
	not lib.zeebe_env
	msg := sprintf("[%s][camunda] zeebe StatefulSet not rendered", [lib.release])
}

deny contains msg if {
	not lib.ingress_nginx_controller
	msg := sprintf("[%s][ingress-nginx] controller Deployment not rendered", [lib.release])
}

deny contains msg if {
	not lib.ingress_nginx_config
	msg := sprintf("[%s][ingress-nginx] controller ConfigMap not rendered", [lib.release])
}

deny contains msg if {
	not lib.has("CronJob", "camunda-backup")
	msg := sprintf("[%s][camunda-backup] CronJob not rendered", [lib.release])
}

# --- security: every Camunda app container drops ALL capabilities ---
deny contains msg if {
	some w in lib.camunda_workloads
	some c in lib.main_containers(w)
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("[%s][camunda] container %q in %s/%s must drop ALL capabilities", [lib.release, c.name, w.kind, w.metadata.name])
}

# --- security: namespace Pod Security Standards labels ---
# monitoring stays warn/audit only: node-exporter + alloy fail even baseline.
ns_pss := {
	"camunda": {"enforce": "restricted", "warn": "restricted", "audit": "restricted"},
	"monitoring": {"warn": "restricted", "audit": "restricted"},
	"ingress-nginx": {"enforce": "restricted", "warn": "restricted", "audit": "restricted"},
	"cert-manager": {"enforce": "restricted", "warn": "restricted", "audit": "restricted"},
	"default": {"enforce": "restricted", "warn": "restricted", "audit": "restricted"},
}

deny contains msg if {
	some ns, labels in ns_pss
	lib.has("Namespace", ns)
	some key, want in labels
	got := object.get(lib.get("Namespace", ns), ["metadata", "labels", sprintf("pod-security.kubernetes.io/%s", [key])], "<missing>")
	got != want
	msg := sprintf("[%s][namespaces] %s pod-security.kubernetes.io/%s = %q, want %q", [lib.release, ns, key, got, want])
}

# --- namespaces must never be prunable: a bad edit here must not delete the namespace ---
deny contains msg if {
	some ns in object.keys(ns_pss)
	lib.has("Namespace", ns)
	got := object.get(lib.get("Namespace", ns), ["metadata", "annotations", "argocd.argoproj.io/sync-options"], "<missing>")
	got != "Prune=false"
	msg := sprintf("[%s][namespaces] %s missing argocd.argoproj.io/sync-options: Prune=false", [lib.release, ns])
}

# --- release-name rule: an in-cluster host must name a Service in this render ---
deny contains msg if {
	some ref in lib.svc_references
	not ref.name in lib.service_names
	msg := sprintf("[%s][release-name] host %q references no Service in this render -- did it need the %q prefix?", [lib.release, sprintf("%s.%s.svc", [ref.name, ref.namespace]), lib.release])
}

# --- perpetual-diff guards: defaulted fields git never declares ---
deny contains msg if {
	app := sprintf("%s-external-secrets", [lib.release])
	lib.has("Application", app)
	missing := lib.externalsecret_defaulted_paths - lib.ignored_paths(app, "ExternalSecret")
	count(missing) > 0
	msg := sprintf("[%s][bootstrap] %s ignoreDifferences missing ExternalSecret path(s): %v", [lib.release, app, missing])
}

deny contains msg if {
	app := sprintf("%s-camunda", [lib.release])
	lib.has("Application", app)
	missing := lib.statefulset_defaulted_paths - lib.ignored_paths(app, "StatefulSet")
	count(missing) > 0
	msg := sprintf("[%s][bootstrap] %s ignoreDifferences missing StatefulSet path(s): %v", [lib.release, app, missing])
}

# Not ignored, so it must be declared explicitly or the perpetual diff returns.
deny contains msg if {
	some d in lib.docs
	d.kind == "ExternalSecret"
	got := object.get(d.spec, ["target", "deletionPolicy"], "<missing>")
	got != "Retain"
	msg := sprintf("[%s][external-secrets] %s target.deletionPolicy = %q, want \"Retain\" (declared, not ignored)", [lib.release, d.metadata.name, got])
}

# --- bootstrap: the camunda Application must carry the cascade-delete finalizer in both envs ---
deny contains msg if {
	d := lib.get("Application", sprintf("%s-camunda", [lib.release]))
	not "resources-finalizer.argocd.argoproj.io" in object.get(d.metadata, "finalizers", [])
	msg := sprintf("[%s][bootstrap] Application %s-camunda missing resources-finalizer.argocd.argoproj.io", [lib.release, lib.release])
}

# --- bootstrap: every Application self-heals and prunes ---
# Without selfHeal an Application stops reverting live drift; without prune, deleting a
# manifest leaves the object running in the cluster.
deny contains msg if {
	some d in lib.docs
	d.kind == "Application"
	some key in {"prune", "selfHeal"}
	object.get(d.spec, ["syncPolicy", "automated", key], false) != true
	msg := sprintf("[%s][bootstrap] Application %s missing syncPolicy.automated.%s: true", [lib.release, d.metadata.name, key])
}

# --- bootstrap: children live in one of this env's AppProjects, never `default` ---
# The AppProject is what bounds sourceRepos, destinations and clusterResourceWhitelist;
# `default` is unrestricted. The roots are exempt (lib.root_apps).
env_projects := {sprintf("camunda-%s", [lib.release]), sprintf("platform-%s", [lib.release])}

deny contains msg if {
	some d in lib.docs
	d.kind == "Application"
	not d.metadata.name in lib.root_apps
	got := object.get(d.spec, "project", "<missing>")
	not got in env_projects
	msg := sprintf("[%s][bootstrap] Application %s project = %q, want one of %v", [lib.release, d.metadata.name, got, env_projects])
}

deny contains msg if {
	lib.has("Application", sprintf("%s-camunda", [lib.release]))
	some p in env_projects
	not lib.has("AppProject", p)
	msg := sprintf("[%s][bootstrap] AppProject %s not rendered", [lib.release, p])
}

# The workload project may not create cluster-scoped objects at all.
deny contains msg if {
	w := object.get(lib.get("AppProject", sprintf("camunda-%s", [lib.release])).spec, "clusterResourceWhitelist", [])
	count(w) > 0
	msg := sprintf("[%s][bootstrap] AppProject camunda-%s carries a clusterResourceWhitelist; cluster-scoped kinds belong in platform-%s", [lib.release, lib.release, lib.release])
}

# ArgoCD validates spec.destination itself, not just the rendered resources. The
# multi-namespace raw-manifest apps declare an empty namespace and need "" whitelisted.
deny contains msg if {
	some d in lib.docs
	d.kind == "Application"
	not d.metadata.name in lib.root_apps
	proj := lib.get("AppProject", d.spec.project)
	ns := object.get(d.spec, ["destination", "namespace"], "")
	allowed := {object.get(dst, "namespace", "") | some dst in proj.spec.destinations}
	not ns in allowed
	msg := sprintf("[%s][bootstrap] Application %s declares destination namespace %q, not allowed by project %q", [lib.release, d.metadata.name, ns, d.spec.project])
}

# Every kind ArgoCD turns into a sync task must be whitelisted by one of the projects.
# Helm hooks are rendered but absent from Application.status.resources, so deriving the
# whitelists from live state alone misses them. Excluded here for the same reason ArgoCD
# does not make them tasks: the List wrapper it flattens, and helm test hooks it ignores.
# The app-of-apps objects sync under `default`, which is unrestricted.
synced_kinds contains [group, kind] if {
	some d in lib.docs
	not d.kind in {"List", "Application", "AppProject"}
	object.get(d, ["metadata", "annotations", "helm.sh/hook"], "") != "test"
	kind := d.kind
	group := lib.api_group(d)
}

project_kinds contains [e.group, e.kind] if {
	some d in lib.docs
	d.kind == "AppProject"
	some e in array.concat(
		object.get(d.spec, "namespaceResourceWhitelist", []),
		object.get(d.spec, "clusterResourceWhitelist", []),
	)
}

deny contains msg if {
	some gk in synced_kinds
	not gk in project_kinds
	msg := sprintf("[%s][bootstrap] %s/%s is rendered but no AppProject whitelists it", [lib.release, gk[0], gk[1]])
}

# Neither project may re-open the namespaced wildcard.
deny contains msg if {
	some d in lib.docs
	d.kind == "AppProject"
	some e in object.get(d.spec, "namespaceResourceWhitelist", [])
	e.group == "*"
	e.kind == "*"
	msg := sprintf("[%s][bootstrap] AppProject %s whitelists */* namespaced kinds; enumerate them", [lib.release, d.metadata.name])
}

# --- bootstrap: chart sources pin an exact version ---
deny contains msg if {
	some d in lib.docs
	d.kind == "Application"
	some src in lib.app_sources(d)
	src.chart
	rev := object.get(src, "targetRevision", "")
	not regex.match(`^v?[0-9]+\.[0-9]+\.[0-9]+$`, rev)
	msg := sprintf("[%s][bootstrap] Application %s chart %s targetRevision = %q, want an exact MAJOR.MINOR.PATCH", [lib.release, d.metadata.name, src.chart, rev])
}

# --- bootstrap: the version rendered here is the version ArgoCD deploys ---
# tests/render.sh carries its own chart versions. Bump a chart in bootstrap/ alone and every
# assertion in this suite keeps grading the previous chart. Only charts this render covers are
# checked, so unrendered charts and charts that label with `chart:` instead of `helm.sh/chart:`
# are skipped rather than failed.
deny contains msg if {
	some d in lib.docs
	d.kind == "Application"
	some src in lib.app_sources(d)
	src.chart
	rendered := {lbl | some lbl in lib.rendered_chart_labels; startswith(lbl, sprintf("%s-", [src.chart]))}
	count(rendered) > 0
	want := sprintf("%s-%s", [src.chart, src.targetRevision])
	not want in rendered
	msg := sprintf("[%s][bootstrap] Application %s pins %s but the render contains %v -- tests/render.sh is out of step", [lib.release, d.metadata.name, want, rendered])
}

# --- external-secrets: core secrets present in both envs ---
core_external_secrets := {
	"entra-credentials",
	"postgres-identity-credentials",
	"postgres-webmodeler-credentials",
	"zeebe-backup-credentials",
	"platform-connection-config",
	"connector-secrets",
	"stackit-sa-authentication",
}

deny contains msg if {
	some name in core_external_secrets
	not name in lib.external_secret_targets
	msg := sprintf("[%s][external-secrets] missing ExternalSecret producing %q", [lib.release, name])
}

# --- network-policies: default-deny both directions on every guarded namespace ---
# camunda (SEC-9), the credential-bearing platform namespaces,
# and ingress-nginx.
# monitoring is prod-only and asserted in prod.rego.
default_deny_namespaces := {"camunda", "argocd", "external-secrets-system", "secrets-manager", "ingress-nginx", "cert-manager"}

deny contains msg if {
	some ns in default_deny_namespaces
	some np in {"default-deny-ingress", "default-deny-egress"}
	not lib.has_ns("NetworkPolicy", ns, np)
	msg := sprintf("[%s][network-policies] %s NetworkPolicy %q missing", [lib.release, ns, np])
}

# Every from-apiserver allow must stay scoped to a pod selector AND ports —
# never a namespace-wide any-port 0.0.0.0/0 allow.
deny contains msg if {
	some d in lib.docs
	d.kind == "NetworkPolicy"
	contains(d.metadata.name, "from-apiserver")
	some rule in d.spec.ingress
	not rule.ports
	msg := sprintf("[%s][network-policies] %s/%s lost its port scoping", [lib.release, d.metadata.namespace, d.metadata.name])
}

deny contains msg if {
	some d in lib.docs
	d.kind == "NetworkPolicy"
	contains(d.metadata.name, "from-apiserver")
	object.get(d.spec, "podSelector", {}) == {}
	msg := sprintf("[%s][network-policies] %s/%s lost its podSelector scoping", [lib.release, d.metadata.namespace, d.metadata.name])
}

# --- images: Camunda components digest-pinned ---
# The digest supersedes the tag at render time; the tag lives next to each digest
# in camunda/values.yaml and both move together on upgrades.
deny contains msg if {
	some w in lib.camunda_workloads
	some c in lib.main_containers(w)
	not valid_image(c.image)
	msg := sprintf("[%s][camunda] container %q image %q is not a digest-pinned camunda/* image", [lib.release, c.name, c.image])
}

valid_image(img) if {
	startswith(img, "camunda/")
	contains(img, "@sha256:")
}


# --- OIDC: orchestration issuer is Microsoft Entra ---
deny contains msg if {
	iss := lib.orchestration_config.camunda.security.authentication.oidc["issuer-uri"]
	not startswith(iss, "https://login.microsoftonline.com/")
	msg := sprintf("[%s][camunda] orchestration OIDC issuer-uri = %q, want Microsoft Entra", [lib.release, iss])
}

# --- coordinated-backup env on the orchestration container (common to both envs) ---
backup_env := {
	"CAMUNDA_DATA_SECONDARYSTORAGE_OPENSEARCH_BACKUP_REPOSITORYNAME": "camunda-backup",
	"CAMUNDA_DATA_PRIMARYSTORAGE_BACKUP_RETENTION_WINDOW": "P7D",
	"CAMUNDA_DATA_PRIMARYSTORAGE_BACKUP_RETENTION_CLEANUPSCHEDULE": "PT1H",
}

deny contains msg if {
	some k, want in backup_env
	got := object.get(lib.zeebe_env, k, "<missing>")
	got != want
	msg := sprintf("[%s][camunda] orchestration env %s = %q, want %q", [lib.release, k, got, want])
}

# --- ingress: per-Ingress allowlists ---
# A per-Ingress whitelist-source-range replaces the controller office gate for that one host.
# Narrow ranges are effective because nginx sees the real client IP via PROXY protocol -- the
# same mechanism the controller gate depends on. Two shapes are legitimate: allow-all for the
# sanctioned public doors below, or a narrowing list that still admits every CIDR the
# controller admits (e.g. a machine endpoint that also admits a load generator).
# Anything else is a mistake.

# No sanctioned public doors. The webhook door was retired, so an allow-all
# on any Ingress is now always a mistake. Re-adding one means adding it here AND abuse
# controls for it.
public_ingresses := set()

allow_all_ranges := {"0.0.0.0/0", "0.0.0.0/0,::/0"}

deny contains msg if {
	some d in lib.docs
	d.kind == "Ingress"
	rng := trim_space(d.metadata.annotations["nginx.ingress.kubernetes.io/whitelist-source-range"])
	rng in allow_all_ranges
	not d.metadata.name in public_ingresses
	msg := sprintf("[%s][ingress] %s whitelist-source-range = %q; only the sanctioned public doors may open the office gate", [lib.release, d.metadata.name, rng])
}

deny contains msg if {
	some d in lib.docs
	d.kind == "Ingress"
	rng := trim_space(d.metadata.annotations["nginx.ingress.kubernetes.io/whitelist-source-range"])
	rng == ""
	msg := sprintf("[%s][ingress] %s whitelist-source-range is empty; that denies every client", [lib.release, d.metadata.name])
}

# The office CIDR is single-sourced in platform/ingress-nginx/office-cidr-values.yaml. A
# narrowing list must still contain it, or an office IP change locks operators out of that one
# host with no other signal. This is what keeps the duplication honest.
deny contains msg if {
	some d in lib.docs
	d.kind == "Ingress"
	rng := trim_space(d.metadata.annotations["nginx.ingress.kubernetes.io/whitelist-source-range"])
	not rng in allow_all_ranges
	rng != ""
	admitted := {trim_space(c) | some c in split(rng, ",")}
	some office in {trim_space(c) | some c in split(lib.ingress_nginx_config["whitelist-source-range"], ",")}
	not office in admitted
	msg := sprintf("[%s][ingress] %s whitelist-source-range %q is missing the controller CIDR %q", [lib.release, d.metadata.name, rng, office])
}

# --- ingress-nginx: the controller-level office-CIDR gate must render, and stay narrow ---
# Both envs take it from platform/ingress-nginx/office-cidr-values.yaml. Drop that valueFile
# from an Application and the whitelist silently vanishes -- every UI public, no other signal.
deny contains msg if {
	rng := object.get(lib.ingress_nginx_config, "whitelist-source-range", "<missing>")
	rng in {"<missing>", "", "0.0.0.0/0", "0.0.0.0/0,::/0"}
	msg := sprintf("[%s][ingress-nginx] controller whitelist-source-range = %q; the office-CIDR gate must render and stay narrow", [lib.release, rng])
}

# --- ingress-nginx: the three PROXY-protocol knobs the gate rests on ---
# yawol SNATs the client IP unless tcpProxyProtocol is set, and nginx only trusts the
# forwarded address with use-proxy-protocol + proxy-real-ip-cidr. With the gate above narrow
# and any one of these missing, nginx matches the LB's 10.250.x.x against the office CIDR and
# 403s every client (2026-07-02). All three are required, in both envs.
deny contains msg if {
	got := object.get(lib.ingress_nginx_config, "use-proxy-protocol", "<missing>")
	got != "true"
	msg := sprintf("[%s][ingress-nginx] controller use-proxy-protocol = %q, want \"true\"; without it the office-CIDR gate 403s everyone", [lib.release, got])
}

deny contains msg if {
	got := object.get(lib.ingress_nginx_config, "proxy-real-ip-cidr", "")
	got == ""
	msg := sprintf("[%s][ingress-nginx] controller proxy-real-ip-cidr is unset; nginx then ignores the PROXY-protocol header it is told to parse", [lib.release])
}

deny contains msg if {
	got := object.get(lib.ingress_nginx_service.metadata, ["annotations", "yawol.stackit.cloud/tcpProxyProtocol"], "<missing>")
	got != "true"
	msg := sprintf("[%s][ingress-nginx] controller Service yawol.stackit.cloud/tcpProxyProtocol = %q, want \"true\"; yawol otherwise SNATs the client IP away", [lib.release, got])
}

# The Service must render at all, or the three-knob check above passes vacuously.
deny contains msg if {
	not lib.ingress_nginx_service
	msg := sprintf("[%s][ingress-nginx] controller Service not rendered", [lib.release])
}

# --- ingress-nginx: the L4 gate must render, stay narrow, and cover the L7 gate ---
# Coarse and provider-enforced, so a values mistake in the L7 gate cannot leave the
# UIs open. It must be a SUPERSET of every range nginx admits -- an L4 list narrower than the
# L7 whitelist silently blocks traffic the L7 rules allow.
deny contains msg if {
	svc := lib.ingress_nginx_service
	count(object.get(svc, ["spec", "loadBalancerSourceRanges"], [])) == 0
	msg := sprintf("[%s][ingress-nginx] controller Service sets no loadBalancerSourceRanges; the L4 gate must render", [lib.release])
}

deny contains msg if {
	svc := lib.ingress_nginx_service
	some rng in object.get(svc, ["spec", "loadBalancerSourceRanges"], [])
	trim_space(rng) in allow_all_ranges
	msg := sprintf("[%s][ingress-nginx] controller Service loadBalancerSourceRanges contains %q; the L4 gate must stay narrow", [lib.release, rng])
}

deny contains msg if {
	svc := lib.ingress_nginx_service
	l4 := {trim_space(r) | some r in object.get(svc, ["spec", "loadBalancerSourceRanges"], [])}
	count(l4) > 0
	some office in {trim_space(c) | some c in split(lib.ingress_nginx_config["whitelist-source-range"], ",")}
	not office in l4
	msg := sprintf("[%s][ingress-nginx] loadBalancerSourceRanges is missing the controller CIDR %q; the L4 gate would block traffic the L7 gate admits", [lib.release, office])
}

# Same superset rule against per-Ingress ranges: a range an Ingress admits must also pass
# the L4 gate, or it is blocked upstream of nginx.
deny contains msg if {
	svc := lib.ingress_nginx_service
	l4 := {trim_space(r) | some r in object.get(svc, ["spec", "loadBalancerSourceRanges"], [])}
	count(l4) > 0
	some d in lib.docs
	d.kind == "Ingress"
	some cidr in {trim_space(c) | some c in split(d.metadata.annotations["nginx.ingress.kubernetes.io/whitelist-source-range"], ",")}
	not cidr in l4
	msg := sprintf("[%s][ingress-nginx] loadBalancerSourceRanges is missing %q, admitted by Ingress %s; the L4 gate would block it", [lib.release, cidr, d.metadata.name])
}

# --- cert-manager: fullnameOverride keeps the controller named "cert-manager" (webhook RBAC binds it) ---
deny contains msg if {
	lib.has("Deployment", "cert-manager-cainjector")
	not lib.has("Deployment", "cert-manager")
	msg := sprintf("[%s][cert-manager] controller Deployment 'cert-manager' missing (fullnameOverride regressed)", [lib.release])
}

# --- external-secrets: the camunda entra bundle must stay narrowed ---
# dataFrom-extract would pull every OIDC client secret (incl. ArgoCD/Grafana) back
# into the camunda namespace.
deny contains msg if {
	some d in lib.docs
	d.kind == "ExternalSecret"
	d.metadata.name == "es-entra-credentials"
	d.spec.dataFrom
	msg := sprintf("[%s][external-secrets] es-entra-credentials must select keys via data:, not dataFrom", [lib.release])
}

# The old namespace-wide monitoring allow must stay gone.
deny contains msg if {
	lib.has_ns("NetworkPolicy", "camunda", "allow-from-monitoring")
	msg := sprintf("[%s][network-policies] allow-from-monitoring is back; use the pod-scoped allow-from-prometheus", [lib.release])
}

# --- landing-page image pinned by digest ---
deny contains msg if {
	some d in lib.docs
	d.kind == "Deployment"
	d.metadata.name == "landing-page"
	some c in d.spec.template.spec.containers
	not contains(c.image, "@sha256:")
	msg := sprintf("[%s][landing-page] image %q not digest-pinned", [lib.release, c.image])
}

# --- CronJob images pinned by digest: these jobs hold backup/OpenSearch credentials ---
deny contains msg if {
	some d in lib.docs
	d.kind == "CronJob"
	spec := d.spec.jobTemplate.spec.template.spec
	some c in array.concat(object.get(spec, "containers", []), object.get(spec, "initContainers", []))
	not regex.match(`@sha256:[0-9a-f]{64}$`, c.image)
	msg := sprintf("[%s][cronjobs] CronJob %q container %q image %q not digest-pinned", [lib.release, d.metadata.name, c.name, c.image])
}

# --- every rendered workload container carries requests + memory limits ---
# Prometheus/Alertmanager pods are operator-created from CRs and asserted via
# their specs in the values, not here.
deny contains msg if {
	some d in lib.docs
	d.kind in lib.workload_kinds
	some c in d.spec.template.spec.containers
	not c.resources.limits.memory
	msg := sprintf("[%s][resources] %s/%s container %q has no memory limit", [lib.release, d.kind, d.metadata.name, c.name])
}

deny contains msg if {
	some d in lib.docs
	d.kind in lib.workload_kinds
	some c in d.spec.template.spec.containers
	not c.resources.requests
	msg := sprintf("[%s][resources] %s/%s container %q has no requests", [lib.release, d.kind, d.metadata.name, c.name])
}

# --- no chart or manifest may render a Secret ---
# ArgoCD manages no Secrets: core/Secret is in resource.exclusions and the controller
# holds no write on it. Secret material reaches the cluster through ESO.
deny contains msg if {
	some d in lib.docs
	d.kind == "Secret"
	msg := sprintf("[%s] Secret %q is rendered; ArgoCD manages no Secrets -- use ESO, or a chart value that stops rendering it", [lib.release, d.metadata.name])
}
