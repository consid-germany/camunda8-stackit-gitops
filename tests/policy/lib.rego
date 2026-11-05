# Shared helpers over the rendered manifests (conftest --combine input).
package lib

import rego.v1

# All rendered resource documents. --combine wraps each as {path, contents}.
docs := [d.contents | some d in input; is_object(d.contents)]

# Env prefix ("dev"/"prod") inferred from the rendered Camunda connectors Service.
default release := "unknown"

release := p if {
	some d in docs
	d.kind == "Service"
	endswith(d.metadata.name, "-camunda-connectors")
	not endswith(d.metadata.name, "-headless")
	p := trim_suffix(d.metadata.name, "-camunda-connectors")
}

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet"}

# Camunda chart app workloads.
camunda_workloads := [d |
	some d in docs
	d.kind in workload_kinds
	d.metadata.labels["app.kubernetes.io/part-of"] == "camunda-platform"
]

# Main containers of a workload doc.
main_containers(d) := d.spec.template.spec.containers if d.kind in workload_kinds

# Resource of kind+name exists (name may repeat across namespaces).
has(kind, name) if {
	some d in docs
	d.kind == kind
	d.metadata.name == name
}

# Resource of kind+namespace+name exists.
has_ns(kind, ns, name) if {
	some d in docs
	d.kind == kind
	d.metadata.namespace == ns
	d.metadata.name == name
}

# Single resource by kind+name (use only where the name is globally unique).
get(kind, name) := d if {
	some d in docs
	d.kind == kind
	d.metadata.name == name
}

kinds(kind) := [d | some d in docs; d.kind == kind]

# API group of a doc: "apps" from apps/v1, "" from v1.
api_group(d) := g if {
	parts := split(object.get(d, "apiVersion", ""), "/")
	count(parts) == 2
	g := parts[0]
}

api_group(d) := "" if {
	count(split(object.get(d, "apiVersion", ""), "/")) != 2
}

svc_exists(name) if {
	some d in docs
	d.kind == "Service"
	d.metadata.name == name
}

# ExternalSecret target Secret names.
external_secret_targets := {d.spec.target.name | some d in docs; d.kind == "ExternalSecret"}

# All hostnames across rendered Ingresses.
ingress_hosts := {r.host | some d in docs; d.kind == "Ingress"; some r in d.spec.rules}

# Parsed orchestration application.yaml (the *-camunda-zeebe-configuration ConfigMap).
orchestration_config := cfg if {
	some d in docs
	d.kind == "ConfigMap"
	endswith(d.metadata.name, "-camunda-zeebe-configuration")
	cfg := yaml.unmarshal(d.data["application.yaml"])
}

# Zeebe StatefulSet main-container env as a name->value map (valueFrom entries omitted).
zeebe_env := m if {
	some d in docs
	d.kind == "StatefulSet"
	endswith(d.metadata.name, "-camunda-zeebe")
	m := {e.name: e.value | some e in d.spec.template.spec.containers[0].env}
}

# Optimize Deployment main-container env as a name->value map.
optimize_env := m if {
	some d in docs
	d.kind == "Deployment"
	endswith(d.metadata.name, "-camunda-optimize")
	m := {e.name: e.value | some e in d.spec.template.spec.containers[0].env}
}

# ingress-nginx controller Deployment.
ingress_nginx_controller := d if {
	some d in docs
	d.kind == "Deployment"
	endswith(d.metadata.name, "-ingress-nginx-controller")
}

# ingress-nginx controller ConfigMap data (the office-CIDR gate lives here).
ingress_nginx_config := d.data if {
	some d in docs
	d.kind == "ConfigMap"
	endswith(d.metadata.name, "-ingress-nginx-controller")
}

# ingress-nginx controller Service (the LoadBalancer carrying the yawol annotations).
# The "-metrics" and "-admission" Services do not match.
ingress_nginx_service := d if {
	some d in docs
	d.kind == "Service"
	endswith(d.metadata.name, "-ingress-nginx-controller")
}

# ConfigMap data by name prefix (kustomize appends a content hash to generated names).
configmap_data(prefix) := d.data if {
	some d in docs
	d.kind == "ConfigMap"
	startswith(d.metadata.name, prefix)
}

# This repo's own URL, as it appears in every bootstrap/ Application source.
gitops_repo_url := "https://github.com/REPLACE_ME-github-org/camunda8-stackit-gitops.git"

# The app-of-apps roots. ArgoCD applies them before the AppProject exists, so they are the
# only Applications allowed in project `default`.
root_apps := {"root-dev", "root-prod"}

# "<chart>-<version>" labels helm stamps on every rendered resource. Ties an Application's
# chart pin to the version tests/render.sh actually rendered.
rendered_chart_labels := {lbl |
	some d in docs
	lbl := object.get(d, ["metadata", "labels", "helm.sh/chart"], "")
	lbl != ""
}

# An Application's source(s), normalized to a list regardless of single- vs multi-source shape.
app_sources(d) := d.spec.sources if {
	d.kind == "Application"
	d.spec.sources
}

app_sources(d) := [d.spec.source] if {
	d.kind == "Application"
	not d.spec.sources
	d.spec.source
}

# Every path an Application's ignoreDifferences covers for a given kind (jq + pointers).
# Empty set when the app carries no entry for that kind.
ignored_paths(name, kind) := ps if {
	get("Application", name)
	ps := {p |
		some ig in object.get(get("Application", name).spec, "ignoreDifferences", [])
		ig.kind == kind
		some p in array.concat(
			object.get(ig, "jqPathExpressions", []),
			object.get(ig, "jsonPointers", []),
		)
	}
}

service_names := {d.metadata.name | some d in docs; d.kind == "Service"}

# Alert names across PrometheusRules, incl. the kind:List wrapper the chart emits for
# additionalPrometheusRulesMap.
alert_names := {r.alert |
	some d in docs
	some it in array.concat(object.get(d, "items", []), [d])
	it.kind == "PrometheusRule"
	some g in it.spec.groups
	some r in g.rules
	r.alert
}

# ServiceMonitors keyed by the namespaces they select (namespaceSelector.matchNames), so a
# monitor placed in `monitoring` for a target elsewhere is still attributable.
servicemonitor_targets := {ns |
	some d in docs
	d.kind == "ServiceMonitor"
	some ns in object.get(d.spec, ["namespaceSelector", "matchNames"], [object.get(d.metadata, "namespace", "monitoring")])
}

# Namespaces whose Services this repo renders; others are foundation-managed.
checkable_namespaces := {"monitoring", "camunda", "ingress-nginx", "cert-manager"}

# "<name>.<ns>.svc" hosts referenced in rendered ConfigMap/Secret values.
svc_references contains {"name": name, "namespace": ns} if {
	some d in docs
	d.kind in {"ConfigMap", "Secret"}
	some _, v in object.get(d, "data", {})
	is_string(v)
	some m in regex.find_n(`[a-z0-9][a-z0-9.-]*\.(?:monitoring|camunda|ingress-nginx|cert-manager)\.svc`, v, -1)
	parts := split(m, ".")
	count(parts) >= 3
	name := parts[count(parts) - 3]
	ns := parts[count(parts) - 2]
	ns in checkable_namespaces
}

# Defaulted fields that must stay ignored, or the Application never reaches Synced.
# deletionPolicy is absent on purpose: declared in the manifests instead.
externalsecret_defaulted_paths := {
	".spec.data[]?.remoteRef.conversionStrategy",
	".spec.data[]?.remoteRef.decodingStrategy",
	".spec.data[]?.remoteRef.metadataPolicy",
	".spec.dataFrom[]?.extract.conversionStrategy",
	".spec.dataFrom[]?.extract.decodingStrategy",
	".spec.dataFrom[]?.extract.metadataPolicy",
}

statefulset_defaulted_paths := {
	".spec.volumeClaimTemplates[]?.status",
	".spec.volumeClaimTemplates[]?.spec.volumeMode",
	".spec.volumeClaimTemplates[]?.metadata.annotations",
}
