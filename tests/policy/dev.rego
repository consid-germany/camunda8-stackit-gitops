# DEV-only assertions (RDBMS secondary storage, single-AZ, monitoring off, Optimize off).
package dev

import data.lib
import rego.v1

storage := lib.orchestration_config.camunda.data["secondary-storage"]

# --- secondary storage = RDBMS ---
deny contains msg if {
	storage.type != "rdbms"
	msg := sprintf("[dev][camunda] secondary-storage type = %q, want \"rdbms\"", [storage.type])
}

deny contains msg if {
	storage["autoconfigure-camunda-exporter"] != false
	msg := sprintf("[dev][camunda] autoconfigure-camunda-exporter = %v, want false", [storage["autoconfigure-camunda-exporter"]])
}

# --- history/retention enabled on the RDBMS path ---
deny contains msg if {
	storage.retention.enabled != true
	msg := sprintf("[dev][camunda] secondary-storage retention.enabled = %v, want true", [storage.retention.enabled])
}

# --- Optimize disabled ---
deny contains msg if {
	lib.svc_exists("dev-camunda-optimize")
	msg := "[dev][camunda] Optimize Service present; must be disabled in the RDBMS profile"
}

# --- monitoring off: no ServiceMonitor ---
deny contains msg if {
	n := count(lib.kinds("ServiceMonitor"))
	n > 0
	msg := sprintf("[dev][camunda] %d ServiceMonitor(s) rendered; monitoring is off in dev", [n])
}

# --- single-AZ sizing ---
deny contains msg if {
	r := lib.get("StatefulSet", "dev-camunda-zeebe").spec.replicas
	r != 1
	msg := sprintf("[dev][camunda] zeebe replicas = %v, want 1", [r])
}

# --- external-secrets: RDBMS profile ---
deny contains msg if {
	not "postgres-operate-credentials" in lib.external_secret_targets
	msg := "[dev][external-secrets] missing postgres-operate-credentials (RDBMS profile)"
}

deny contains msg if {
	some name in {"opensearch-credentials", "opensearch-backup-credentials"}
	name in lib.external_secret_targets
	msg := sprintf("[dev][external-secrets] unexpected %q ExternalSecret (OpenSearch not used in dev)", [name])
}

# --- no OpenSearch egress policy ---
deny contains msg if {
	lib.has("NetworkPolicy", "allow-egress-opensearch")
	msg := "[dev][network-policies] allow-egress-opensearch present; dev has no OpenSearch"
}

# --- dev hostnames land on the Ingresses ---
dev_hosts := {"my-camunda-dev.stackit.gg", "zeebe.my-camunda-dev.stackit.gg"}

deny contains msg if {
	some host in dev_hosts
	not host in lib.ingress_hosts
	msg := sprintf("[dev][ingress] expected host %q not found in rendered Ingresses", [host])
}

# --- camunda-backup CronJob config (dev variant) ---
deny contains msg if {
	got := object.get(lib.configmap_data("camunda-backup-config"), "MGMT_BASE_URL", "<missing>")
	got != "http://dev-camunda-zeebe-gateway:9600"
	msg := sprintf("[dev][camunda-backup] MGMT_BASE_URL = %q, want http://dev-camunda-zeebe-gateway:9600", [got])
}

deny contains msg if {
	some k in {"OPTIMIZE_MANAGEMENT_API", "BACKUP_RETENTION_DAYS"}
	k in object.keys(lib.configmap_data("camunda-backup-config"))
	msg := sprintf("[dev][camunda-backup] %s present; dev has no Optimize/OpenSearch backup", [k])
}

# --- bootstrap: dev always tracks main ---
deny contains msg if {
	some d in lib.docs
	d.kind == "Application"
	some src in lib.app_sources(d)
	src.repoURL == lib.gitops_repo_url
	src.targetRevision != "main"
	msg := sprintf("[dev][bootstrap] Application %q targetRevision = %q on this repo, want \"main\"", [d.metadata.name, src.targetRevision])
}

# --- ingress-nginx: default single controller ---
deny contains msg if {
	r := lib.ingress_nginx_controller.spec.replicas
	r != 1
	msg := sprintf("[dev][ingress-nginx] controller replicas = %v, want 1", [r])
}
