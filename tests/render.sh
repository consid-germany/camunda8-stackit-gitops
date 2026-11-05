#!/usr/bin/env bash
# Render every layer for dev and prod into tests/temp/<env> as plain YAML.
# Mirrors the bootstrap/<env> Application sources (chart versions, valueFiles,
# kustomize overlays, raw manifest paths) plus the bootstrap/<env> Application manifests
# themselves. Feeds the conftest policies.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/tests/temp"
cd "${REPO_ROOT}"

CAMUNDA_CHART_VERSION="14.10.0"
CERT_MANAGER_VERSION="v1.20.0"
INGRESS_NGINX_VERSION="4.15.1"
KPS_VERSION="72.3.0"
LOKI_VERSION="6.28.0"
ALLOY_VERSION="1.12.1"
TEST_PROD_SHA="0000000000000000000000000000000000000000"

log() { printf '  %s\n' "$*"; }
fail() { printf 'render FAILED: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "$1 not installed"; }
need helm
# Helm 3 renders these charts differently (nil coalescing); ArgoCD >= 3.5 uses Helm 4.
case "$(helm version --short)" in v4.*) ;; *) fail "helm 4 required, found $(helm version --short)" ;; esac
need kubectl

# Add the chart repos (idempotent) and refresh the index.
add_repos() {
  helm repo add camunda https://helm.camunda.io >/dev/null 2>&1 || true
  helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
  helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
  helm repo add grafana https://grafana.github.io/helm-charts >/dev/null 2>&1 || true
  retry helm repo update >/dev/null 2>&1 || fail "helm repo update failed (network?)"
}

# The chart hosts 5xx often enough to red a PR on nothing. 3 attempts, 10s then 20s.
retry() {
  local attempt
  for attempt in 1 2 3; do
    if [ "$attempt" -gt 1 ]; then sleep $(( (attempt - 1) * 10 )); fi
    "$@" && return 0
  done
  return 1
}

# helm_render <out> <release> <repo/chart> <version> <namespace> <valuefile...>
helm_render() {
  local out="$1" release="$2" chart="$3" version="$4" ns="$5"; shift 5
  local args=() vf
  for vf in "$@"; do args+=(-f "$vf"); done
  # --api-versions: several charts gate ServiceMonitors on the CRD being present. ArgoCD
  # renders against the live cluster, so without this the local render silently omits them.
  local attempt
  for attempt in 1 2 3; do
    if [ "$attempt" -gt 1 ]; then sleep $(( (attempt - 1) * 10 )); fi
    helm template "$release" "$chart" --version "$version" -n "$ns" \
      --api-versions "monitoring.coreos.com/v1/ServiceMonitor" \
      "${args[@]}" > "$out" && return 0
  done
  fail "helm template ${release} (${chart} ${version})"
}

# kustomize_render <out> <overlay-dir>
kustomize_render() {
  kubectl kustomize "$2" > "$1" || fail "kubectl kustomize $2"
}

# raw_render <out> <dir...>  -- concat every yaml under the given dirs (ArgoCD directory source)
raw_render() {
  local out="$1"; shift
  local src f
  : > "$out"
  for src in "$@"; do
    while IFS= read -r f; do
      printf '\n---\n' >> "$out"
      cat "$f" >> "$out"
    done < <(find "$src" -type f \( -name '*.yaml' -o -name '*.yml' \) | sort)
  done
}

render_env() {
  local env="$1"
  local dir="${OUT}/${env}"
  rm -rf "$dir"; mkdir -p "$dir"
  log "[${env}] camunda"
  helm_render "${dir}/camunda.yaml" "${env}-camunda" camunda/camunda-platform "$CAMUNDA_CHART_VERSION" camunda \
    camunda/values.yaml "envs/${env}/values.yaml"

  # bootstrap/<env> is a Helm chart (app-of-apps); the root passes targetRevision in.
  # Prod gets a dummy 40-hex SHA: the policies assert the *format*, the real pin
  # lives in the infra repo's prod.tfvars.
  log "[${env}] bootstrap"
  local rev_args=(--set "targetRevision=main")
  [ "$env" = "prod" ] && rev_args=(--set "targetRevision=${TEST_PROD_SHA}")
  helm template "root-${env}" "bootstrap/${env}" -n argocd "${rev_args[@]}" \
    > "${dir}/bs-bootstrap.yaml" || fail "helm template bootstrap/${env}"
  raw_render      "${dir}/bs-root-app.yaml"         "bootstrap/root-app-${env}.yaml"

  log "[${env}] cluster-config"
  raw_render      "${dir}/cc-namespaces.yaml"       cluster-config/namespaces
  raw_render      "${dir}/cc-storage.yaml"          cluster-config/storage
  raw_render      "${dir}/cc-issuers.yaml"          "cluster-config/issuers/${env}"
  raw_render      "${dir}/cc-external-secrets.yaml" "cluster-config/external-secrets/${env}"
  kustomize_render "${dir}/cc-landing-page.yaml"    "cluster-config/landing-page/${env}"
  kustomize_render "${dir}/cc-camunda-backup.yaml"  "cluster-config/camunda-backup/${env}"

  log "[${env}] platform"
  local cm_values=(platform/cert-manager/values.yaml)
  [ "$env" = "prod" ] && cm_values+=(platform/cert-manager/prod-values.yaml)
  helm_render "${dir}/plat-cert-manager.yaml" "${env}-cert-manager" jetstack/cert-manager "$CERT_MANAGER_VERSION" cert-manager \
    "${cm_values[@]}"
  helm_render "${dir}/plat-ingress-nginx.yaml" "${env}-ingress-nginx" ingress-nginx/ingress-nginx "$INGRESS_NGINX_VERSION" ingress-nginx \
    platform/ingress-nginx/office-cidr-values.yaml "platform/ingress-nginx/${env}-values.yaml"
}

add_repos
render_env dev

# prod-only layers (see bootstrap/prod).
render_env prod
raw_render       "${OUT}/prod/cc-external-secrets-monitoring.yaml" cluster-config/external-secrets/monitoring
raw_render       "${OUT}/prod/cc-alertmanager-config.yaml" cluster-config/alertmanager/prod
raw_render       "${OUT}/prod/cc-network-policies.yaml" cluster-config/network-policies/base cluster-config/network-policies/opensearch cluster-config/network-policies/monitoring
kustomize_render "${OUT}/prod/cc-opensearch-retention.yaml" cluster-config/opensearch-retention/prod
kustomize_render "${OUT}/prod/cc-opensearch-index-settings.yaml" cluster-config/opensearch-index-settings/prod
raw_render       "${OUT}/prod/cc-disruption-budgets.yaml" cluster-config/disruption-budgets/prod
helm_render "${OUT}/prod/plat-kube-prometheus-stack.yaml" prod-kube-prometheus-stack prometheus-community/kube-prometheus-stack "$KPS_VERSION" monitoring \
  platform/kube-prometheus-stack/prod-values.yaml
helm_render "${OUT}/prod/plat-loki.yaml" prod-loki grafana/loki "$LOKI_VERSION" monitoring \
  platform/loki/values.yaml
helm_render "${OUT}/prod/plat-alloy.yaml" prod-alloy grafana/alloy "$ALLOY_VERSION" monitoring \
  platform/alloy/values.yaml

# dev network policies = base only (no opensearch/monitoring; RDBMS profile, monitoring off).
raw_render "${OUT}/dev/cc-network-policies.yaml" cluster-config/network-policies/base

printf 'render OK -> %s\n' "${OUT}"
