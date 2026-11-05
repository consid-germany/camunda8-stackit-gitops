# Render-and-assert tests

Renders the full config for **both `dev` and `prod`** across all layers, then
asserts the rendered output matches what we intend. Catches a bad values edit or
a broken overlay before merge — nothing here touches a cluster.

## Run

```
tests/run.sh
```

Exits non-zero on any mismatch, naming the env, layer, and expected-vs-actual.

## Tooling

- `helm` (`helm template`) — Camunda + platform charts.
- `kubectl` (`kubectl kustomize`) — cluster-config overlays.
- `conftest` (OPA/Rego) — the assertions.

`tests/render.sh` runs `helm repo add`/`update` for the chart repos, so a first
run needs network. Rendered YAML lands in `tests/temp/` (gitignored).

## Layout

- `render.sh` — renders every layer per env into `tests/temp/<env>/`, mirroring
  the `bootstrap/<env>` Application sources (chart versions, valueFiles, overlays,
  raw manifest paths).
- `run.sh` — entrypoint: renders, then runs conftest per env.
- `policy/lib.rego` — shared helpers over the rendered docs.
- `policy/common.rego` — assertions for **both** envs (namespace `common`).
- `policy/dev.rego`, `policy/prod.rego` — env-specific assertions.

conftest runs with `--combine` (all of an env's docs are one input array) and
`--namespace common --namespace <env>`, so cross-resource checks (e.g. a
PDB targets must resolve to rendered Camunda objects) work.

## What it covers

Common (both envs):
- Every Camunda app container drops `ALL` capabilities.
- Every PDB's selector matches a rendered workload — the release-name trap, where
  a bare or guessed label selects zero pods and the budget protects nothing.
  Prometheus/Alertmanager are exempt: the operator builds their StatefulSets.
- Every rendered workload container has `resources.requests` and a memory
  limit — Prometheus/Alertmanager are operator-created from CRs and
  are out of this rule's reach, but their resources are set directly in the
  values. The hard-spread rule *does* reach them: it reads `spec.affinity` off
  the CR, since the operator builds their StatefulSets at runtime.
- Namespace Pod Security Standards labels: `enforce=restricted` on `camunda`,
  `ingress-nginx`, `cert-manager`, `default`; `monitoring` stays warn/audit
  only (node-exporter/alloy fail even baseline).
- Core ExternalSecrets present (entra, postgres identity/webmodeler, zeebe-backup,
  platform-connection-config, connector-secrets, stackit-sa-authentication).
- `entra-credentials` selects its three keys via `data:`, never the full
  `dataFrom:` bundle — ArgoCD/Grafana/WebModeler keys must not leak back into
  `camunda`.
- `default-deny` ingress + egress NetworkPolicies on `camunda`, `argocd`,
  `external-secrets-system`, `secrets-manager`, `ingress-nginx`, `cert-manager`
  (`monitoring` is prod-only, asserted in `prod.rego`).
- Any `*-from-apiserver` NetworkPolicy keeps a non-empty podSelector and a
  ports clause — never a namespace-wide any-port `0.0.0.0/0` allow.
- The old namespace-wide `allow-from-monitoring` rule must not reappear under
  its former name (see `allow-from-prometheus` under Prod, below).
- Camunda images are digest-pinned (`@sha256:...`), not tag-matched.
- Orchestration OIDC issuer is Microsoft Entra.
- Coordinated-backup env on the orchestration container (repo name, retention
  window/cleanup) — these are common to both envs.
- The ingress-nginx controller ConfigMap renders a narrow
  `whitelist-source-range` — the office-CIDR gate. Guards against
  `office-cidr-values.yaml` being dropped from an Application's `valueFiles`,
  which would leave every UI public with no other signal.
- The three PROXY-protocol settings the gate rests on are all present:
  `use-proxy-protocol: "true"` and a non-empty `proxy-real-ip-cidr` in the
  controller ConfigMap, `yawol.stackit.cloud/tcpProxyProtocol: "true"` on the
  controller Service. Drop any one and nginx sees the LB's `10.250.x.x`, matches
  it against the office CIDR, and 403s every client (the 2026-07-02 outage).
- Per-`Ingress` `whitelist-source-range` annotations are a narrowing list that
  still admits every CIDR the controller admits. A narrower per-ingress range *is*
  enforceable, because PROXY protocol gives nginx the real client IP. Never empty,
  and never allow-all — there are no sanctioned public doors since the webhook door
  was retired.
- The controller Service renders `loadBalancerSourceRanges` — the coarse **L4**
  gate, enforced by STACKIT outside the cluster so a values mistake in the L7 gate
  cannot leave the UIs open. It must be non-empty, never allow-all, and a
  **superset** of every range nginx admits (controller-level and per-`Ingress`);
  an L4 list narrower than the L7 rules silently blocks traffic they permit.
- cert-manager controller Deployment stays named `cert-manager` (fullnameOverride).
- Render-completeness guards so a missing resource fails loudly, never silently.

Bootstrap (the `bootstrap/<env>` chart helm-templated into `bs-bootstrap.yaml` —
prod with a dummy 40-hex SHA — plus `bootstrap/root-app-<env>.yaml` rendered raw
into `bs-root-app.yaml`):
- Every `Application` sets `syncPolicy.automated.prune` and `.selfHeal`.
- Every child `Application` sets `project` to `camunda-<env>` or `platform-<env>`,
  and both `AppProject`s render. The two roots are exempt — ArgoCD applies them
  before the projects exist, so they use `default`. `camunda-<env>` carries no
  `clusterResourceWhitelist`, and neither project whitelists `*`/`*` namespaced
  kinds (#89). Every Application's declared `spec.destination.namespace` is one its
  project allows — ArgoCD validates that field itself, not just the rendered
  resources, so a multi-namespace app that declares `""` needs it whitelisted.
  Every kind ArgoCD would turn into a sync task is whitelisted by one of the two
  projects — Helm hooks included, which are rendered but never appear in
  `Application.status.resources`. The `List` wrapper ArgoCD flattens and
  `helm.sh/hook: test` objects it ignores are excluded, as ArgoCD makes no task
  for either.
- No layer renders a `Secret` in either env — ArgoCD manages none.
- Every chart source pins an exact `MAJOR.MINOR.PATCH` (optionally `v`-prefixed),
  never a range.
- The chart version `render.sh` rendered equals the version `bootstrap/` pins,
  compared via the `helm.sh/chart` label. Without this, a chart bump landing in
  `bootstrap/` alone leaves the whole suite grading the previous chart. Charts the
  render does not cover are skipped.
- `ignoreDifferences` covers the ExternalSecret and StatefulSet fields that
  otherwise diff forever (#42), and `<env>-camunda` keeps its cascade-delete
  finalizer.
- `targetRevision` on this repo's own source: dev tracks `main`; prod carries a
  full commit SHA — never a branch or tag — with `root-app-prod.yaml`'s
  `REPLACE_ME_PROD_SHA` sentinel as the one break-glass exception
  (`dev.rego` / `prod.rego`).

Dev (RDBMS profile): secondary-storage `rdbms` + retention on, Optimize absent,
no ServiceMonitor, zeebe replicas 1, `postgres-operate-credentials` present and no
OpenSearch secrets, no OpenSearch egress policy, dev hostnames, camunda-backup
config points at `dev-camunda-zeebe-gateway` without Optimize/retention vars,
single ingress-nginx controller, connectors `envFrom` stays `optional: true`.

Prod (OpenSearch profile): secondary-storage `opensearch`, Optimize on with its
backup-repository env, ServiceMonitors present, zeebe replicas 3 + PDB
(maxUnavailable 1, instance `prod-camunda`), PDBs on connectors/console/
web-modeler-restapi (maxUnavailable 1) and the ingress-nginx controller
, connectors 2 replicas with `connector-secrets` `optional: false`
, `opensearch-credentials` + `opensearch-backup-credentials` +
`grafana-entra-secret` present, OpenSearch egress policy on ports 53091-53098,
`allow-from-prometheus` scoped to the Prometheus pod (not the whole
`monitoring` namespace), Alertmanager 3 replicas with a chart-native PDB
(maxUnavailable 1) and routed by the `teams-routing` AlertmanagerConfig with the
Watchdog on a real receiver and the webhook URL taken from a secret ref,
Grafana 2 replicas with a PDB and cookie session
affinity on its Ingress, Prometheus 2 replicas with a PDB, Alloy shipping logs with a pods-only
ClusterRole, Loki 2 replicas on S3 with a PDB and its credential left as a
`${LOKI_S3_*}` placeholder in the rendered config, monitoring egress
default-deny + scoped allows, no
ClusterRole other than kube-state-metrics/the operator/ingress-nginx grants
cluster-wide `secrets` access, Grafana `grafana.ini` disables
basic auth and the chart renders neither an admin Secret nor
`GF_SECURITY_ADMIN_*` env, every Ingress
`cert-manager.io/cluster-issuer` is `letsencrypt-production`, prod
hostnames, camunda-backup config with `OPTIMIZE_MANAGEMENT_API` +
`BACKUP_RETENTION_DAYS=7`, opensearch-retention CronJob (`INDEX_RETENTION_DAYS=60`),
two ingress-nginx controllers.

## Adding an assertion

Add one `deny contains msg if { ... }` block to `common.rego`, `dev.rego`, or
`prod.rego`. Reuse the `lib` helpers; message format is
`[<env>][<layer>] <what> = <actual>, want <expected>`.
