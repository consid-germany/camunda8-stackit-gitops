# Camunda 8 on STACKIT — GitOps

ArgoCD GitOps repository for **Camunda 8.9 Self-Managed on [STACKIT](https://stackit.com/en)**
Kubernetes (SKE), using the camunda-platform Helm chart `14.10.0`. This repo holds everything that runs **inside** the
Kubernetes cluster, expressed as ArgoCD `Application`s + manifests.

The companion repo
**[camunda8-stackit-terraform](https://github.com/consid-germany/camunda8-stackit-terraform)** provisions the STACKIT *foundation*
(SKE cluster, PostgresFlex, OpenSearch, Object Storage, Secrets Manager, the
External Secrets Operator + the `ClusterSecretStore secrets-<env>` + secret-zero)
and bootstraps an in-cluster ArgoCD that syncs **this** repo. There is one ArgoCD
per cluster: the dev cluster syncs `bootstrap/dev`, the prod cluster syncs
`bootstrap/prod`.

**Further information:** [itsmestefanjay.dev/topics/camunda-stackit](https://itsmestefanjay.dev/topics/camunda-stackit/)

> **Status:** a reference implementation, extracted from a proof of concept. It is published as
> a starting point, not as a supported product. Replace every `REPLACE_ME*` value with your own
> before syncing. Camunda 8 Self-Managed is subject to Camunda's own license terms.
>
> **Blueprint:** GitHub Actions are disabled in this repository. The workflows in
> `.github/workflows/` are templates for your own copy.
>
> **Use at your own risk.** This code creates and destroys real cloud resources, identities
> and access rules. Do not apply it to a production environment without reviewing and testing
> it yourself. See [Disclaimer](#disclaimer).

> **ArgoCD's own config lives in the foundation, not here.** The `argocd-bootstrap`
> Terraform module (in `camunda8-stackit-terraform`) installs ArgoCD and configures the
> Argo UI's Entra OIDC login + group-based RBAC, syncing its client secret from the
> `argocd-client-secret` property of the shared `entra-credentials` SM entry into the
> `argocd` namespace. This repo does
> **not** manage the `argocd` namespace, so do not look for ArgoCD's Helm values or
> OIDC settings here.

---

## App-of-apps layout

```
bootstrap/
  root-app-dev.yaml      # ROOT Application -> renders bootstrap/dev (break-glass copy; the foundation applies the real one)
  root-app-prod.yaml     # ROOT Application -> renders bootstrap/prod (break-glass copy, SHA sentinel)
  dev/                   # Helm chart: AppProject + one Application per concern in templates/
  prod/                  #   (sync-wave annotated; the root passes targetRevision in)
platform/                # Helm value files for platform charts (cert-manager, ingress-nginx,
                         # kube-prometheus-stack, loki, alloy)
cluster-config/          # raw manifests: namespaces+PSS, ClusterIssuers, ExternalSecrets,
                         # NetworkPolicies, Zeebe StorageClass, PodDisruptionBudgets (prod),
                         # camunda-backup, opensearch-retention (prod),
                         # opensearch-index-settings (prod),
                         # landing page
camunda/values.yaml      # COMMON Camunda Helm values (shared across environments)
envs/dev/values.yaml     # dev overlay (rdbms, single-AZ, monitoring off, Optimize off)
envs/prod/values.yaml    # prod overlay (opensearch, 3-AZ, monitoring on, Optimize on)
```

The **root** Application (created by the foundation; `bootstrap/root-app-<env>.yaml`
is the break-glass copy) is the only thing the foundation's ArgoCD needs to point
at. It renders the `bootstrap/<env>` chart — two `AppProject`s and the child
`Application`s, with `targetRevision` passed in as a chart value. `platform-<env>`
holds the charts that create cluster-scoped objects (CRDs, cluster RBAC, webhooks,
IngressClass, StorageClass, ClusterIssuers); `camunda-<env>` holds everything else and
whitelists no cluster-scoped kind at all. Each child is
annotated with `argocd.argoproj.io/sync-wave` so the rollout is ordered:

| Wave | Apps |
|------|------|
| 0    | namespaces (+PSS), cert-manager, stackit-cert-manager-webhook, ingress-nginx, Zeebe StorageClass |
| 1    | ClusterIssuers, ExternalSecrets, NetworkPolicies (camunda, argocd, external-secrets-system, secrets-manager, ingress-nginx, cert-manager + opensearch egress / monitoring policies / Grafana secret in prod) |
| 2    | Camunda, landing page, PodDisruptionBudgets (prod: connectors/console/web-modeler-restapi) (+ kube-prometheus-stack, Loki, Alloy in prod) |
| 3    | camunda-backup (+ opensearch-retention, opensearch-index-settings and the Alertmanager routing in prod) |

Zeebe's own PDB is chart-native (`orchestration.podDisruptionBudget`, wave 2's
Camunda Application), not a raw manifest — only the three extra components'
PDBs are declared here.

Namespaces created here (`enforce=restricted` PSS — except
`monitoring`, which stays warn/audit only): `camunda`, `ingress-nginx`,
`cert-manager`, `monitoring`, `default`. The `external-secrets-system`,
`secrets-manager` and `argocd` namespaces are **foundation-managed** (including
their PSS labels) and are not declared here — their NetworkPolicies are,
though (`cluster-config/network-policies/base/`).

---

## Camunda values layering

The Camunda `Application` is **multi-source**: source 1 is the chart from
`https://helm.camunda.io`, source 2 is *this* repo (`ref: values`) providing the
value files via `$values/...`. Helm merges the value files in order, later wins:

```yaml
helm:
  valueFiles:
    - $values/camunda/values.yaml      # common: security, OIDC structure, DB plumbing
    - $values/envs/<env>/values.yaml   # overlay: dns, client ids, sizing, toggles
```

> **Helm list-merge caveat:** Helm *replaces* list values on merge (it only
> deep-merges maps). Do **not** redefine list keys such as `orchestration.env` in
> an env overlay -- that would drop the entries from the common file. Per-env
> scalars and maps are safe.

### Dynamic coordinates (the Terraform -> GitOps conversion)

PostgresFlex / OpenSearch hostnames are **not** known at commit time, so they are
never hardcoded in the values. Connection URLs are injected at runtime from the
ESO-synced secrets and resolved by Spring:

| Component | How the connection URL is wired | Chart keys (verified, 14.10.0) |
|-----------|----------------------------------|-------------------------------|
| **identity** | `externalDatabase.enabled: false` (so no datasource block / bad host is templated). `identity.env` injects `SPRING_DATASOURCE_URL` (from `platform-connection-config` → `IDENTITY_DATABASE_URL`), `SPRING_DATASOURCE_USERNAME`/`PASSWORD` (from `postgres-identity-credentials`). Spring relaxed binding maps `SPRING_DATASOURCE_*` → `spring.datasource.*`. | `identity.env` is rendered with `tpl (toYaml .)`, so `valueFrom.secretKeyRef` works. |
| **orchestration (rdbms)** | `data.secondaryStorage.rdbms.url: "${OPERATE_DATABASE_URL}"`, `.username: "${OPERATE_DATABASE_USERNAME}"` (rendered verbatim into the Spring `application.yaml` as placeholders), password via `rdbms.secret.existingSecret`. `orchestration.env` injects `OPERATE_DATABASE_URL` (from `platform-connection-config`) and `OPERATE_DATABASE_USERNAME` (from `postgres-operate-credentials`). | `rdbms.url` / `rdbms.username` rendered verbatim; password env is `VALUES_ORCHESTRATION_DATA_SECONDARYSTORAGE_RDBMS_PASSWORD`. |
| **orchestration (opensearch)** | `data.secondaryStorage.opensearch.url: "${OPENSEARCH_URL}"`, `auth.username: "${OPENSEARCH_USERNAME}"`, password via `opensearch.auth.secret.existingSecret`. `orchestration.env` injects `OPENSEARCH_URL` **and** `OPENSEARCH_USERNAME`, both from `platform-connection-config` (the username is STACKIT-generated, not static). | `camundaPlatform.opensearchURL` returns `...opensearch.url` verbatim when set; password env is `VALUES_OPENSEARCH_PASSWORD`. |
| **webModeler.restapi** | `externalDatabase.url: "${WEBMODELER_DATABASE_URL}"`, `.user: "${WEBMODELER_DATABASE_USER}"` (rendered verbatim into the restapi configmap), password via `externalDatabase.secret.existingSecret`. `restapi.env` injects the two placeholders from `platform-connection-config` + `postgres-webmodeler-credentials`. | `webModeler.restapi.databaseUrl`/`databaseUser` helpers pass the values through verbatim; password env is `SPRING_DATASOURCE_PASSWORD`. |
| **optimize (opensearch only)** | Optimize has **no single-url field** and no runtime-injection path; it renders `CAMUNDA_OPTIMIZE_OPENSEARCH_HOST`/`_HTTP_PORT` and `auth.username` as plain values at **template time**. Both the host and the (STACKIT-generated) username are only known **after the first prod foundation apply**, so `envs/prod/values.yaml` carries them as `REPLACE_ME_OPENSEARCH_HOST` / `REPLACE_ME_OPENSEARCH_USERNAME` — fill from `terraform -chdir=stacks/prod/foundation output`. Password via `opensearch-credentials`. | `CAMUNDA_OPTIMIZE_OPENSEARCH_HOST` value from `optimize.database.opensearch.url.host`. Since 14.8.5 the legacy `zeebe-record` exporter also resolves its url/username from these keys (`camundaPlatform.legacyExporterOpensearchURL`), with the password in `VALUES_OPTIMIZE_DATABASE_OPENSEARCH_PASSWORD`. |

Static values (dns_name, OIDC client IDs, Entra tenant id, admin/user group ids,
sizing, toggles, `secondaryStorage.type`, exporter selection, Optimize OpenSearch
host) live in `envs/<env>/values.yaml`. Placeholders are marked `REPLACE_ME_*`.

---

## ExternalSecrets (ESO)

ESO and the `ClusterSecretStore secrets-<env>` are installed by the foundation.
This repo only declares the `ExternalSecret` CRs, and it renders **no `Secret` of its
own** — ArgoCD has neither write access to Secrets nor them in its cache, so a chart that ships one needs a value that stops it (`tests/policy`
asserts this). Secret material reaches the cluster through ESO or an operator. Most live in the `camunda`
namespace; three are in `monitoring` (Grafana, Teams webhook, Loki storage — prod only) and one is in
`cert-manager` (DNS-01 SA key). `secretStoreRef`: `name: secrets-<env>`, `kind: ClusterSecretStore`.

| SM entry | k8s Secret | Namespace | Notes |
|----------|-----------|-----------|-------|
| `entra-credentials` | `entra-credentials` | camunda | identity, optimize + orchestration-cluster client secrets only |
| `postgres-<env>-identity-user-credentials` | `postgres-identity-credentials` | camunda | username, password |
| `postgres-<env>-webmodeler-user-credentials` | `postgres-webmodeler-credentials` | camunda | |
| `postgres-<env>-operate-user-credentials` | `postgres-operate-credentials` | camunda | **rdbms only** |
| `opensearch-credentials` | `opensearch-credentials` | camunda | **opensearch only**, key `password`; SM entry name from `modules/stackit-opensearch` (no env suffix — each env has its own SM instance) |
| `zeebe-backup-credentials` | `zeebe-backup-credentials` | camunda | ZEEBE_* keys, consumed via `envFrom` |
| `platform-connection-config` | `platform-connection-config` | camunda | foundation-written: POSTGRES_HOST/PORT, *_DATABASE_URL, OPENSEARCH_URL |
| `camunda-connector-secrets-<env>` | `connector-secrets` | camunda | every key rewritten to `SECRET_<key>` |
| `web-modeler-pusher-credentials` | `web-modeler-pusher-credentials` | camunda | foundation-written: `pusher-app-secret`, `pusher-app-key`. Internal restapi↔websockets secret; without it the chart regenerates one per render |
| `entra-credentials` (key `grafana-client-secret`) | `grafana-entra-secret` | monitoring | **prod only**; exposed as `GF_AUTH_AZUREAD_CLIENT_SECRET` |
| `teams-webhook-url` (key `url`) | `teams-webhook-url` | monitoring | **prod only**; Power Automate webhook (bearer `sig=`), referenced by key from the `teams-routing` AlertmanagerConfig; prometheus-operator resolves it into the Alertmanager config it generates. Seeded by hand (Power Automate mints it) — infra `SETUP.md` Step 20; re-seed before ArgoCD syncs after a foundation rebuild |
| `loki-storage-credentials` | `loki-storage-credentials` | monitoring | **prod only**; foundation-written LOKI_S3_* keys for the `<deployment>-logs` bucket. Consumed as env vars and expanded by Loki (`-config.expand-env=true`), so the rendered config object carries `${LOKI_S3_*}` placeholders, never a credential |
| `stackit-dns-sa-key` | `stackit-sa-authentication` | cert-manager | DNS-01 webhook SA key, mapped to key `sa.json` (`cert-manager-dns.yaml`) |

The OpenSearch SM entry name (`opensearch-credentials`) is set by
`locals.credentials_kv_secret` in `modules/stackit-opensearch`; the prod ExternalSecret
extracts that exact key. Adjust both together if it ever changes.

---

## Office-CIDR ingress gate

**Both envs gate the ingress LB at both layers**. The coarse gate is L4
`loadBalancerSourceRanges` on the controller Service — provider-enforced and whole-LB, so
it carries the union of every admitted range: the base list (office + CI runner) sits in
`office-cidr-values.yaml`; an env that admits more must repeat the full list, because Helm
replaces lists on merge. The fine gate is the controller-level L7 `whitelist-source-range`,
which keeps the per-host granularity L4 cannot express — a per-Ingress `whitelist-source-range`
can widen one host without opening the UIs. yawol by default SNATs the client
source IP — a naive `whitelist-source-range` therefore blocks everyone (a full 403 outage).
The working L7 gate enables yawol PROXY protocol (`yawol.stackit.cloud/tcpProxyProtocol`) plus nginx
`use-proxy-protocol` + `proxy-real-ip-cidr`, so nginx sees the real client IP and the
controller-level `whitelist-source-range` filters correctly — see
`platform/ingress-nginx/<env>-values.yaml`, both knobs must move together. App-layer access
control (Camunda Identity / ArgoCD OIDC) + TLS remains in place on top.

**The CIDR itself lives in exactly one file**, `platform/ingress-nginx/office-cidr-values.yaml`,
which both envs' ingress-nginx `Application`s merge ahead of their `<env>-values.yaml` (Helm
deep-merges the `controller.config` map, so the two files compose). Change the office IP
there once, not per env — plus prod's repeated L4 list in `prod-values.yaml`, which conftest
asserts still carries the office CIDR. Because dev tracks `main` and prod pins a commit
SHA, dev still picks the change up first and prod follows on promotion. Dropping the
valueFile from an Application would silently remove the gate and leave every UI public, so
`tests/policy` asserts the rendered controller ConfigMap carries a narrow
`whitelist-source-range` — and, alongside it, all three PROXY-protocol settings the gate
depends on, so the knobs cannot drift apart. If an
office IP change locks you out, update the CIDR here and in the infra repo's
`office_cidr` / `api_allowed_cidrs` together.

**There is no public ingress host.** Inbound connectors are not deployed; the webhook door
that once exposed `/connectors` on a public `webhooks.<dns_name>` host was retired, along
with its DNS records, when the L4 gate was added. Outbound connectors are unaffected.

---

## Grafana dashboards (prod)

Grafana ships with kube-prometheus-stack's built-in dashboards, filed under a `Kubernetes`
folder via `grafana.sidecar.dashboards.annotations`. `folderAnnotation: grafana_folder` lets
any other dashboard pick its own folder.

Grafana itself is stateless in prod (`persistence.enabled: false`) and runs two
replicas: dashboards arrive from ConfigMaps, datasources come from values, and identity
from Entra. What does not survive a restart is per-user state — starred dashboards,
preferences and manually added annotations — and a session is valid only on the replica
that issued it, which is why the Ingress pins a browser with a session cookie.

`nodes-aix` and `nodes-darwin` are switched off
(`nodeExporter.operatingSystems.{aix,darwin}.enabled: false`) — the workers are
Linux, so both rendered empty. The other built-ins have no individual chart toggle; they
are all-or-nothing behind `grafana.defaultDashboardsEnabled`, so they stay.

### Adding the Camunda dashboards

Camunda publishes Grafana dashboards in
[`camunda/camunda`](https://github.com/camunda/camunda) under `monitor/grafana/`, under
Camunda's own license terms. They are not included here. To load them, put each JSON file
in a ConfigMap in the `monitoring` namespace, labelled `grafana_dashboard: "1"` and
annotated `grafana_folder: Camunda` (the sidecar watches only Grafana's own namespace).
Use stable ConfigMap names and server-side apply; the JSON is past the last-applied
annotation limit.

Not all of them fit an 8.9 / OpenSearch deployment. Counted against live metric names:

| Dashboard | Panels with data | Notes |
|-----------|------------------|-------|
| `jvm.json`                | 32/35 | heap, GC, threads per component JVM |
| `core-features-rest.json` |  4/4  | REST latency + error rate by URI |
| `identity-overview.json`  |  8/8  | auth/OIDC; 6 are error panels, empty while healthy |
| `zeebe-overview.json`     | 11/15 | partition health, Raft role, backpressure, exporter |
| `data-layer.json`         | 19/36 | the 19 cover `zeebe_camunda_exporter_*` (the OpenSearch export path behind `ZeebeExportingPaused`) |

The rest render empty here: `elasticsearch.json` (no elasticsearch-exporter),
`operate.json` / `tasklist.json` (8.9 folds both into the orchestration app),
the load-test dashboards (they need a benchmark driver's `starter_*` metrics),
`core-features/overview.json` (SaaS-only filters), `spring.json` (pre-Spring-Boot-4
metric names) and `zeebe.json` (126 panels use renamed `atomix_*` metrics).

Two upstream issues show up under file provisioning:

- `core-features-rest.json` has no `DS_PROMETHEUS` templating variable, so its
  `${DS_PROMETHEUS}` datasource refs never resolve. Pin them to `uid: prometheus`.
- `data-layer.json` matches `cluster="$cluster"` exactly against a variable whose All
  value is `.*`, leaving the partition picker empty. Use `cluster=~"$cluster"`.

Drop the numeric `id` from each file; Grafana rejects a provisioned dashboard that
carries one.

---

## How to add / change an Application

- **New in-cluster workload:** drop the manifests under `cluster-config/<thing>/`
  (raw) or add value files under `platform/<chart>/` (Helm), then add an
  `Application` to **both** `bootstrap/dev/templates` and `bootstrap/prod/templates`
  with the right `sync-wave`, `project: camunda-<env>` (or `platform-<env>` if it
  creates cluster-scoped objects), repoURL placeholder
  `https://github.com/REPLACE_ME-github-org/camunda8-stackit-gitops.git`, and destination
  `https://kubernetes.default.svc`. On this repo's `repoURL`, `targetRevision` is
  `{{ .Values.targetRevision | quote }}` — the root Application passes the revision
  in (see *dev -> prod promotion*); external chart sources keep their own version pin.
- **New Helm chart:** add its repo URL to the `sourceRepos` of the project it belongs
  to, in `bootstrap/<env>/00-project.yaml`, and any kind it renders to that project's
  `namespaceResourceWhitelist` / `clusterResourceWhitelist`. A kind that is missing
  fails the sync with a message naming it.
- **Change Camunda values:** edit `camunda/values.yaml` (common) or
  `envs/<env>/values.yaml` (env-specific). Re-render locally before committing
  (see *Verifying changes*).

## dev -> prod promotion

**dev tracks `main`; prod pins a full commit SHA.** A merge to `main` deploys to dev
immediately. Prod deploys only the SHA pinned in the infra repo's
`stacks/prod/foundation/prod.tfvars` (`gitops.repo_revision`) — promotion is a reviewed
PR there that bumps the SHA, applied by the runner; rollback is setting the previous SHA.

`bootstrap/<env>` is a Helm chart: the foundation's root Application passes the revision
as the `targetRevision` chart value, and every child Application sourcing this repo
renders it. This is per-Application on purpose: ArgoCD child Applications do **not**
inherit the root's `targetRevision`, so pinning only the root would leave every child
reading live `main`. `bootstrap/prod/values.schema.json` refuses anything but a 40-hex
SHA, and `tests/run.sh` asserts the rendered prod Applications carry one while dev always
carries `main`.

1. Land and validate the change in dev (`envs/dev/values.yaml`, `bootstrap/dev/...`,
   `cluster-config/.../dev`). The dev ArgoCD reconciles it off `main`.
2. Mirror it into the prod equivalents and merge the PR. Nothing happens in prod yet.
3. Bump the prod SHA (`gitops.repo_revision` in the infra repo's `prod.tfvars`) to promote.

---

## Verifying changes

Render the Camunda chart with the layered values before committing:

```bash
helm repo add camunda https://helm.camunda.io
helm template camunda camunda/camunda-platform --version 14.10.0 \
  -f camunda/values.yaml -f envs/dev/values.yaml --namespace camunda
helm template camunda camunda/camunda-platform --version 14.10.0 \
  -f camunda/values.yaml -f envs/prod/values.yaml --namespace camunda
```

Lint the raw manifests (`bootstrap/<env>/templates` are Helm templates, not raw
YAML — `tests/run.sh` renders and asserts those):

```bash
kubeconform -strict -ignore-missing-schemas cluster-config/
yamllint cluster-config/ platform/ camunda/ envs/
```

---

## Operator checklist (Step 0)

**dev is fully filled in.** `envs/dev/values.yaml` has the real Entra tenant id,
the six OIDC client ids, the admin/user group ids, the break-glass admin email and
the real host `my-camunda-dev.stackit.gg`. No `REPLACE_ME_*` remain in dev, so the
dev cluster can sync as-is.

**prod is fully filled in.** `envs/prod/values.yaml` and
`platform/kube-prometheus-stack/prod-values.yaml` have the real Entra tenant id, all OIDC
client ids (including Grafana), admin/user group ids, and the real DNS. The Teams webhook
URL is **not** in Git — it comes from the SM entry `teams-webhook-url` via ESO, which
the `teams-routing` AlertmanagerConfig (`cluster-config/alertmanager/prod`) references by
secret key. That CR is Alertmanager's whole top-level configuration; the chart's own
`alertmanager.config` is not used.
The two values STACKIT does not mint until the first prod foundation apply are also filled:

- The Optimize block of `envs/prod/values.yaml` has the real OpenSearch `host`/`port` and
  `auth.username` (no `REPLACE_ME_*` left) -- Optimize consumes them at Helm template time
  (no runtime-injection path). If this ever needs re-filling after a foundation rebuild, the
  source is `terraform -chdir=stacks/prod/foundation output -raw opensearch_host` /
  `... -raw opensearch_username`.

Foundation / cluster-config items to set per environment regardless of the above:

- `cluster-config/issuers/<env>/clusterissuers.yaml`: STACKIT `projectId`.
- `platform/ingress-nginx/<env>-values.yaml`: TLS/HSTS hardening + the office-CIDR
  allowlist via PROXY protocol (see above).
- `cluster-config/landing-page/<env>`: the host (must match the values files; dev
  already uses `my-camunda-dev.stackit.gg`).

The `cert-manager` DNS-01 `stackit-sa-authentication` Secret is now synced by ESO
(`cluster-config/external-secrets/<env>/cert-manager-dns.yaml`) from the
operator-seeded SM entry `stackit-dns-sa-key`, so it no longer has to be created by
hand -- just make sure that SM entry exists.

## Disclaimer

This repository is provided "as is", without warranty of any kind, express or implied,
including but not limited to the warranties of merchantability, fitness for a particular
purpose and non-infringement. It is a reference implementation, not a product, and comes
with no support, maintenance or security-update commitment.

You are solely responsible for reviewing, testing, adapting and operating this code in your
own environment, including its security configuration, sizing, backups, compliance with
applicable law and regulation, and the costs it incurs with your cloud provider. Do not use
it in production without that review.

To the maximum extent permitted by applicable law, the authors and contributors are not
liable for any damages, data loss, security incidents, service outages, costs or other
losses arising from the use of, or inability to use, this code, whether used as published
or modified.

STACKIT, Camunda, Microsoft Entra ID, GitHub and other names are trademarks of their
respective owners. This project is not affiliated with or endorsed by them.
