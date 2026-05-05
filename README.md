# PodPulse

> **Kubernetes incident root-cause engine. Not another log dashboard.**
> Open-source, zero instrumentation, one Helm command.

PodPulse fuses **log anomalies**, **ConfigMap/Secret diffs**, and **K8s events** into one ranked feed of issues — with the timeline, the likely cause, and the kubectl command to fix it.

[Live demo](https://podpulse-demo.fly.dev) · [Install](#install) · [How it works](#how-it-works) · [Compare](#how-it-compares)

---

## Why this exists

Most production K8s incidents are not log problems:

- ~35–40% are **misconfiguration** (empty configmap key, malformed secret JSON)
- ~20% are **bad deploys**
- ~15% are **resource exhaustion** (OOM, CPU throttle)
- The rest is networking, storage, scheduling

Existing tools (Datadog Watchdog, Robusta, Komodor, SigNoz) watch logs and metrics — and miss config drift entirely. They show you the **symptom** (errors in logs). PodPulse tries to show you the **cause** (the empty configmap key those errors are coming from).

## What it catches

| Signal | How | Why it matters |
|---|---|---|
| **New error template per workload** | Pure-Go Drain3 + image-digest tracking | "Errors that started after a rollout" — the headline detection |
| **ConfigMap/Secret diff** | client-go informer + per-key diff | Mount-aware: tells you which pods will break |
| **K8s Events fusion** | Categorized OOM / CrashLoop / FailedMount / ImagePull / Unhealthy | Half of incidents leave both a log line and an event |
| **Severity-aware filtering** | JSON `level` / logfmt / bracketed / keyword fallback | Only WARN+ feeds the templater — kills the info-log noise |
| **Cold-start gating** | 5-min warm-up + 200-line minimum | Stops the "first install fires 200 alerts" flood |
| **Variant grouping** | Same workload + same error topic within 10 min collapses | Cuts alert fatigue (3 "user not found" variants → one card) |
| **Audit log** | `metadata.managedFields` (no audit-webhook) | Who edited what, when — pull-based, zero apiserver config |

## Live demo

A hosted demo runs at **[podpulse-demo.fly.dev](https://podpulse-demo.fly.dev)** — synthetic workloads, real detector, anomalies fire every couple of minutes so you can click around.

## Install

```sh
# One command in your own cluster
helm repo add podpulse https://podpulse.github.io/charts
helm install podpulse podpulse/podpulse \
  --namespace podpulse --create-namespace \
  --set alerts.slack.webhook=$SLACK_WEBHOOK

# Open the dashboard
kubectl -n podpulse port-forward svc/podpulse-detector 8080:8080
open https://localhost:8080
```

Templates-only storage by default — raw logs never leave the cluster.

## How it works

```
┌──────────────────────────── Kubernetes cluster ────────────────────────────┐
│                                                                            │
│   pp-tailer (DaemonSet)              pp-detector (Deployment)              │
│   ────────────────────                ──────────────────────                │
│   reads /var/log/pods/*               K8s informers (pods, RS, svc,        │
│   parses CRI format          ──HTTPS─►  configmaps, secrets, events)       │
│   ships log batches                   Drain3 template miner                │
│                                       Severity classifier                  │
│                                       Issue engine                         │
│                                       HTTP API + embedded SPA              │
│                                       /k8s reverse proxy                   │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │
                          Slack · Teams · SMTP · PagerDuty · webhook
```

### Detection pipeline

1. **Tailer** reads `/var/log/pods/<ns>_<pod>_<uid>/<container>/0.log` (CRI format) on each node, ships batches over HTTPS.
2. **Severity classifier** filters the firehose — only WARN/ERROR/FATAL feed Drain3 (info-level chatter is not an anomaly even if it's new).
3. **Drain3** clusters lines into templates. Templates are tracked per `(workload, image-digest)` so a brand-new error after a rollout is detected.
4. **Cold-start gate**: workload must have been observed for 5 min AND emitted 200+ lines before any new-template alert can fire.
5. **Issue engine** correlates log anomalies with recent ConfigMap/Secret diffs and K8s events to produce ranked **Issues** (one per real incident, not per matching template).
6. **RCA** attaches a human headline, a "what happened" narrative, a confidence score with explainable factors, a timeline of recent deploys/configmap edits, and pattern-aware investigation steps.

## How it compares

| | Datadog Watchdog | Robusta | SigNoz | **PodPulse** |
|---|---|---|---|---|
| Log anomaly detection | Paid | Rule-based | Needs OTel | **Zero instrumentation** |
| ConfigMap diff with mount blast-radius | ❌ | ❌ | ❌ | **✅** |
| K8s Events fused into incidents | Partial | ✅ | ❌ | **✅** |
| Audit (who changed what) | Paid add-on | Partial | ❌ | **✅** (managedFields) |
| RBAC user onboarding from UI | ❌ | ❌ | ❌ | **✅** |
| Open source | ❌ | ✅ | ✅ | **Apache-2.0** |
| Self-hosted | ❌ | ✅ | ✅ | **✅** |

## What it doesn't do (yet, or by design)

- **Not an APM** — no tracing, no metrics collection. Use Prometheus + Grafana for that.
- **Not a long-term log store** — we keep templates + counts and a 1h rolling raw buffer. Loki/ELK if you need everything.
- **No auto-rollback** — by design. We suggest, humans run the command.
- **No security/runtime threat detection** — Falco's job.
- **In-memory state** today — SQLite persistence is on the roadmap.
- **Single-cluster** today — federation/SaaS is on the roadmap.

## Repo layout

```
cmd/
  pp-detector/      control-plane binary (Deployment)
  pp-tailer/        log-tailing binary (DaemonSet)
  podpulse/         CLI
  podpulse-demo/    single-process demo for fly.io / Render

internal/
  detect/drain3/    pure-Go Drain3 template miner
  detect/templates/ new-template-per-image-digest detector
  k8s/              client-go informers (pods, RS, svc, configmaps, secrets, events, audit)
  issue/            issue engine — fuses log + config + event signals
  logsev/           severity classifier (JSON / logfmt / bracketed / keyword)
  rca/              human headlines, narrative, confidence factors, suggestions
  redact/           secret pattern redaction (Stripe, HubSpot, JWT, mongo URIs, …)
  alert/            channel dispatchers (slack, teams, smtp, pagerduty, webhook)
  api/              HTTP API + embedded SPA
  proxy/            kubectl-compatible /k8s reverse proxy + self-signed TLS
  users/            user onboarding (SA + Role + RoleBinding + TokenRequest)
  tail/             CRI log file reader (rotation-aware)

charts/podpulse/    Helm chart
landing/            podpulse.vercel.app marketing page
Dockerfile          production image (detector + tailer)
Dockerfile.demo     fly.io demo image (single-process)
```

## License

[Apache-2.0](LICENSE).

---

Built for the team that's tired of opening ten kubectl tabs during an outage.
