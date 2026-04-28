# PodPulse

> Open-source Kubernetes incident detector for logs + events. Zero instrumentation. Tells you *what* broke, *when*, and *probably why*.

PodPulse watches every pod, service, and deployment in your cluster, learns a baseline of "what normal looks like" per workload, and fires high-signal alerts the moment something deviates — a pod that never returned 502s suddenly does, a new error template appears right after a rollout, restart rate jumps, error volume spikes.

It works on raw container stdout/stderr — **no OpenTelemetry, no SDK, no code changes** — and ships a one-liner Helm install.

## What you get

- **Auto root-cause summary.** When an alert fires, it reads like an SRE wrote it: *"Deployment `payments-api` rolled out 7m ago (image `payments:v2.4.1`, commit `a3f1b2c`). 5xx ratio jumped from 0.2% → 14%. New error template `connection refused: redis-master:6379` first seen 6m ago. 3 of 5 pods restarted. Likely cause: bad release."*
- **Rollback suggestion** (never auto-executed): a copy-pasteable `kubectl rollout undo` line.
- **GitOps / CI correlation.** Image digest, git commit SHA, Helm release, ArgoCD `Application`, Flux `HelmRelease`, GitHub Actions run — all linked to the alert.
- **First-seen-by-version.** New-error alerts are gated on `(workload, image-digest)`, not just `(workload)` — slashing false positives from "we've seen this before."
- **Blast-radius scoring.** Severity comes from how many pods/workloads/namespaces are affected, not just rate.
- **Privacy-first.** Templates and counts only by default — raw logs are not stored. Optional in-cluster Ollama for richer alert phrasing; nothing leaves your cluster unless you opt in.
- **Multi-channel alerts.** Slack, Microsoft Teams, SMTP, generic webhook, PagerDuty.

## How it compares

| | PodPulse | Loki / OpenSearch | SigNoz | Coralogix / Datadog |
|---|---|---|---|---|
| K8s-native, zero instrumentation | ✅ | partial | requires OTel | requires agents |
| Anomaly detection on logs | ✅ | manual queries | ✅ (new exceptions) | ✅ (paid tier) |
| Root-cause summary + rollback hint | ✅ | ❌ | ❌ | partial |
| GitOps / commit correlation | ✅ | ❌ | ❌ | partial |
| Self-hosted, OSS | ✅ Apache-2.0 | ✅ | ✅ | ❌ |
| Stores raw logs by default | ❌ (templates only) | ✅ | ✅ | ✅ |

## Status

🚧 **Pre-alpha.** MVP wedge in active development: Slack alert + CLI + animated single-page web view, fed by new-template-after-rollout detection. See [PLAN](https://github.com/...) for the build order.

## Install (planned)

```sh
helm repo add podpulse https://podpulse.dev/charts
helm install podpulse podpulse/podpulse \
  --namespace podpulse --create-namespace \
  --set postgres.enabled=true \
  --set clickhouse.enabled=true \
  --set alerts.slack.webhook=$SLACK_WEBHOOK
```

CLI:

```sh
brew install podpulse/tap/podpulse
podpulse anomalies
podpulse explain <id>
```

## Architecture

```
DaemonSet pp-tailer  ─▶  Deployment pp-detector  ─▶  Postgres + ClickHouse
   (CRI logs)              (informers, Drain3,        (templates, counts,
                            EWMA, Holt-Winters,        short raw buffer)
                            RCA engine)
                                  │
                                  ▼
                       Slack / Teams / SMTP / PagerDuty / Webhook
                                  │
                                  ▼
                       CLI · Animated Web View · Full UI (later)
```

## License

Apache-2.0. See [LICENSE](LICENSE).
