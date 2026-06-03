# LLM-API-Sentinel

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A security scanner for LLM (Large Language Model) APIs. Detects prompt injection, jailbreak attempts, and sensitive data exposure through automated black-box testing.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Attack Payloads](#attack-payloads)
- [Output Formats](#output-formats)
- [Project Structure](#project-structure)
- [Cloud-Native Integration](#cloud-native-integration)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Batch Scanning** — Test target LLM APIs with 23+ built-in attack payloads in a single run
- **Prompt Injection Detection** — Identifies whether the model leaks system instructions or internal prompts
- **Jailbreak Detection** — Tests content safety guardrails against common jailbreak techniques
- **Sensitive Data Exposure** — Checks if the model inadvertently discloses credentials, keys, or PII
- **Multiple Output Formats** — Plain text table and professional Markdown security reports
- **Containerized** — Multi-stage Docker image for easy deployment in any environment
- **Cloud-Native Ready** — Designed for Kubernetes CronJob integration with Prometheus metrics export (roadmap)

## Quick Start

### Option 1: Build from Source

```bash
go install llm-api-sentinel@latest
```

Or clone and build:

```bash
git clone https://github.com/yourusername/llm-api-sentinel.git
cd llm-api-sentinel
go build -o sentinel .
```

### Option 2: Docker

```bash
# Build the image
docker build -t llm-api-sentinel .

# Run a scan
docker run --rm \
  -e MOONSHOT_API_KEY=your-key \
  llm-api-sentinel scan \
  --url https://api.moonshot.cn/v1/chat/completions \
  --apikey $MOONSHOT_API_KEY \
  --payloads /etc/sentinel/payloads/payloads.json \
  --output markdown
```

## Usage

### Command Line Interface

```
sentinel scan [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | *(required)* | LLM API endpoint URL (OpenAI-compatible) |
| `--apikey` | *(required)* | API authentication key |
| `--payloads` | `payloads/payloads.json` | Path to the JSON payload file |
| `--output` | `text` | Output format: `text` or `markdown` |

### Examples

**Basic text output scan:**

```bash
sentinel scan \
  --url https://api.moonshot.cn/v1/chat/completions \
  --apikey sk-your-api-key
```

**Scan with Markdown report:**

```bash
sentinel scan \
  --url https://api.moonshot.cn/v1/chat/completions \
  --apikey sk-your-api-key \
  --output markdown > scan-report.md
```

**Custom payload file:**

```bash
sentinel scan \
  --url https://api.moonshot.cn/v1/chat/completions \
  --apikey sk-your-api-key \
  --payloads /path/to/custom-payloads.json \
  --output markdown
```

## Attack Payloads

The scanner ships with 23 built-in payloads across three categories:

| Category | Count | Description |
|----------|-------|-------------|
| `prompt_injection` | 10 | Attempts to extract system prompts through role-playing, translation, JSON formatting, etc. |
| `jailbreak` | 10 | Tests content safety guardrails via DAN, role-playing, academic pretext, token smuggling, etc. |
| `sensitive_data` | 3 | Probes for training data leaks, hardcoded API keys, and PII disclosure |

### Custom Payloads

Create a JSON file following this schema:

```json
[
  {
    "id": "custom-001",
    "name": "My Custom Payload",
    "content": "Your attack message here",
    "type": "prompt_injection"
  }
]
```

Supported types: `prompt_injection`, `jailbreak`, `sensitive_data`

## Output Formats

### Text

Plain-text tabular output showing payload name, type, vulnerability status, and evidence:

```
================================================================================
No.  Payload                        Type               Vulnerable Evidence
--------------------------------------------------------------------------------
1    Direct System Prompt Repeat    prompt_injection   YES        响应中包含系统指令相关信息
2    Ignore Previous Instructions   prompt_injection   YES        响应中包含系统指令相关信息
...
================================================================================
Total: 23 payloads tested at 2026-06-01T12:00:00+08:00
```

### Markdown

Professional security report with summary table, vulnerability details grouped by type, risk levels, and actionable recommendations.

## Project Structure

```
llm-api-sentinel/
├── main.go                  # Entry point
├── cmd/
│   ├── root.go              # Root Cobra command
│   └── scan.go              # Scan subcommand
├── models/
│   └── models.go            # Shared data structures (OpenAI API compatible)
├── payloads/
│   ├── payloads.go          # Payload loading logic
│   └── payloads.json        # Built-in attack payloads (23 entries)
├── scanner/
│   └── scanner.go           # Scan engine and vulnerability detectors
├── reporter/
│   └── reporter.go          # Markdown report generator
├── Dockerfile               # Multi-stage container build
├── go.mod
└── README.md
```

## Cloud-Native Integration

LLM-API-Sentinel is designed from the ground up for modern cloud-native environments. Below are architectural patterns for production deployment.

### Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                 │
│                                                       │
│  ┌─────────────┐    CronJob (Scheduled)              │
│  │ Prometheus  │◄─── metrics scrape                  │
│  └──────┬──────┘                                     │
│         │                                             │
│  ┌──────▼──────┐    ┌───────────────────────────┐   │
│  │  Grafana    │    │  LLM-API-Sentinel Pod       │   │
│  │  Dashboard  │    │  ┌───────────────────────┐ │   │
│  └─────────────┘    │  │ Scanner Engine         │ │   │
│                      │  │ (23+ payloads)         │ │   │
│                      │  └───────────┬───────────┘ │   │
│                      │              │               │   │
│                      │  ┌───────────▼───────────┐ │   │
│                      │  │ Report Generator      │ │   │
│                      │  │ (Markdown / JSON)     │ │   │
│                      │  └───────────────────────┘ │   │
│                      └───────────────────────────┘   │
│                               │                       │
│                               ▼                       │
│                      ┌─────────────────┐             │
│                      │  LLM API Gateway │             │
│                      │  (Envoy / NGINX)│             │
│                      └────────┬────────┘             │
│                               │                       │
│                               ▼                       │
│                      ┌─────────────────┐             │
│                      │  LLM Service    │             │
│                      │  (Internal)     │             │
│                      └─────────────────┘             │
└─────────────────────────────────────────────────────┘
```

The scanner runs as a Kubernetes CronJob, scheduled to periodically probe the internal LLM API Gateway. It acts as an external adversarial validator — continuously testing whether deployed guardrails remain effective as models are updated.

### Kubernetes CronJob Deployment

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: llm-api-sentinel-scan
  namespace: security
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: sentinel
            image: llm-api-sentinel:latest
            args:
            - scan
            - --url
            - https://llm-gateway.internal/v1/chat/completions
            - --apikey
            - $(API_KEY)
            - --payloads
            - /etc/sentinel/payloads/payloads.json
            - --output
            - markdown
            env:
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: llm-api-credentials
                  key: api-key
            volumeMounts:
            - name: reports
              mountPath: /data
          restartPolicy: Never
          volumes:
          - name: reports
            persistentVolumeClaim:
              claimName: sentinel-reports
```

### Envoy Gateway Integration

The scanner can be integrated with Envoy Proxy by pointing it at your LLM API gateway's external endpoint. This validates:

1. **Gateway-level guards** — Whether request filtering at the gateway layer catches malicious payloads
2. **Rate limiting effectiveness** — Ensures scanners don't accidentally trip rate limiters (scan delays are configurable between payloads)
3. **Auth bypass attempts** — Some payloads probe for authentication weaknesses in the API layer itself

### Prometheus / Grafana Monitoring (Roadmap)

Future versions will export Prometheus metrics for observability:

```go
// Planned: prometheus metrics exporter
var (
    scanTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "sentinel_scans_total",
            Help: "Total number of scans executed",
        },
    )
    vulnerabilitiesFound = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "sentinel_vulnerabilities_found",
            Help: "Vulnerabilities found by type",
        },
        []string{"type"},
    )
    scanDuration = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "sentinel_scan_duration_seconds",
            Help:    "Scan duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
    )
)
```

**Grafana Dashboard Ideas:**

- **Security Posture Overview** — Vulnerability count over time, grouped by severity
- **Attack Surface Map** — Which payload types succeed most frequently
- **Response Time Baseline** — Drastic changes in LLM response time may indicate guardrail modifications or model updates
- **Alerting Rules** — Trigger alerts when new vulnerability types appear or vulnerability count exceeds threshold

### Why Cloud-Native?

LLM APIs are increasingly deployed behind cloud-native API gateways (Envoy, Traefik, Istio) within Kubernetes clusters. A security scanner that runs natively in this environment provides:

1. **Continuous Validation** — Scheduled scans ensure that model updates or prompt engineering changes don't regress security
2. **GitOps Integration** — Scan results can block deployments via CI/CD pipelines when new vulnerabilities are detected
3. **Zero-Trust Alignment** — Treats even internal LLM APIs as untrusted, validating them continuously
4. **Cost Efficiency** — CronJob scheduling avoids idle infrastructure costs

## Contributing

Contributions are welcome! Areas of interest:

- **New detection rules** for emerging attack vectors (grandma exploits, multi-turn injection, etc.)
- **Additional LLM providers** — Adapt the scanner for non-OpenAI-compatible APIs
- **Metrics export** — Implement the Prometheus metrics roadmap
- **Web dashboard** — A companion frontend for viewing historical scan results

## License

MIT License — see [LICENSE](LICENSE) file for details.

---

> **Disclaimer:** This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any API endpoint. The built-in payloads are designed for local evaluation and should not be used against production systems without explicit permission.
