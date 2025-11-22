# BlueFlux Architecture

## 1. Overview

BlueFlux is an LLM-aware defensive agent designed to detect PromptFlux-style, AI-assisted polymorphic malware. It does this by monitoring:

- LLM API usage (prompts and responses),
- simple host context (which app/container/client is calling the LLM),
- network behavior associated with those LLM-using workloads.

BlueFlux is not a generic antivirus. Its focus is to detect processes or applications that:

1. Repeatedly call an LLM to **generate or mutate potentially malicious code**, and
2. Execute that code while exhibiting **suspicious network behavior** (e.g., beacons, exfiltration-like patterns).

The system is built around four layers:

1. Telemetry layer (LLM logs + network capture)
2. BlueFlux agent core (ingestion, correlation, orchestration)
3. Analyzer layer (prompt intent, LLM usage patterns, network behavior)
4. Reporting & CLI (alerts, summaries, demo output)

All components are packaged in a Docker-based demo environment that includes an attacker simulator.

---

## 2. Logical Architecture

At a high level:

- **Monitored Environment**
  - Attacker app (AI-malware / PromptFlux-style simulator) runs inside a container.
  - It uses Grok through a local **LLM proxy**.

- **Telemetry Capture**
  - `llm_proxy` logs every LLM API request/response pair into structured telemetry files.
  - `net_capture` (e.g., tshark/pyshark) captures network flows for the monitored environment and writes summarized network telemetry.

- **BlueFlux Agent**
  - Reads telemetry from shared volumes.
  - Correlates LLM usage with network activity into sessions.
  - Applies analyzers to derive a risk score per session.
  - Emits alerts and reports via the CLI and file outputs.

---

## 3. Component Breakdown

### 3.1 Monitored Environment (Attacker / Demo)

**Responsibilities**

- Provide realistic PromptFlux-style activity:
  - Repeated LLM calls to modify/mutate code.
  - Execution of generated scripts or binaries.
- Stay fully contained within Docker (no impact on host).

**Implementation Notes**

- Lives under `attack_scenarios/`:
  - `ai_malware/`: imported or vendored AI-malware project.
- Communicates with `llm_proxy` instead of directly with Grok.

---

### 3.2 LLM Proxy

**Responsibilities**

- Expose an HTTP endpoint that mimics Grok’s API to the attacker app.
- Forward each request to the real Grok API.
- Log **full telemetry** for each request/response:
  - timestamp
  - client identifier (container name, API key, etc.)
  - prompt text
  - response metadata (truncated content or hashes, tokens used)
- Write logs to a shared volume in a structured format (e.g., JSONL).

**Key Properties**

- The proxy is the **primary telemetry source** for LLM usage.
- It must be resilient to high-frequency calls and avoid blocking the demo.

---

### 3.3 Network Capture Service

**Responsibilities**

- Observe network traffic on the Docker network where the attacker app runs.
- Capture and summarize:
  - source/destination IP/port
  - protocol
  - byte counts
  - timing characteristics (e.g., inter-packet gaps, flow duration)
- Emit **network summaries** into a shared volume for BlueFlux.

**Implementation Notes**

- `net_capture` container uses `tshark` or `pyshark` to:
  - either store full PCAP,
  - or directly generate JSON flow summaries.
- BlueFlux will consume the processed summaries, not raw PCAP, to simplify analysis.

---

### 3.4 BlueFlux Agent Core

The agent core lives in the `blueflux_core` Python package and is responsible for:

1. Telemetry ingestion
2. Correlation / session building
3. Analyzer orchestration
4. Risk scoring and alerting

#### 3.4.1 Telemetry Ingestion

Modules:
- `blueflux_core/telemetry/llm_logs.py`
- `blueflux_core/telemetry/network.py`

Responsibilities:

- Load LLM telemetry from the proxy logs.
- Load network summaries from the capture service.
- Normalize them into common data models (`TelemetryEvent`, `NetworkEvent`).
- Support:
  - **replay mode** (process a finite log file),
  - **monitor mode** (tail files for near-real-time processing).

#### 3.4.2 Correlation and Sessions

Module:
- `blueflux_core/telemetry/correlator.py`

Responsibilities:

- Associate LLM events with network events into **sessions** using:
  - client/container identifiers,
  - coarse time window alignment,
  - optional port/domain filters if needed.
- Provide a simple interface to the analyzers:
  - `iter_sessions()` yields sessions containing:
    - ordered LLM requests/responses,
    - aggregated network flows for the same period and client.

#### 3.4.3 Analyzer Layer

Folder:
- `blueflux_core/analyzers/`

All analyzers implement a common interface defined in `base.py` and are registered via configuration.

Primary analyzers:

1. **PromptIntentAnalyzer (`prompt_intent.py`)**
   - Detects suspicious or dual-use prompt content based on:
     - keyword and pattern rules (e.g., “obfuscate”, “bypass antivirus”, “for educational purposes only”, “cybersecurity student”).
     - optional calls to Grok to classify intent/maliciousness.

2. **LLMUsagePatternAnalyzer (`llm_usage_pattern.py`)**
   - Works over sessions:
     - detects repeated mutate/execute/mutate loops.
     - counts how many prompts refer to “previous code”, “fix the error”, “make it stealthier”, etc.
   - Maintains in-memory windows (e.g., last N events per session).

3. **NetworkBehaviorAnalyzer (`network_behavior.py`)**
   - Examines network summaries associated with suspicious sessions:
     - repeated outbound connections shortly after high-risk prompts,
     - beacon-like periodic patterns,
     - connections to unusual ports/domains.
   - Produces a risk contribution based on heuristic rules.

Each analyzer returns an `AnalyzerResult` object containing:

- local risk score,
- short explanation (for the report),
- references to telemetry artifacts (event IDs, flow IDs).

#### 3.4.4 Tools Layer

Folder:
- `blueflux_core/tools/`

Responsibilities:

- Provide thin wrappers around external services and tools so analyzers remain focused on detection logic.

Components:

- `llm_client.py`
  - Defender-side use of Grok (classification, explanation).
- `net_capture_parser.py`
  - Convenience functions to parse and normalize capture outputs (if needed from raw PCAP).
- `vt_client.py` (optional)
  - Adds reputation data for IPs/domains/hashes if API keys are available.

---

### 3.4.5 Agent Engine, Policies, and State

Folder:
- `blueflux_core/agent/`

Components:

- `engine.py`
  - Main orchestration loop.
  - Steps:
    1. Read telemetry events and update sessions.
    2. For each session, run configured analyzers.
    3. Combine analyzer outputs into a `RiskAssessment`.
    4. Emit `Alert` objects when thresholds are exceeded.

- `policies.py`
  - Encapsulates risk scoring and thresholds.
  - For example:
    - PromptIntent score (0–1),
    - LLMUsagePattern score (0–1),
    - NetworkBehavior score (0–1),
    - Weighted combination → overall risk level (Low/Medium/High).

- `state.py`
  - Short-lived caches:
    - recent sessions,
    - previously alerted sessions,
    - sliding windows for pattern detection.

---

### 3.5 Reporting and CLI

Folder:
- `blueflux_core/reporting/`
- `blueflux_core/cli/`

Responsibilities:

- `formatters.py`
  - Convert `Alert` objects into:
    - CLI-friendly text lines,
    - JSON records,
    - simple HTML reports for demo purposes.

- `sinks.py`
  - Decide where formatted alerts go:
    - stdout,
    - files in a shared volume,
    - potential HTTP webhook.

- `cli/main.py`
  - Implements the `blueflux` command with subcommands like:
    - `blueflux monitor`: tail live telemetry (Docker demo).
    - `blueflux replay`: process a static log file.
    - `blueflux report`: summarize recent alerts.

---

## 4. Deployment Architecture (Docker)

The demo stack is managed via `infra/docker-compose.yml`.

### 4.1 Services

- `attacker_app`
  - Runs the AI-malware / PromptFlux simulation.
  - Container connects to `llm_proxy`.

- `llm_proxy`
  - Exposes a local Grok-compatible API.
  - Forwards requests to Grok.
  - Writes telemetry logs to `/data/llm_logs` (shared volume).

- `net_capture`
  - Attached to the same Docker network as `attacker_app`.
  - Captures or summarizes traffic.
  - Writes flow summaries to `/data/net_logs` (shared volume).

- `blueflux_agent`
  - Reads `/data/llm_logs` and `/data/net_logs`.
  - Runs the BlueFlux agent core.
  - Writes alerts and HTML reports to `/data/blueflux_out`.

### 4.2 Volumes and Networks

- Shared volumes:
  - `llm_logs_volume` → used by `llm_proxy` and `blueflux_agent`.
  - `net_logs_volume` → used by `net_capture` and `blueflux_agent`.
  - `blueflux_out_volume` → used by `blueflux_agent` and optionally by a viewer.

- Networks:
  - `demo_net`:
    - connects `attacker_app`, `llm_proxy`, `net_capture`, and `blueflux_agent`.
    - bounded to the demo only, isolated from the host.

---

## 5. Data Models

Core data models live in `blueflux_core/models/` and act as contracts between layers.

- `TelemetryEvent`
  - Represents a single LLM API call (prompt, response metadata, client info).
- `NetworkEvent`
  - Represents a summarized network flow (5-tuple, counts, timing).
- `Session`
  - Groups related telemetry and network events for a single client/activity.
- `AnalyzerResult`
  - Output of a single analyzer, with score and explanation.
- `RiskAssessment`
  - Aggregated view for a session, combining analyzer results.
- `Alert`
  - Final object emitted by the agent; used for reporting and demos.

---

## 6. Extensibility

- New **analyzers** can be added by:
  - Implementing the interface in `analyzers/base.py`.
  - Registering them in configuration.
- New **telemetry sources** (e.g., additional LLM providers) can be added by:
  - Writing new readers under `telemetry/`.
  - Mapping them into existing models.
- Risk policies can be tuned by editing:
  - `config/default.yaml`
  - `agent/policies.py`

The goal is that additional detectors or telemetry sources can be added without changing the overall architecture.

---
