# BlueFlux Threat Model

## 1. Objective

BlueFlux’s primary security objective is to **detect LLM-assisted polymorphic malware** that relies on repeated LLM calls to mutate and execute code, particularly PromptFlux-style attacks.

The threat model focuses on:

- How attackers might use LLMs to generate and evolve malware.
- How BlueFlux observes and reasons about that behavior.
- How the BlueFlux system itself might be attacked or evaded.

---

## 2. Assets

### 2.1 Primary Assets

- **LLM Telemetry**
  - Logs of prompts, responses, and metadata from the LLM proxy.
  - These logs are critical for detecting malicious intent and usage patterns.

- **Network Telemetry**
  - Network flow summaries or PCAP-derived logs.
  - Used to correlate LLM usage with suspicious network behavior.

- **Detection Logic**
  - Analyzer rules and policies that define what is “suspicious.”
  - Includes prompt intent rules and pattern detection logic.

- **Alerts and Reports**
  - Output produced by BlueFlux that signals suspicious activity.
  - Used for decision-making during demo and potential future integration.

### 2.2 Supporting Assets

- **Configuration**
  - Thresholds, enabled analyzers, API keys, and environment settings.
- **Docker Infrastructure**
  - Containers, networks, and volumes that define the demo environment.
- **LLM API Credentials**
  - Grok (or other LLM) API keys used by both attacker and defender components.

---

## 3. Actors

### 3.1 Adversaries

- **Malware Operator (Red Team / Attacker)**
  - Controls the attacker container.
  - Uses or modifies AI-malware to:
    - repeatedly query an LLM to generate or mutate malware.
    - attempt to evade detection.

- **BlueFlux Evasion Adversary**
  - More advanced adversary trying to:
    - bypass or mislead BlueFlux detection logic,
    - poison telemetry and/or classification (e.g., prompt obfuscation, misleading context).

### 3.2 Other Roles

- **Defender / Analyst**
  - Operates BlueFlux.
  - Interprets alerts and reports (primarily during the hackathon demo).

- **Infrastructure Operator**
  - Manages the Docker environment and secrets.
  - Ensures containers are isolated and resources are properly configured.

---

## 4. Trust Boundaries and Assumptions

### 4.1 Trust Boundaries

- **Between Attacker App and LLM Proxy**
  - The attacker can send any prompt through the proxy.
  - Proxy is trusted to log inputs and outputs faithfully.

- **Between Telemetry Sources and BlueFlux Agent**
  - BlueFlux trusts telemetry files mounted via shared volumes.
  - There is a risk of attacker tampering if volumes are not properly isolated.

- **Between BlueFlux and External Services**
  - LLM (Grok) and optional external services (e.g., VirusTotal).
  - Responses are trusted for detection, but untrusted for security decisions beyond classification.

### 4.2 Core Assumptions

- Attacker activity is confined to the **attacker container** and Docker network.
- The **LLM proxy** is not directly controlled by the attacker and logs all requests.
- Docker configuration for the demo provides:
  - container isolation,
  - restricted host access,
  - controlled networking.
- BlueFlux has **read-only** access to telemetry volumes; the attacker does not have easy write access to BlueFlux output.

---

## 5. Threat Scenarios

### 5.1 PromptFlux-Style Polymorphic Malware (Primary Use Case)

**Description**

- The attacker app repeatedly asks the LLM to:
  - generate a malicious script or loader,
  - modify existing code to evade detection,
  - obfuscate or encrypt payloads.
- Generated code is executed inside the attacker container.
- The malware communicates with some simulated C2 or exfiltration endpoint.

**Potential BlueFlux Observables**

- Prompts containing:
  - explicit malicious intent,
  - evasion language,
  - cover stories (“educational”, “cybersecurity student”).
- High-frequency sequences of mutate/execute requests.
- Network flows exhibiting:
  - periodic beacons,
  - connections to unusual endpoints after suspicious prompts.

**Goal**

- BlueFlux should raise an alert with reasoning that connects:
  - suspicious prompts,
  - repeated usage patterns,
  - correlated network behavior.

---

### 5.2 Detection Evasion via Prompt Engineering

**Description**

- The attacker intentionally:
  - hides malicious intent in indirect or obfuscated language,
  - uses code words or multi-step chains (e.g., encode instructions),
  - mimics benign use-cases to bypass static keyword-based rules.

**Potential BlueFlux Observables**

- Complex, indirect prompts that still result in code-generation patterns.
- Repeated code refinement and obfuscation behavior even when language seems benign.
- Network behavior incompatible with a legitimate “student experiment.”

**Mitigation Strategy**

- Use LLM-based classification on top of simple rules.
- Incorporate usage pattern analysis (not just single prompts).
- Treat unusual combinations of benign-looking text and clearly malicious network behavior as suspicious.

---

### 5.3 Telemetry Tampering

**Description**

- The attacker attempts to:
  - disable or bypass the LLM proxy,
  - inject fake or misleading telemetry into logs,
  - delete or overwrite logs before BlueFlux processes them.

**Potential BlueFlux Observables**

- Sudden gaps or inconsistencies in telemetry.
- Unexpected absence of logs while network activity continues.
- Misalignment between observed network flows and LLM logs.

**Mitigation Strategy (Demo Scope)**

- Keep the LLM proxy and telemetry volumes isolated from the attacker container.
- Treat missing or inconsistent telemetry as **suspicious**, even if not fully handled in code.
- In documentation, highlight that production deployment would require stronger hardening (e.g., secure logging pipeline, append-only storage).

---

### 5.4 Poisoning the Detection Logic

**Description**

- The attacker attempts to manipulate detection logic by:
  - crafting prompts that bias the classifier (e.g., repeated “harmless” context),
  - forcing volume of benign-looking telemetry to hide a malicious subset.

**Potential BlueFlux Observables**

- High volume of repetitive, near-duplicate benign prompts with scattered malicious ones.
- Unusual ratio of “explanation/cover story” prompts to actual code generation.

**Mitigation Strategy**

- Focus detection on **behavioral patterns** over time, not just isolated classification.
- Make risk policies resilient to noise (e.g., thresholds based on proportions, not absolute counts).

---

### 5.5 Attacks on the Docker Environment

**Description**

- Misconfigured Docker could allow:
  - breakouts from attacker container to host,
  - lateral movement to the BlueFlux container,
  - modification of telemetry or configuration.

**Mitigation Strategy (Demo Scope)**

- Use:
  - separate network for demo (`demo_net`),
  - no host mounts from the attacker container except as strictly required,
  - read-only mounts for telemetry in BlueFlux where possible.
- Explicitly document these assumptions in the infra README.

---

## 6. Out-of-Scope Threats (Hackathon Version)

The following are acknowledged but out of scope for this iteration:

- Preventing or mitigating **true host-level compromise** outside Docker.
- Nation-state-level evasion techniques or extremely subtle covert channels.
- Attacks on the downstream user/analyst interpreting BlueFlux output (e.g., HTML injection in reports).
- Detailed binary-level malware analysis or disassembly.

---

## 7. Mitigations Summary

High-level mitigations per threat type:

- **PromptFlux-style Malware**
  - Telemetry capture via LLM proxy.
  - Prompt intent and pattern analyzers.
  - Network behavior analyzer and correlation.

- **Evasion via Prompt Engineering**
  - Combination of rules and Grok-based intent classification.
  - Focus on repeated usage patterns and post-prompt behavior.

- **Telemetry Tampering**
  - Architectural separation between attacker containers and proxy/storage.
  - Treat missing or inconsistent telemetry as suspicious.

- **Detection Logic Poisoning**
  - Session-based pattern analysis and risk scoring, not just one-shot classification.
  - Thresholds and ratios that are harder to game with noise.

- **Docker / Infra Attacks**
  - Isolated Docker networks.
  - Controlled volume mounts.
  - Acknowledgment of limitations and documentation of assumptions.

---

## 8. Residual Risk

Even with BlueFlux in place, an advanced attacker may:

- Find prompt strategies that both:
  - evade classification, and
  - produce malware-like behavior with network traffic that appears benign.
- Exploit weaknesses in the simulated environment that do not exist in production.
- Use LLMs offline or through channels not monitored by the proxy.

BlueFlux’s role in this hackathon is to demonstrate:

- That LLM-aware telemetry and network correlation meaningfully improve visibility into PromptFlux-style attacks.
- That a modular architecture can be extended with more sophisticated detectors and defenses over time.

---
