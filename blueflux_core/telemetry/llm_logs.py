"""
Responsible for reading telemetry files emitted by llm_proxy.
Converts raw JSONL/structured logs into TelemetryEvent objects.
Handles replay mode (for demos) and tailing mode (for near-real-time).
"""

