"""
Defines core data structures representing:
- LLM API events (prompt, completion, metadata)
- network events or summaries (per flow/session)
- combined "session" objects used by analyzers

These models are the contract between telemetry ingestion and analyzers.
Keep them stable; changing them affects the entire system.
"""

