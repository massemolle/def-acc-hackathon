"""
Main orchestration loop:
- fetches telemetry events
- builds/updates sessions
- runs configured analyzers
- aggregates their outputs
- produces alerts and passes them to reporting

Should be conscious of latency and cost (how often it calls Grok).
"""

