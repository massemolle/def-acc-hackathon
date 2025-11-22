"""
Defines the analyzer interface:
- what input they accept (event or session)
- what output they produce (analysis results)

Maintains a registry so the agent can dynamically discover and run analyzers
configured in config/default.yaml.
"""

