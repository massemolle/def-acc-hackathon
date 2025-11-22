"""
Looks at individual prompts (and possibly completions) and flags:
- explicit malicious goals (e.g., "create a polymorphic virus")
- indirect/cover story phrasing ("for educational purposes", "cybersecurity student", etc.)
- obfuscation/bypass language (e.g., "make it undetectable", "bypass antivirus")

Uses first a cheap local ruleset, then optional escalation to Grok:
  "Given this prompt, how likely is it that the user is trying to create or modify malware?"

Exposes parameters (thresholds, keywords) via config.
"""

