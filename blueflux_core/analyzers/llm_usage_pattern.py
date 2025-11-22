"""
Observes sequences of events per session:
- counts how often the user asks to modify or mutate previous code
- checks for loops like:
    generate code → run → error or "not working" → mutate/obfuscate again

Focuses on pattern detection only, not code-level details.
Maintains in-memory state for a sliding window (e.g., last N minutes or last N events per session).
"""

