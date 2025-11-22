"""
Manages short-lived state:
- per-session windows
- caches of recent prompts
- previously emitted alerts (to avoid alert storms)

Keeps all "memory" logic in one place.
"""

