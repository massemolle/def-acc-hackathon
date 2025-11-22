"""
Associates LLM events and network events into sessions:
- simple rules: same container/host, similar timestamps, same app identifier, etc.

Provides a clean interface: "give me sessions that combine prompt sequences and network behavior."
Keeps correlation logic in one place for transparency.
"""

