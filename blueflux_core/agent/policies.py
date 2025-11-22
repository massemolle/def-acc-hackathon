"""
Encodes how individual analyzer scores are combined into:
- a final numeric risk score
- discrete levels (low/medium/high)

Allows quick experimentation with thresholds without touching analyzer implementations.
At first,
Hardcode the logic. "If > 3 malicious prompts AND > 1 unknown IP connection = ALERT." Don't build a complex weighting engine.
"""

