"""
Consumes sessions with both LLM usage and network summaries.
Applies heuristics such as:
- new or rare domains contacted shortly after suspicious LLM usage
- periodic egress to fixed endpoints (beacon-like)
- unusual ports or protocols

Emits a risk contribution based on how strange the traffic is.
"""

