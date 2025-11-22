"""
Reads network-related artifacts from net_capture:
- PCAP-derived summaries
- or pre-baked JSON flow logs

Converts them into network event models.
Does not do heavy analysis; that belongs in analyzers/network_behavior.py.
"""

