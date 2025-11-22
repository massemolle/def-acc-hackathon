"""
Wraps tools like tshark or pyshark to:
- transform PCAP into JSON flow statistics
- extract only relevant features (IP, port, count, timing)

Ensures the rest of BlueFlux never has to parse raw PCAP.
"""

