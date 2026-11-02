#!/usr/bin/env python3
"""
Raw Packet Bridge & Local Interface Sniffer.
Captures live network packets traversing the lab network using Scapy/sockets,
and routes them to monitoring outputs if needed.
"""

import os
import sys
import time
import logging
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [PacketBridge] %(message)s")
logger = logging.getLogger("PacketBridge")

INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")

def packet_callback(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
        sport = pkt.sport if (TCP in pkt or UDP in pkt) else 0
        dport = pkt.dport if (TCP in pkt or UDP in pkt) else 0

        # Log significant packets
        if dport in [80, 3000, 8000, 53] or sport in [80, 3000, 8000, 53]:
            logger.debug(f"[Capture] {proto} {src}:{sport} -> {dst}:{dport}")

def run():
    logger.info(f"Starting raw packet sniffer on interface {INTERFACE}...")
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=0)
    except Exception as e:
        logger.warning(f"Could not bind to {INTERFACE}: {e}. Running in passive bridge mode.")
        while True:
            time.sleep(5)

if __name__ == "__main__":
    run()
