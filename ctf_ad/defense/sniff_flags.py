"""Passive traffic monitor: alert when a flag-shaped string crosses the wire
on one of your service ports, so you know who's exploiting what before the
scoreboard tells you (it won't).

This is detection only — it never blocks anything. Run it on the vulnbox
itself (or a span/mirror port) while you're triaging which service to patch
first: whichever port lights up most is your priority.

Requires scapy + libpcap/Npcap and (on Linux) root or CAP_NET_RAW.

Usage:
    sudo python -m ctf_ad.defense.sniff_flags --config ctf_ad/config.yaml
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_ad.common.flags import compile_flag_regex, extract_flags

log = logging.getLogger("ctf_ad.defense.sniff")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="ctf_ad/config.yaml")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    dcfg = cfg["defense"]
    scfg = dcfg["sniff"]

    logging.basicConfig(
        level=getattr(logging, dcfg["logging"].get("level", "INFO")),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(dcfg["logging"]["path"]),
            logging.StreamHandler(),
        ],
    )

    try:
        from scapy.all import sniff, TCP, IP, Raw  # type: ignore
    except ImportError:
        log.error(
            "scapy is required for sniffing: pip install scapy "
            "(Linux also needs libpcap; Windows needs Npcap)"
        )
        return

    flag_regex = compile_flag_regex(cfg["flag_regex"])
    ports = set(scfg.get("ports", []))

    def handle(pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if ports and sport not in ports and dport not in ports:
            return
        try:
            payload = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
        except Exception:
            return
        for flag in extract_flags(payload, flag_regex):
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            log.warning(
                "FLAG SEEN ON WIRE %s:%d -> %s:%d : %s", src, sport, dst, dport, flag
            )

    log.info("sniffing on %s, ports=%s (ctrl-c to stop)", scfg.get("interface") or "default", ports)
    sniff(iface=scfg.get("interface"), prn=handle, store=False)


if __name__ == "__main__":
    main()
