"""Triage a pcap for a forensics/blue-team challenge: list conversations,
reassemble TCP streams enough to pull out HTTP requests/responses and
cleartext credentials, dump DNS queries, and flag-regex scan everything.

Requires scapy (pip install scapy).

Usage:
    python -m ctf_toolkit.blue.pcap_triage capture.pcap
    python -m ctf_toolkit.blue.pcap_triage capture.pcap --streams   # print reassembled TCP streams
"""
from __future__ import annotations

import argparse
import re
from collections import defaultdict

from ctf_toolkit.common.flagscan import DEFAULT_PATTERN


def load_scapy():
    try:
        from scapy.all import rdpcap, TCP, UDP, IP, DNS, DNSQR, Raw  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "scapy is required: pip install scapy "
            "(Linux also needs libpcap; Windows needs Npcap)"
        ) from exc
    return rdpcap, TCP, UDP, IP, DNS, DNSQR, Raw


def summarize_conversations(packets, IP, TCP, UDP) -> None:
    convos = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "other"
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        key = (proto, pkt[IP].src, sport, pkt[IP].dst, dport)
        convos[key]["packets"] += 1
        convos[key]["bytes"] += len(pkt)

    print(f"{len(convos)} conversation(s):")
    for (proto, src, sport, dst, dport), stats in sorted(
        convos.items(), key=lambda kv: -kv[1]["bytes"]
    ):
        print(f"  {proto:4s} {src}:{sport} -> {dst}:{dport}  {stats['packets']} pkts, {stats['bytes']} bytes")


def reassemble_tcp_streams(packets, IP, TCP, Raw) -> dict[tuple, bytes]:
    streams: dict[tuple, list[tuple[int, bytes]]] = defaultdict(list)
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        streams[key].append((pkt[TCP].seq, bytes(pkt[Raw].load)))

    out = {}
    for key, chunks in streams.items():
        chunks.sort(key=lambda c: c[0])
        out[key] = b"".join(c[1] for c in chunks)
    return out


def find_http_credentials(text: str) -> list[str]:
    hits = []
    for m in re.finditer(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text):
        import base64

        try:
            hits.append(base64.b64decode(m.group(1)).decode("utf-8", errors="replace"))
        except Exception:
            pass
    for m in re.finditer(r"(?:USER|PASS)\s+(\S+)", text):  # FTP
        hits.append(f"FTP credential part: {m.group(0)}")
    for m in re.finditer(r"(?i)(username|password|passwd|user|pass)=([^&\s]+)", text):
        hits.append(f"{m.group(1)}={m.group(2)}")
    return hits


def dump_dns(packets, DNS, DNSQR) -> None:
    queries = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                queries.append(pkt[DNSQR].qname.decode())
            except Exception:
                pass
    if queries:
        print(f"\n{len(queries)} DNS quer(y/ies), unique hostnames:")
        for host in sorted(set(queries)):
            print(f"  {host}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN, help="flag regex")
    ap.add_argument("--streams", action="store_true", help="print full reassembled TCP streams")
    args = ap.parse_args()

    rdpcap, TCP, UDP, IP, DNS, DNSQR, Raw = load_scapy()
    packets = rdpcap(args.pcap)
    pattern = re.compile(args.pattern)

    summarize_conversations(packets, IP, TCP, UDP)
    dump_dns(packets, DNS, DNSQR)

    streams = reassemble_tcp_streams(packets, IP, TCP, Raw)
    print(f"\n{len(streams)} TCP stream(s) with payload:")
    for (src, sport, dst, dport), data in streams.items():
        text = data.decode("utf-8", errors="replace")
        flags = pattern.findall(text)
        creds = find_http_credentials(text)
        print(f"  {src}:{sport} -> {dst}:{dport}  ({len(data)} bytes)")
        if flags:
            print(f"    FLAG MATCH: {flags}")
        if creds:
            print(f"    possible credentials: {creds}")
        if args.streams:
            print("    --- stream ---")
            print("\n".join("    " + line for line in text.splitlines()[:200]))


if __name__ == "__main__":
    main()
