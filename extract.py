import os
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ICMP, ARP

def extract_features(pcap_path, target_ips=None):
    if not os.path.exists(pcap_path):
        print(f"[EXTRACT] File not found: {pcap_path}")
        return _empty()

    try:
        all_packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[EXTRACT] rdpcap failed: {e}")
        return _empty()

    if not all_packets:
        return _empty()

    if target_ips:
        filtered = [p for p in all_packets if IP in p and
                    (p[IP].src in target_ips or p[IP].dst in target_ips)]
        if len(filtered) < 5:
            filtered = list(all_packets)
    else:
        filtered = list(all_packets)

    print(f"[EXTRACT] Processing {len(filtered)} packets")

    total_packets = len(filtered)
    packet_sizes  = [len(p) for p in filtered]
    total_bytes   = sum(packet_sizes)
    mean_pkt      = round(total_bytes / total_packets, 2) if total_packets else 0
    min_pkt       = min(packet_sizes) if packet_sizes else 0
    max_pkt       = max(packet_sizes) if packet_sizes else 0

    proto_counts = {"TCP":0,"UDP":0,"DNS":0,"HTTPS":0,"ICMP":0,"ARP":0,"Other":0}
    unique_ips   = set()
    dns_queries  = []

    for pkt in filtered:
        if ARP in pkt:
            proto_counts["ARP"] += 1
        elif IP in pkt:
            dst = pkt[IP].dst
            if not dst.startswith("127."):
                unique_ips.add(dst)
            if ICMP in pkt:
                proto_counts["ICMP"] += 1
            elif DNS in pkt:
                proto_counts["DNS"] += 1
                if pkt.haslayer(DNSQR):
                    try:
                        name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                        if name:
                            dns_queries.append(name)
                    except:
                        pass
            elif TCP in pkt:
                d, s = pkt[TCP].dport, pkt[TCP].sport
                if d in (443,8443) or s in (443,8443):
                    proto_counts["HTTPS"] += 1
                else:
                    proto_counts["TCP"] += 1
            elif UDP in pkt:
                proto_counts["UDP"] += 1
            else:
                proto_counts["Other"] += 1
        else:
            proto_counts["Other"] += 1

    protocol_distribution = {
        k: round((v/total_packets)*100, 1)
        for k, v in proto_counts.items() if v > 0
    }

    timestamps = sorted(float(p.time) for p in filtered)
    inter_arrival_times = [
        round(timestamps[i]-timestamps[i-1], 6)
        for i in range(1, len(timestamps))
    ]

    timeline = []
    if timestamps:
        t0 = timestamps[0]
        buckets = {}
        for pkt in filtered:
            sec = int(float(pkt.time) - t0)
            buckets[sec] = buckets.get(sec, 0) + len(pkt)
        if buckets:
            timeline = [{"second": s, "bytes": buckets.get(s,0)}
                        for s in range(max(buckets.keys())+1)]

    size_histogram = {"0-100":0,"101-500":0,"501-1000":0,"1001-1500":0,"1500+":0}
    for sz in packet_sizes:
        if sz <= 100:       size_histogram["0-100"] += 1
        elif sz <= 500:     size_histogram["101-500"] += 1
        elif sz <= 1000:    size_histogram["501-1000"] += 1
        elif sz <= 1500:    size_histogram["1001-1500"] += 1
        else:               size_histogram["1500+"] += 1

    return {
        "total_packets":         total_packets,
        "total_bytes":           total_bytes,
        "packet_sizes":          packet_sizes,
        "mean_packet_size":      mean_pkt,
        "min_packet_size":       min_pkt,
        "max_packet_size":       max_pkt,
        "unique_ips":            list(unique_ips),
        "dns_queries":           list(set(dns_queries)),
        "protocol_distribution": protocol_distribution,
        "inter_arrival_times":   inter_arrival_times,
        "timeline":              timeline,
        "size_histogram":        size_histogram,
    }

def _empty():
    return {
        "total_packets":0,"total_bytes":0,"packet_sizes":[],
        "mean_packet_size":0,"min_packet_size":0,"max_packet_size":0,
        "unique_ips":[],"dns_queries":[],"protocol_distribution":{},
        "inter_arrival_times":[],"timeline":[],
        "size_histogram":{"0-100":0,"101-500":0,"501-1000":0,"1001-1500":0,"1500+":0}
    }