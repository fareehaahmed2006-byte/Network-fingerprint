def classify_behavior(features):
    total_bytes     = features.get("total_bytes", 0)
    total_packets   = features.get("total_packets", 0)
    mean_size       = features.get("mean_packet_size", 0)
    unique_ip_count = len(features.get("unique_ips", []))
    dns_count       = len(features.get("dns_queries", []))
    proto           = features.get("protocol_distribution", {})
    inter_arrival   = features.get("inter_arrival_times", [])

    https_pct = proto.get("HTTPS", 0)
    tcp_pct   = proto.get("TCP",   0)
    udp_pct   = proto.get("UDP",   0)

    scores = {"Streaming": 0, "Social Media": 0, "Static Content": 0, "API-Heavy": 0}

    # Streaming rules
    if total_bytes > 1_000_000:   scores["Streaming"] += 40
    elif total_bytes > 300_000:   scores["Streaming"] += 25
    elif total_bytes > 100_000:   scores["Streaming"] += 10
    if mean_size > 1000:          scores["Streaming"] += 30
    elif mean_size > 700:         scores["Streaming"] += 15
    if tcp_pct + https_pct > 80:  scores["Streaming"] += 20
    elif tcp_pct + https_pct > 60:scores["Streaming"] += 10
    if udp_pct > 40:              scores["Streaming"] += 15

    # Social Media rules
    if unique_ip_count > 20:      scores["Social Media"] += 40
    elif unique_ip_count > 10:    scores["Social Media"] += 25
    elif unique_ip_count > 5:     scores["Social Media"] += 10
    if mean_size < 300:           scores["Social Media"] += 25
    elif mean_size < 500:         scores["Social Media"] += 10
    active = sum(1 for v in proto.values() if v > 3)
    if active >= 4:               scores["Social Media"] += 20
    elif active >= 3:             scores["Social Media"] += 10
    if dns_count > 15:            scores["Social Media"] += 15
    elif dns_count > 8:           scores["Social Media"] += 8

    # Static Content rules
    if total_packets < 80:        scores["Static Content"] += 40
    elif total_packets < 200:     scores["Static Content"] += 20
    if dns_count <= 2:            scores["Static Content"] += 30
    elif dns_count <= 5:          scores["Static Content"] += 15
    if unique_ip_count <= 3:      scores["Static Content"] += 20
    elif unique_ip_count <= 6:    scores["Static Content"] += 10
    if total_bytes < 30_000:      scores["Static Content"] += 15

    # API-Heavy rules
    if https_pct > 80:            scores["API-Heavy"] += 35
    elif https_pct > 60:          scores["API-Heavy"] += 20
    if mean_size < 200:           scores["API-Heavy"] += 30
    elif mean_size < 350:         scores["API-Heavy"] += 15
    if inter_arrival:
        avg_iat = sum(inter_arrival) / len(inter_arrival)
        if avg_iat < 0.02:        scores["API-Heavy"] += 25
        elif avg_iat < 0.08:      scores["API-Heavy"] += 12
    if total_packets > 300 and total_bytes < 150_000:
                                  scores["API-Heavy"] += 20

    best_label = max(scores, key=scores.get)
    best_score = scores[best_label]

    print(f"[CLASSIFY] Scores: {scores} → {best_label}")

    if best_score < 20:
        return "Unknown", 0

    confidence = max(30, min(95, int(best_score)))
    return best_label, confidence