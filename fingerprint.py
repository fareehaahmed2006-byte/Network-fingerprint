import datetime
from classify import classify_behavior

def generate_fingerprint(url, features):
    proto_dist   = features.get("protocol_distribution", {})
    top_protocol = max(proto_dist, key=proto_dist.get) if proto_dist else "Unknown"
    behavior_label, confidence = classify_behavior(features)

    return {
        "site_url":              url,
        "capture_timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
        "total_packets":         features["total_packets"],
        "total_bytes":           features["total_bytes"],
        "top_protocol":          top_protocol,
        "protocol_distribution": proto_dist,
        "unique_ips":            features["unique_ips"],
        "unique_ip_count":       len(features["unique_ips"]),
        "dns_queries":           features["dns_queries"],
        "mean_packet_size":      features["mean_packet_size"],
        "min_packet_size":       features["min_packet_size"],
        "max_packet_size":       features["max_packet_size"],
        "timeline":              features.get("timeline", []),
        "size_histogram":        features.get("size_histogram", {}),
        "behavior_label":        behavior_label,
        "confidence":            confidence,
    }