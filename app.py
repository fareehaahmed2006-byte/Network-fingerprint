import os
import socket
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
from capture import capture_traffic
from extract import extract_features
from fingerprint import generate_fingerprint

app = Flask(__name__, static_folder="static")
PCAP_DIR = "pcap_files"
os.makedirs(PCAP_DIR, exist_ok=True)

def resolve_url_to_ips(url):
    try:
        hostname = urlparse(url).hostname
        results = socket.getaddrinfo(hostname, None)
        ips = list(set(r[4][0] for r in results))
        print(f"[DNS] {hostname} → {ips}")
        return ips
    except Exception as e:
        print(f"[DNS] Failed: {e}")
        return []

def run_pipeline(url, pcap_path):
    target_ips = resolve_url_to_ips(url)
    capture_traffic(url, pcap_path, duration=10)
    features = extract_features(pcap_path, target_ips)
    fingerprint = generate_fingerprint(url, features)
    return fingerprint

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"error": "Invalid URL. Must start with http:// or https://"}), 400
    pcap_path = os.path.join(PCAP_DIR, "capture_single.pcap")
    try:
        result = run_pipeline(url, pcap_path)
        return jsonify(result)
    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

@app.route("/api/compare", methods=["POST"])
def compare():
    data = request.get_json(force=True)
    url1 = (data.get("url1") or "").strip()
    url2 = (data.get("url2") or "").strip()
    for url in [url1, url2]:
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            return jsonify({"error": f"Invalid URL: {url}"}), 400
    pcap1 = os.path.join(PCAP_DIR, "capture_site1.pcap")
    pcap2 = os.path.join(PCAP_DIR, "capture_site2.pcap")
    try:
        fp1 = run_pipeline(url1, pcap1)
        fp2 = run_pipeline(url2, pcap2)
        diff = {
            "more_bytes":         url1 if fp1["total_bytes"]      >= fp2["total_bytes"]      else url2,
            "more_unique_ips":    url1 if fp1["unique_ip_count"]  >= fp2["unique_ip_count"]  else url2,
            "higher_mean_packet": url1 if fp1["mean_packet_size"] >= fp2["mean_packet_size"] else url2,
            "bytes_diff":         abs(fp1["total_bytes"]      - fp2["total_bytes"]),
            "ips_diff":           abs(fp1["unique_ip_count"]  - fp2["unique_ip_count"]),
            "mean_size_diff":     round(abs(fp1["mean_packet_size"] - fp2["mean_packet_size"]), 2),
        }
        return jsonify({"fingerprint1": fp1, "fingerprint2": fp2, "diff": diff})
    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({"error": f"Comparison failed: {str(e)}"}), 500

if __name__ == "__main__":
    print("="*50)
    print("  NetPrint running at http://127.0.0.1:5000")
    print("  Run as Administrator for Scapy to work!")
    print("="*50)
    app.run(debug=True, port=5000)