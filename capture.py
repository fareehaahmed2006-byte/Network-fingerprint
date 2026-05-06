import threading
import time
import warnings
import requests as http_requests
from scapy.all import sniff, wrpcap

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def _make_http_request(url, delay=1.5):
    time.sleep(delay)
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
            "Connection": "keep-alive",
        }
        resp = http_requests.get(url, timeout=15, headers=headers, verify=False)
        print(f"[CAPTURE] Request done — status {resp.status_code}")
    except Exception as e:
        print(f"[CAPTURE] Request warning (non-fatal): {e}")

def capture_traffic(url, pcap_path, duration=10):
    print(f"[CAPTURE] Starting {duration}s capture for: {url}")
    request_thread = threading.Thread(target=_make_http_request, args=(url,), daemon=True)
    request_thread.start()
    try:
        packets = sniff(timeout=duration, store=True)
    except Exception as e:
        print(f"[CAPTURE] Sniff error: {e}")
        packets = []
    request_thread.join(timeout=5)
    if packets:
        wrpcap(pcap_path, packets)
        print(f"[CAPTURE] Saved {len(packets)} packets to {pcap_path}")
    else:
        print("[CAPTURE] No packets captured. Run as Administrator and check Npcap.")
    return pcap_path