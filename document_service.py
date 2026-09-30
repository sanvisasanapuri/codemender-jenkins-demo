import os
import pickle
import urllib.request
import urllib.parse
import socket
import ipaddress


def read_user_document(storage_dir: str, filename: str) -> str:
    """Reads a user document from the storage directory."""
    file_path = os.path.join(storage_dir, filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def fetch_partner_webhook(webhook_url: str) -> str:
    """Sends a notification request to a partner webhook endpoint."""
    parsed = urllib.parse.urlparse(webhook_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid URL scheme")
        
    try:
        if not parsed.hostname:
            raise ValueError("Invalid URL hostname")
            
        try:
            ip_obj = ipaddress.ip_address(parsed.hostname.strip("[]"))
        except ValueError:
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)
            
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
            raise ValueError("Private/loopback IPs are not allowed")
    except Exception as e:
        raise ValueError(f"Invalid URL: {e}")

    req = urllib.request.Request(
        webhook_url,
        headers={"User-Agent": "PartnerWebhookClient/1.0"}
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.read().decode("utf-8")


def load_user_session_token(token_bytes: bytes) -> dict:
    """Restores the user session object from raw token bytes."""
    return pickle.loads(token_bytes)
