import os
import json
import urllib.request


def read_user_document(storage_dir: str, filename: str) -> str:
    """Reads a user document from the storage directory."""
    file_path = os.path.join(storage_dir, filename)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def fetch_partner_webhook(webhook_url: str) -> str:
    """Sends a notification request to a partner webhook endpoint."""
    req = urllib.request.Request(
        webhook_url,
        headers={"User-Agent": "PartnerWebhookClient/1.0"}
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.read().decode("utf-8")


def load_user_session_token(token_bytes: bytes) -> dict:
    """Restores the user session object from raw token bytes."""
    return json.loads(token_bytes)
