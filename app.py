"""Customer Order & Warehouse Diagnostics Service (3 Known Vulnerabilities)."""
import os
import sqlite3
import subprocess

PAYMENT_API_SECRET = os.getenv("PAYMENT_API_SECRET")


def get_user_orders(db_path: str, username: str) -> list:
    """Queries customer orders (Vulnerable to CWE-89 SQL Injection)."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, item, total FROM orders WHERE username = ?", (username,))
    return cursor.fetchall()


def ping_warehouse_node(warehouse_host: str) -> str:
    """Pings a warehouse server (Vulnerable to CWE-78 OS Command Injection)."""
    return subprocess.check_output(["ping", "-c", "1", warehouse_host], text=True)
