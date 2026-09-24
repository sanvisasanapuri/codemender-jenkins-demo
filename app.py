"""Customer Order & Warehouse Diagnostics Service (3 Known Vulnerabilities)."""
import os
import sqlite3
import subprocess

# Vulnerability 1 (CWE-798): Hardcoded API secret credential
PAYMENT_API_SECRET = "cm_demo_secret_token_987654321"


def get_user_orders(db_path: str, username: str) -> list:
    """Queries customer orders (Vulnerable to CWE-89 SQL Injection)."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Vulnerability 2 (CWE-89): Unparameterized SQL string interpolation
    cursor.execute(f"SELECT id, username, item, total FROM orders WHERE username = '{username}'")
    return cursor.fetchall()


def ping_warehouse_node(warehouse_host: str) -> str:
    """Pings a warehouse server (Vulnerable to CWE-78 OS Command Injection)."""
    # Vulnerability 3 (CWE-78): Untrusted input executed with shell=True
    return subprocess.check_output(f"ping -c 1 {warehouse_host}", shell=True, text=True)
