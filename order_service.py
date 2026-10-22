import os
import re
import sqlite3
import subprocess
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)
DB_PATH = os.getenv("ORDERS_DB_PATH", "orders.db")
INVOICE_DIR = "/var/data/invoices"


@app.route("/api/orders")
def list_orders():
    customer = request.args.get("customer", "")
    sort_by = request.args.get("sort", "created_at")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT id, customer, item, amount FROM orders WHERE customer = '{customer}' ORDER BY {sort_by}"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"orders": rows})


@app.route("/api/warehouse/diagnostics")
def warehouse_diagnostics():
    target_host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output(
        f"ping -c 1 {target_host}",
        shell=True,
        text=True,
    )
    return jsonify({"host": target_host, "result": result})


@app.route("/api/invoices/download")
def download_invoice():
    filename = request.args.get("file", "sample.pdf")
    full_path = os.path.join(INVOICE_DIR, filename)
    return send_file(full_path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
