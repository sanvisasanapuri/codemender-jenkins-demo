import urllib.request
import urllib.parse
import socket
import ipaddress
import http.client
import ssl

def fetch_partner_webhook(webhook_url: str) -> str:
    parsed = urllib.parse.urlparse(webhook_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid URL scheme")
        
    try:
        if not parsed.hostname:
            raise ValueError("Invalid URL hostname")
            
        try:
            ip_obj = ipaddress.ip_address(parsed.hostname.strip("[]"))
            ip = str(ip_obj)
        except ValueError:
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)
            
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
            raise ValueError("Private/loopback IPs are not allowed")
    except Exception as e:
        raise ValueError(f"Invalid URL: {e}")

    class SafeHTTPConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)

    class SafeHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            self.sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)
            if self._tunnel_host:
                self.setup_tunnel()
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

    class SafeHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(SafeHTTPConnection, req)

    class SafeHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(SafeHTTPSConnection, req, context=self._context, check_hostname=self._check_hostname)

    req = urllib.request.Request(
        webhook_url,
        headers={"User-Agent": "PartnerWebhookClient/1.0"}
    )
    
    opener = urllib.request.build_opener(SafeHTTPHandler(), SafeHTTPSHandler())
    with opener.open(req, timeout=5) as response:
        return response.read().decode("utf-8")

print("HTTP:")
print(fetch_partner_webhook("http://example.com")[:50])
print("HTTPS:")
print(fetch_partner_webhook("https://example.com")[:50])
