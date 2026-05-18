import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bluejay.http_checks import fetch_web_url
from bluejay.targets import is_allowed_web_url, normalize_web_urls


class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", "https://not-allowed.bluejay.invalid/")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class WebTargetSafetyTests(unittest.TestCase):
    def test_normalize_web_urls_rejects_query_and_control_characters(self) -> None:
        self.assertIsNone(normalize_web_urls("http://127.0.0.1/?debug=true"))
        self.assertIsNone(normalize_web_urls("http://127.0.0.1/\nHost: example.com"))

    def test_redirects_to_non_allowlisted_hosts_are_blocked(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            host, port = server.server_address
            result = fetch_web_url(f"http://{host}:{port}/")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertIsNone(result["status"])
        self.assertIn("Redirect blocked", result["error"])

    def test_redirect_validation_allows_query_on_allowed_hosts(self) -> None:
        self.assertTrue(is_allowed_web_url("http://127.0.0.1/path?next=/home", allow_query=True))
        self.assertFalse(is_allowed_web_url("http://127.0.0.1/path?next=/home"))


if __name__ == "__main__":
    unittest.main()
