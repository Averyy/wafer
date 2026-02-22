"""Local HTTP server for PX mock testing.

Serves files from tests/ directory and provides delayed responses
for fake resources to simulate real network loading.

Used by test_px_captcha_local.py (started automatically via start_server()).
"""

import http.server
import os
import random
import threading
import time


class DelayHandler(http.server.SimpleHTTPRequestHandler):
    """Serves files from tests/ dir. Fake resources get random delays."""

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            directory=os.path.dirname(__file__),
            **kwargs,
        )

    def do_GET(self):
        if "fake-resource" in self.path:
            # Random delay 1-5s to simulate slow iframe resources
            delay = random.uniform(1.0, 5.0)
            time.sleep(delay)
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"/* fake */")
            return
        super().do_GET()

    def log_message(self, format, *args):
        # Quiet unless it's a fake resource
        if "fake-resource" in str(args):
            print(f"  [server] {args[0]} {args[1]}")


def start_server(port=8765):
    """Start the mock server in a daemon thread. Returns the URL."""
    server = http.server.HTTPServer(("127.0.0.1", port), DelayHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}"


if __name__ == "__main__":
    url = start_server()
    print(f"Serving at {url}/px_captcha_local.html")
    print("Press Ctrl+C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
