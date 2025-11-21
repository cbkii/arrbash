#!/usr/bin/env python3
import http.server
import json
import sys
import threading
import urllib.parse

forward_file = sys.argv[1]
event_log = sys.argv[2]
port = int(sys.argv[3])

state = {
    "listen_port": 0,
    "paused": False,
}


def log_event(message: str) -> None:
    with open(event_log, "a", encoding="utf-8") as handle:
        handle.write(message + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self, status=200, cookies=None, content_type="application/json"):
        self.send_response(status)
        if cookies:
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", content_type)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/v1/openvpn/portforwarded"):
            with open(forward_file, "r", encoding="utf-8") as handle:
                try:
                    port_val = int(handle.read().strip() or 0)
                except ValueError:
                    port_val = 0
            body = json.dumps({"port": port_val}).encode()
            self._set_headers(200)
            self.wfile.write(body)
            log_event("GET portforwarded -> %s" % port_val)
            return
        if self.path.startswith("/api/v2/app/preferences"):
            body = json.dumps({"listen_port": state["listen_port"]}).encode()
            self._set_headers(200)
            self.wfile.write(body)
            log_event("GET preferences")
            return
        if self.path.startswith("/api/v2/app/version"):
            self._set_headers(200, content_type="text/plain")
            self.wfile.write(b"1.0")
            log_event("GET version")
            return
        self._set_headers(404, content_type="text/plain")
        self.wfile.write(b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        log_event(f"POST {self.path} body={body}")

        if self.path.startswith("/api/v2/auth/login"):
            self._set_headers(200, cookies=["SID=dummy; Path=/"])
            self.wfile.write(b"Ok.")
            return

        if not self.headers.get("Cookie"):
            self._set_headers(401)
            self.wfile.write(b"auth required")
            return

        if self.path.startswith("/api/v2/app/setPreferences"):
            payload = urllib.parse.parse_qs(body).get("json", ["{}"])[0]
            try:
                prefs = json.loads(payload)
            except json.JSONDecodeError:
                prefs = {}
            listen_port = int(prefs.get("listen_port", 0)) if isinstance(prefs, dict) else 0
            state["listen_port"] = listen_port
            self._set_headers(200, content_type="text/plain")
            self.wfile.write(b"ok")
            return

        if self.path.startswith("/api/v2/torrents/pause"):
            state["paused"] = True
            self._set_headers(200, content_type="text/plain")
            self.wfile.write(b"paused")
            return

        if self.path.startswith("/api/v2/torrents/resume"):
            state["paused"] = False
            self._set_headers(200, content_type="text/plain")
            self.wfile.write(b"resumed")
            return

        self._set_headers(404, content_type="text/plain")
        self.wfile.write(b"not found")

    def log_message(self, format, *args):
        return


def main():
    server = http.server.ThreadingHTTPServer(("", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
