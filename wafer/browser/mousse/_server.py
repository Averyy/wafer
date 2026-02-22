"""Mousse HTTP server — serves UI and recording API."""

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_STATIC_DIR = Path(__file__).resolve().parent / "_static"
_RECORDINGS_DIR = Path(__file__).resolve().parent.parent / "_recordings"
_CATEGORIES = ("idles", "paths", "holds", "drags", "browses")

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".ico": "image/x-icon",
    ".png": "image/png",
}

# Target counts per the press-and-hold spec
_TARGETS = {"idles": 30, "paths": 26, "holds": 20, "drags": 20, "browses": 20}

_PATH_TARGETS = {
    "to_center_from_ul": 8,
    "to_center_from_ur": 5,
    "to_center_from_l": 4,
    "to_center_from_bl": 3,
    "to_center_from_br": 3,
    "to_lower_from_ul": 3,
}


def _safe_filename(name: str) -> bool:
    """Reject path traversal or weird filenames."""
    return bool(re.fullmatch(r"[a-zA-Z0-9_.\-]+", name))


def _list_recordings(category: str) -> list[str]:
    """List CSV files in a category directory, sorted."""
    d = _RECORDINGS_DIR / category
    if not d.is_dir():
        return []
    return sorted(f.name for f in d.iterdir() if f.suffix == ".csv")


def _next_filename(category: str, prefix: str) -> str:
    """Generate next auto-incremented filename like idle_003.csv."""
    existing = _list_recordings(category)
    max_num = 0
    pat = re.compile(re.escape(prefix) + r"_(\d+)\.csv$")
    for name in existing:
        m = pat.match(name)
        if m:
            max_num = max(max_num, int(m.group(1)))
    return f"{prefix}_{max_num + 1:03d}.csv"


def _parse_csv(filepath: Path) -> dict:
    """Parse a recording CSV into metadata + rows."""
    metadata = {}
    headers = []
    rows = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                # Parse metadata comment
                for part in line.lstrip("# ").split():
                    if "=" in part:
                        k, v = part.split("=", 1)
                        metadata[k] = v
            elif not headers:
                headers = line.split(",")
            else:
                vals = line.split(",")
                if len(vals) == len(headers):
                    rows.append([float(v) for v in vals])
    return {"metadata": metadata, "columns": headers, "rows": rows}


def _path_direction_counts() -> dict[str, int]:
    """Count existing recordings per path direction."""
    counts: dict[str, int] = {}
    for name in _list_recordings("paths"):
        # Extract direction from filename: to_center_from_ul_003.csv → to_center_from_ul
        m = re.match(r"(.+?)_\d+\.csv$", name)
        if m:
            direction = m.group(1)
            counts[direction] = counts.get(direction, 0) + 1
    return counts


class MousseHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        # Quieter logging
        pass

    def _send_json(self, data: dict | list, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, filepath: Path, content_type: str) -> None:
        body = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        self._send_json({"error": message}, status)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]  # strip query string

        if path == "/":
            self._send_file(_STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return

        if path.startswith("/static/"):
            filename = path[len("/static/"):]
            if not _safe_filename(filename):
                self._send_error(400, "Invalid filename")
                return
            filepath = _STATIC_DIR / filename
            if not filepath.is_file():
                self._send_error(404, "Not found")
                return
            ct = _CONTENT_TYPES.get(filepath.suffix, "application/octet-stream")
            self._send_file(filepath, ct)
            return

        if path == "/api/recordings":
            result = {}
            for cat in _CATEGORIES:
                files = _list_recordings(cat)
                result[cat] = {
                    "files": files,
                    "count": len(files),
                    "target": _TARGETS[cat],
                }
            result["path_breakdown"] = {
                "counts": _path_direction_counts(),
                "targets": _PATH_TARGETS,
            }
            self._send_json(result)
            return

        # /api/preview/{category}/{filename}
        m = re.match(r"^/api/preview/(\w+)/(.+)$", path)
        if m:
            category, filename = m.group(1), m.group(2)
            if category not in _CATEGORIES or not _safe_filename(filename):
                self._send_error(400, "Invalid request")
                return
            filepath = _RECORDINGS_DIR / category / filename
            if not filepath.is_file():
                self._send_error(404, "Not found")
                return
            self._send_json(_parse_csv(filepath))
            return

        self._send_error(404, "Not found")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]

        if path == "/api/save":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))

            rec_type = body.get("type")
            if rec_type not in _CATEGORIES:
                self._send_error(400, f"Invalid type: {rec_type}")
                return

            metadata = body.get("metadata", {})
            rows = body.get("rows", [])
            columns = body.get("columns", [])
            direction = body.get("direction", "")

            if not rows or not columns:
                self._send_error(400, "Empty recording")
                return

            # Determine filename prefix
            if rec_type == "paths" and direction:
                prefix = direction
            elif rec_type == "holds":
                prefix = "hold"
            elif rec_type == "drags":
                prefix = "drag"
            elif rec_type == "browses":
                prefix = "browse"
            else:
                prefix = "idle"

            filename = _next_filename(rec_type, prefix)
            filepath = _RECORDINGS_DIR / rec_type / filename

            # Build CSV
            lines = []

            # Metadata comment
            meta_parts = [f"type={rec_type}"]
            for k, v in metadata.items():
                meta_parts.append(f"{k}={v}")
            if direction:
                meta_parts.append(f"direction={direction}")
            lines.append("# " + " ".join(meta_parts))

            # Header
            lines.append(",".join(columns))

            # Data rows
            for row in rows:
                lines.append(",".join(str(v) for v in row))

            filepath.write_text("\n".join(lines) + "\n")

            self._send_json({"filename": filename, "category": rec_type})
            return

        self._send_error(404, "Not found")

    def do_DELETE(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]

        # /api/recordings/{category}/{filename}
        m = re.match(r"^/api/recordings/(\w+)/(.+)$", path)
        if m:
            category, filename = m.group(1), m.group(2)
            if category not in _CATEGORIES or not _safe_filename(filename):
                self._send_error(400, "Invalid request")
                return
            filepath = _RECORDINGS_DIR / category / filename
            if not filepath.is_file():
                self._send_error(404, "Not found")
                return
            filepath.unlink()
            self._send_json({"deleted": filename})
            return

        self._send_error(404, "Not found")


def run_server(port: int = 8377) -> None:
    server = HTTPServer(("127.0.0.1", port), MousseHandler)
    print(f"Mousse server running on http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Mousse server.")
        server.server_close()
