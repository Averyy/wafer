"""Mousse HTTP server — serves UI and recording API."""

import json
import re
import shutil
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_STATIC_DIR = Path(__file__).resolve().parent / "_static"
_RECORDINGS_DIR = Path(__file__).resolve().parent.parent / "_recordings"
_CATEGORIES = ("idles", "paths", "holds", "drags", "slide_drags", "grids", "browses")

_COLLECTED_DET_DIR: Path | None = None
_COLLECTED_CLS_DIR: Path | None = None
_WAFER_CLS_DIR: Path | None = None
_WAFER_DET_DIR: Path | None = None

# Map reCAPTCHA keywords to CLS class names (Title Case, matching CLS dataset).
# Covers English keywords only since that's what metadata.jsonl stores.
_KEYWORD_TO_CLASSNAME: dict[str, str] = {
    "bicycles": "Bicycle", "a bicycle": "Bicycle",
    "bridges": "Bridge", "a bridge": "Bridge",
    "buses": "Bus", "a bus": "Bus",
    "school buses": "Bus", "a school bus": "Bus",
    "cars": "Car", "a car": "Car", "taxis": "Car", "a taxi": "Car",
    "chimneys": "Chimney", "a chimney": "Chimney",
    "crosswalks": "Crosswalk", "a crosswalk": "Crosswalk",
    "fire hydrants": "Hydrant", "a fire hydrant": "Hydrant",
    "motorcycles": "Motorcycle", "a motorcycle": "Motorcycle",
    "mountains": "Mountain", "mountains or hills": "Mountain",
    "palm trees": "Palm",
    "stairs": "Stair", "a staircase": "Stair",
    "tractors": "Tractor", "a tractor": "Tractor",
    "traffic lights": "Traffic Light", "a traffic light": "Traffic Light",
    "boats": "Boat", "a boat": "Boat",
    "parking meters": "Parking Meter", "a parking meter": "Parking Meter",
}

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".ico": "image/x-icon",
    ".png": "image/png",
}

# Target counts per the press-and-hold spec
_TARGETS = {
    "idles": 30, "paths": 26, "holds": 20,
    "drags": 20, "slide_drags": 15, "grids": 30, "browses": 20,
}

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


def _safe_resolve(base: Path, user_path: str) -> Path | None:
    """Resolve user_path under base and verify it doesn't escape.

    Returns the resolved Path if safe, None if traversal detected.
    """
    try:
        resolved = (base / user_path).resolve()
        if not resolved.is_relative_to(base.resolve()):
            return None
        return resolved
    except (ValueError, OSError):
        return None


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


def _read_jsonl(filepath: Path) -> list[dict]:
    """Read a JSONL file, returning list of dicts."""
    if not filepath.is_file():
        return []
    entries = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _count_labeled(dataset_dir: Path | None) -> dict[str, int]:
    """Count labeled images per class in a dataset directory."""
    counts: dict[str, int] = {}
    if not dataset_dir or not dataset_dir.is_dir():
        return counts
    for cls_dir in dataset_dir.iterdir():
        if cls_dir.is_dir():
            n = sum(1 for f in cls_dir.iterdir() if f.suffix in (".jpg", ".png"))
            counts[cls_dir.name] = n
    return counts


def _load_cls_tiles() -> dict:
    """Load collected CLS tiles with metadata and review status."""
    if not _COLLECTED_CLS_DIR or not _COLLECTED_CLS_DIR.is_dir():
        return {"tiles": [], "total": 0, "reviewed": 0, "has_tiles": False}

    metadata = _read_jsonl(_COLLECTED_CLS_DIR / "metadata.jsonl")

    # Build set of already-labeled files
    reviewed_files: set[str] = set()
    if _WAFER_CLS_DIR and _WAFER_CLS_DIR.is_dir():
        for cls_dir in _WAFER_CLS_DIR.iterdir():
            if cls_dir.is_dir():
                for f in cls_dir.iterdir():
                    if f.suffix == ".jpg":
                        reviewed_files.add(f.name)

    # Count labeled per class for priority sorting
    cls_counts = _count_labeled(_WAFER_CLS_DIR)

    tiles = []
    for entry in metadata:
        filepath = entry.get("file", "")
        filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
        # Check if file still exists in collected dir
        full_path = _COLLECTED_CLS_DIR / filepath
        is_reviewed = filename in reviewed_files
        exists = full_path.is_file()
        if not exists and not is_reviewed:
            continue
        tiles.append({
            **entry,
            "reviewed": is_reviewed,
            "exists": exists,
        })

    # Sort unreviewed tiles: lowest labeled class count first
    def _cls_sort_key(tile):
        if tile["reviewed"]:
            return (1, 0)  # reviewed tiles last
        cls_name = tile.get("predicted_class", "Other")
        count = cls_counts.get(cls_name, 0)
        return (0, count)

    tiles.sort(key=_cls_sort_key)

    reviewed_count = sum(1 for t in tiles if t["reviewed"])
    return {
        "tiles": tiles,
        "total": len(tiles),
        "reviewed": reviewed_count,
        "has_tiles": len(tiles) > 0,
    }


def _load_det_grids() -> dict:
    """Load unannotated DET grids from collected_det/."""
    if not _COLLECTED_DET_DIR or not _COLLECTED_DET_DIR.is_dir():
        return {"grids": [], "total": 0, "has_grids": False}

    metadata = _read_jsonl(_COLLECTED_DET_DIR / "metadata.jsonl")

    # Count labeled per class for priority sorting
    det_counts = _count_labeled(_WAFER_DET_DIR)

    grids = []
    for entry in metadata:
        filename = entry.get("file")
        if not filename:
            continue
        # Flat structure: file is just "uuid.jpg"
        if not (_COLLECTED_DET_DIR / filename).is_file():
            continue
        grids.append(entry)

    # Sort: lowest labeled class count first
    def _det_sort_key(grid):
        kw = (grid.get("keyword") or "").lower()
        cls_name = _KEYWORD_TO_CLASSNAME.get(kw, "Other")
        return det_counts.get(cls_name, 0)

    grids.sort(key=_det_sort_key)

    return {
        "grids": grids,
        "total": len(grids),
        "has_grids": len(grids) > 0,
    }


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

        if path == "/api/label-stats":
            cls_counts = _count_labeled(_WAFER_CLS_DIR)
            det_counts = _count_labeled(_WAFER_DET_DIR)
            # Build set of already-labeled CLS filenames
            cls_reviewed: set[str] = set()
            if _WAFER_CLS_DIR and _WAFER_CLS_DIR.is_dir():
                for d in _WAFER_CLS_DIR.iterdir():
                    if d.is_dir():
                        for f in d.iterdir():
                            cls_reviewed.add(f.name)
            # Count unlabeled CLS per predicted class
            cls_pending: dict[str, int] = {}
            if _COLLECTED_CLS_DIR and (_COLLECTED_CLS_DIR / "metadata.jsonl").is_file():
                for entry in _read_jsonl(_COLLECTED_CLS_DIR / "metadata.jsonl"):
                    fp = entry.get("file", "")
                    fn = fp.rsplit("/", 1)[-1] if "/" in fp else fp
                    if fn not in cls_reviewed:
                        cls_name = entry.get("predicted_class", "Other")
                        cls_pending[cls_name] = cls_pending.get(cls_name, 0) + 1
            # Count unlabeled DET per keyword class
            det_pending: dict[str, int] = {}
            if _COLLECTED_DET_DIR and (_COLLECTED_DET_DIR / "metadata.jsonl").is_file():
                for entry in _read_jsonl(_COLLECTED_DET_DIR / "metadata.jsonl"):
                    kw = (entry.get("keyword") or "").lower()
                    cls_name = _KEYWORD_TO_CLASSNAME.get(kw, "Other")
                    det_pending[cls_name] = det_pending.get(cls_name, 0) + 1
                for k, v in det_counts.items():
                    if k in det_pending:
                        det_pending[k] = max(0, det_pending[k] - v)
            self._send_json({
                "cls": {"labeled": cls_counts, "pending": cls_pending},
                "det": {"labeled": det_counts, "pending": det_pending},
            })
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

        # /api/det/grids - list collected DET grids with metadata
        if path == "/api/det/grids":
            self._send_json(_load_det_grids())
            return

        # /api/det/image/{filename} or /api/det/image/{sub}/{filename}
        if path.startswith("/api/det/image/"):
            if not _COLLECTED_DET_DIR:
                self._send_error(404, "DET dir not configured")
                return
            user_path = path[len("/api/det/image/"):]
            filepath = _safe_resolve(_COLLECTED_DET_DIR, user_path)
            if not filepath or not filepath.is_file():
                self._send_error(404, "Not found")
                return
            self._send_file(filepath, "image/jpeg")
            return

        # /api/cls/tiles - list collected tiles with metadata
        if path == "/api/cls/tiles":
            self._send_json(_load_cls_tiles())
            return

        # /api/cls/image/{filename} or /api/cls/image/{sub}/{filename}
        if path.startswith("/api/cls/image/"):
            if not _COLLECTED_CLS_DIR:
                self._send_error(404, "Collected dir not configured")
                return
            user_path = path[len("/api/cls/image/"):]
            filepath = _safe_resolve(_COLLECTED_CLS_DIR, user_path)
            if (not filepath or not filepath.is_file()) and _WAFER_CLS_DIR:
                # Check wafer_cls dir (for history thumbnails)
                filepath = _safe_resolve(_WAFER_CLS_DIR, user_path)
            if not filepath or not filepath.is_file():
                self._send_error(404, "Not found")
                return
            self._send_file(filepath, "image/jpeg")
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

        if path == "/api/det/annotate":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            if not _COLLECTED_DET_DIR:
                self._send_error(400, "DET dir not configured")
                return
            file_path = body.get("file", "")
            keyword = body.get("keyword", "")
            if not file_path:
                self._send_error(400, "Missing file")
                return

            # Map keyword to CLS class name (Title Case)
            kw_lower = keyword.lower().strip()
            class_name = _KEYWORD_TO_CLASSNAME.get(kw_lower)
            if not class_name:
                # Fallback: title-case the keyword
                class_name = keyword.strip().title()

            # Validate source file
            src = _safe_resolve(_COLLECTED_DET_DIR, file_path)
            if not src or not src.is_file():
                self._send_error(404, "Source file not found")
                return
            bare = src.name

            # Copy to datasets/wafer_det/ (DET training data)
            if _WAFER_DET_DIR:
                det_out = _safe_resolve(
                    _WAFER_DET_DIR, class_name,
                )
                if det_out:
                    det_out.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(src), str(det_out / bare))

            # Copy to datasets/wafer_cls/ (valid CLS data)
            if _WAFER_CLS_DIR:
                cls_dir = _safe_resolve(
                    _WAFER_CLS_DIR, class_name,
                )
                if cls_dir:
                    cls_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(src), str(cls_dir / bare))

            # Write annotation to wafer_det/
            annotation = {
                "file": bare,
                "keyword_folder": class_name,
                "keyword": keyword,
                "grid_type": body.get("grid_type", ""),
                "ground_truth": body.get("ground_truth", []),
            }
            if _WAFER_DET_DIR:
                ann_path = _WAFER_DET_DIR / "annotations.jsonl"
            else:
                ann_path = _COLLECTED_DET_DIR / "annotations.jsonl"
            ann_path.parent.mkdir(parents=True, exist_ok=True)
            with open(ann_path, "a") as f:
                f.write(json.dumps(annotation) + "\n")

            # Remove from collected queue
            src.unlink()
            self._send_json({
                "ok": True,
                "dest": f"{class_name}/{bare}",
            })
            return

        if path == "/api/cls/label":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            file_path = body.get("file", "")
            label = body.get("label", "")
            if not file_path or not label:
                self._send_error(400, "Missing file or label")
                return
            if not _COLLECTED_CLS_DIR or not _WAFER_CLS_DIR:
                self._send_error(400, "Dirs not configured")
                return
            src = _safe_resolve(_COLLECTED_CLS_DIR, file_path)
            if not src or not src.is_file():
                self._send_error(404, "Tile not found")
                return
            dest_dir = _safe_resolve(_WAFER_CLS_DIR, label)
            if not dest_dir:
                self._send_error(400, "Invalid label")
                return
            filename = src.name
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dest_dir / filename))
            self._send_json({"ok": True, "dest": f"{label}/{filename}"})
            return

        if path == "/api/cls/undo":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            reviewed_path = body.get("reviewed_path", "")  # e.g. "Stair/uuid.jpg"
            original_path = body.get("original_path", "")  # e.g. "uuid.jpg"
            if not reviewed_path or not original_path:
                self._send_error(400, "Missing paths")
                return
            if not _COLLECTED_CLS_DIR or not _WAFER_CLS_DIR:
                self._send_error(400, "Dirs not configured")
                return
            src = _safe_resolve(_WAFER_CLS_DIR, reviewed_path)
            if not src or not src.is_file():
                self._send_error(404, "Reviewed file not found")
                return
            dest = _safe_resolve(_COLLECTED_CLS_DIR, original_path)
            if not dest:
                self._send_error(400, "Invalid path")
                return
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dest))
            self._send_json({"ok": True})
            return

        if path == "/api/cls/skip":
            # Just acknowledge - tile stays in collected/
            self._send_json({"ok": True})
            return

        if path == "/api/cls/delete":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            file_path = body.get("file", "")
            if not file_path or not _COLLECTED_CLS_DIR:
                self._send_error(400, "Missing file or dir not configured")
                return
            src = _safe_resolve(_COLLECTED_CLS_DIR, file_path)
            if src and src.is_file():
                src.unlink()
            self._send_json({"ok": True})
            return

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
            elif rec_type == "slide_drags":
                prefix = "slide"
            elif rec_type == "grids":
                prefix = "grid_hop"
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


def run_server(
    port: int = 8377,
    collected_det: Path | None = None,
    collected_cls: Path | None = None,
) -> None:
    global _COLLECTED_DET_DIR, _COLLECTED_CLS_DIR, _WAFER_CLS_DIR, _WAFER_DET_DIR  # noqa: PLW0603
    _COLLECTED_DET_DIR = collected_det
    _COLLECTED_CLS_DIR = collected_cls
    if collected_cls:
        _WAFER_CLS_DIR = collected_cls.parent / "datasets" / "wafer_cls"
    if collected_det:
        _WAFER_DET_DIR = collected_det.parent / "datasets" / "wafer_det"
    server = HTTPServer(("127.0.0.1", port), MousseHandler)
    url = f"http://localhost:{port}"
    print(f"Mousse server running on {url}")
    import webbrowser
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Mousse server.")
        server.server_close()
