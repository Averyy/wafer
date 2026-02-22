"""Computer vision for drag/slider CAPTCHA notch detection.

Canny edge detection + template matching to find the X offset where
a puzzle piece fits into a background image.  Works across GeeTest,
Alibaba Cloud CAPTCHA, and other jigsaw-style slider puzzles.

Uses multi-blur voting (edge matching at several Gaussian blur levels)
plus shape-aware contrast verification to handle diverse background
textures — halftone dots, circuit-board patterns, photographs, etc.

Requires ``opencv-python-headless``.
"""

import logging

import cv2
import numpy as np

logger = logging.getLogger("wafer")

_DILATE_KERNEL = np.ones((3, 3), np.uint8)
_BLUR_LEVELS = (0, 3, 5, 7, 9)
_CLUSTER_RADIUS = 15  # px — candidates within this distance are same cluster


def _prep_piece(
    piece_raw: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, int]:
    """Crop piece to alpha bbox, return (piece_rgb, piece_mask, x0_crop).

    piece_mask is a 2-D bool array (True = opaque piece pixels).
    x0_crop is the left padding removed during crop — needed to map
    the CV match position back to the full piece image coordinate.
    """
    if piece_raw.shape[2] == 4:
        alpha = piece_raw[:, :, 3]
        # Content boundary (alpha > 128) — tight crop for matching
        rows = np.any(alpha > 128, axis=1)
        cols = np.any(alpha > 128, axis=0)
        y0, y1 = np.where(rows)[0][[0, -1]]
        x0, x1 = np.where(cols)[0][[0, -1]]
        # x0_crop: how much left padding to subtract from the CV
        # match position to get the full piece image coordinate.
        # The piece has a semi-transparent drop shadow between
        # alpha=0 (outer edge) and alpha=128 (opaque content).
        # GeeTest positions the piece including this shadow, so
        # x0_crop should be the midpoint of the shadow region —
        # not the full content offset (too far left) nor the
        # image edge (too far right).
        cols_any = np.any(alpha > 0, axis=0)
        x0_outer = int(np.where(cols_any)[0][0]) if cols_any.any() else x0
        x0_crop = int((x0_outer + x0) // 2)
        piece_raw = piece_raw[y0 : y1 + 1, x0 : x1 + 1]
        piece_mask = piece_raw[:, :, 3] > 128
        mask_f = piece_mask.astype(np.float32)[:, :, np.newaxis]
        gray_fill = np.full(
            piece_raw.shape[:2] + (3,), 128, dtype=np.uint8
        )
        piece_rgb = (
            piece_raw[:, :, :3] * mask_f + gray_fill * (1 - mask_f)
        ).astype(np.uint8)
        return piece_rgb, piece_mask, x0_crop
    else:
        piece_rgb = piece_raw[:, :, :3]
        piece_mask = np.ones(piece_raw.shape[:2], dtype=bool)
        return piece_rgb, piece_mask, 0


def _edge_match(
    bg_gray: np.ndarray, piece_edges_rgb: np.ndarray, blur: int
) -> tuple[int, int, float]:
    """Run edge-based template matching at a given blur level.

    Returns ``(x, y, confidence)``.
    """
    if blur > 0:
        bg_proc = cv2.GaussianBlur(bg_gray, (blur, blur), 0)
    else:
        bg_proc = bg_gray
    bg_edges = cv2.Canny(bg_proc, 100, 200)
    result = cv2.matchTemplate(
        cv2.cvtColor(bg_edges, cv2.COLOR_GRAY2RGB),
        piece_edges_rgb,
        cv2.TM_CCOEFF_NORMED,
    )
    _, max_val, _, max_loc = cv2.minMaxLoc(result)
    return max_loc[0], max_loc[1], float(max_val)


def _hsv_match(
    bg_bgr: np.ndarray,
    piece_bgr: np.ndarray,
    piece_mask: np.ndarray,
) -> tuple[int, int, float]:
    """Match piece against bg using hue + saturation (ignoring brightness).

    GeeTest darkens the notch with a semi-transparent black overlay.
    This preserves hue and saturation while only reducing brightness.
    By matching in HS space, the darkening becomes invisible — the
    piece colors match the notch colors regardless of the overlay.
    """
    bg_hsv = cv2.cvtColor(bg_bgr, cv2.COLOR_BGR2HSV).astype(np.float32)
    piece_hsv = cv2.cvtColor(piece_bgr, cv2.COLOR_BGR2HSV).astype(np.float32)
    # H and S channels only (drop V which carries the darkening)
    bg_hs = bg_hsv[:, :, :2]
    piece_hs = piece_hsv[:, :, :2]
    mask_u8 = piece_mask.astype(np.uint8) * 255
    mask_2ch = np.stack([mask_u8, mask_u8], axis=2)
    result = cv2.matchTemplate(
        bg_hs, piece_hs, cv2.TM_SQDIFF, mask=mask_2ch
    )
    min_val, max_val, min_loc, _ = cv2.minMaxLoc(result)
    # Invert: lower SQDIFF = better match → higher confidence
    conf = 1.0 - (min_val / max(max_val, 1.0))
    return min_loc[0], min_loc[1], float(conf)


def _cluster_candidates(
    candidates: list[tuple[int, int, float]],
) -> list[tuple[int, int, float, int, float]]:
    """Cluster candidate (x, y, conf) triples by X proximity.

    Returns ``[(x_center, y_best, best_conf, vote_count, conf_sum), ...]``
    sorted by conf_sum descending, then vote count descending.
    ``y_best`` is the Y from the highest-confidence match in the cluster.
    """
    if not candidates:
        return []
    sorted_cands = sorted(candidates, key=lambda c: c[0])
    clusters: list[list[tuple[int, int, float]]] = []
    current: list[tuple[int, int, float]] = [sorted_cands[0]]
    for x, y, conf in sorted_cands[1:]:
        if x - current[0][0] <= _CLUSTER_RADIUS:
            current.append((x, y, conf))
        else:
            clusters.append(current)
            current = [(x, y, conf)]
    clusters.append(current)

    results = []
    for cluster in clusters:
        xs = [c[0] for c in cluster]
        confs = [c[2] for c in cluster]
        center = int(round(sum(xs) / len(xs)))
        # Use Y from the highest-confidence match in this cluster
        best_idx = max(range(len(cluster)), key=lambda i: cluster[i][2])
        y_best = cluster[best_idx][1]
        results.append((center, y_best, max(confs), len(cluster), sum(confs)))
    results.sort(key=lambda r: (-r[4], -r[3]))
    return results


def _contrast_score(
    bg_gray: np.ndarray, piece_mask: np.ndarray, x: int, y: int
) -> float:
    """Score how well the dark region at (x,y) matches the piece shape.

    GeeTest shades the drop zone darker.  We check that the shape of
    the darkened area in the background matches the piece shape — not
    just that the region is darker overall (which would false-positive
    on any random dark patch).

    Method: compute a local "darkness delta" (how much each pixel is
    darker than its local neighbourhood), threshold into a binary blob,
    then measure overlap (IoU) with the piece mask.  High overlap =
    the dark region is the same shape as the piece.

    Returns 0.0–1.0 (IoU between darkened blob and piece mask).
    """
    ph, pw = piece_mask.shape
    bh, bw = bg_gray.shape

    # Bounds check — piece must fit inside bg at this position
    if y + ph > bh or x + pw > bw or x < 0 or y < 0:
        return 0.0

    # Extract bg patch with some padding for context
    pad = 10
    x0 = max(x - pad, 0)
    y0 = max(y - pad, 0)
    x1 = min(x + pw + pad, bw)
    y1 = min(y + ph + pad, bh)
    context = bg_gray[y0:y1, x0:x1].astype(np.float64)

    # Local average: heavily blurred version represents "what the
    # area would look like without the notch shadow"
    local_avg = cv2.GaussianBlur(context, (31, 31), 0)

    # Darkness delta: positive where pixel is darker than surroundings
    delta = local_avg - context

    # Crop back to piece region (remove padding)
    px_off = x - x0
    py_off = y - y0
    delta_crop = delta[py_off : py_off + ph, px_off : px_off + pw]
    if delta_crop.shape != (ph, pw):
        return 0.0

    # Threshold: pixels darker than their surroundings by >= 5 levels
    dark_blob = delta_crop > 5.0

    # IoU: intersection over union with piece mask
    intersection = np.count_nonzero(dark_blob & piece_mask)
    union = np.count_nonzero(dark_blob | piece_mask)
    if union == 0:
        return 0.0

    return float(intersection / union)


def find_notch(bg_png: bytes, piece_png: bytes) -> tuple[int, float]:
    """Find the X pixel offset where *piece* fits into *bg*.

    Uses multi-blur edge voting + shape-aware contrast verification:

    1. Run Canny edge matching at blur levels 0, 3, 5, 7, 9.
    2. Cluster candidate X positions within 15px.
    3. Verify each cluster by checking if the notch region's dark
       shape matches the piece (IoU).  Picks best combined score.

    Returns the position of the full piece image (accounting for
    transparent padding removed during alpha crop).

    Args:
        bg_png: Raw PNG bytes of the background image (RGB).
        piece_png: Raw PNG bytes of the puzzle piece (RGBA with
            transparent padding around the actual shape).

    Returns:
        ``(x_offset, confidence)`` where *x_offset* is the pixel
        column in the background for the full piece image and
        *confidence* is the normalized correlation score (0.0–1.0).
    """
    bg = cv2.imdecode(np.frombuffer(bg_png, np.uint8), cv2.IMREAD_COLOR)
    piece = cv2.imdecode(
        np.frombuffer(piece_png, np.uint8), cv2.IMREAD_UNCHANGED
    )

    piece_rgb, piece_mask, x0_crop = _prep_piece(piece)

    bg_gray = cv2.cvtColor(bg, cv2.COLOR_BGR2GRAY)

    piece_gray = cv2.cvtColor(piece_rgb, cv2.COLOR_BGR2GRAY)
    piece_edges = cv2.Canny(piece_gray, 100, 200)
    piece_edges = cv2.dilate(piece_edges, _DILATE_KERNEL, iterations=1)
    piece_edges_rgb = cv2.cvtColor(piece_edges, cv2.COLOR_GRAY2RGB)

    # ── Multi-blur edge voting ─────────────────────────────────────
    candidates: list[tuple[int, int, float]] = []
    for blur in _BLUR_LEVELS:
        x, y, conf = _edge_match(bg_gray, piece_edges_rgb, blur)
        candidates.append((x, y, conf))
        logger.debug("CV edge blur=%d: x=%d y=%d conf=%.3f", blur, x, y, conf)

    # ── HSV color match (brightness-invariant) ─────────────────────
    # Matches piece hue+saturation against bg, ignoring the darkening
    # overlay.  Adds one vote that's independent of edge detection.
    # Skip for B&W / grayscale puzzles — no hue signal to match.
    piece_hsv_check = cv2.cvtColor(piece_rgb, cv2.COLOR_BGR2HSV)
    mean_sat = float(np.mean(piece_hsv_check[:, :, 1][piece_mask]))
    if mean_sat > 15:
        hsv_x, hsv_y, hsv_conf = _hsv_match(bg, piece_rgb, piece_mask)
        candidates.append((hsv_x, hsv_y, hsv_conf))
        logger.debug("CV hsv: x=%d y=%d conf=%.3f", hsv_x, hsv_y, hsv_conf)
    else:
        logger.debug("CV hsv: skipped (grayscale, sat=%.1f)", mean_sat)

    clusters = _cluster_candidates(candidates)

    # Fast path: high-confidence clean match (no blur needed)
    best_no_blur = candidates[0]  # blur=0
    if best_no_blur[2] >= 0.4 and clusters[0][3] >= 3:
        x_offset = max(clusters[0][0] - x0_crop, 0)
        logger.debug(
            "CV fast path: x=%d (raw=%d x0=%d) conf=%.3f votes=%d",
            x_offset, clusters[0][0], x0_crop,
            clusters[0][2], clusters[0][3],
        )
        return x_offset, clusters[0][2]

    # ── Contrast verification ──────────────────────────────────────
    # For each cluster, check if the dark region's shape matches the
    # piece shape (IoU).  Uses matched Y from template match — not
    # an estimate — so contrast checks the actual notch position.
    best_x = clusters[0][0]
    best_conf = clusters[0][2]
    best_score = -1.0

    for x_center, y_matched, conf, votes, conf_sum in clusters:
        contrast = _contrast_score(bg_gray, piece_mask, x_center, y_matched)
        # Confidence-weighted score: conf_sum rewards both quantity
        # AND quality of votes (3 weak votes < 1 strong HSV vote).
        score = conf_sum * 5 + contrast * 3
        logger.debug(
            "CV cluster x=%d y=%d conf=%.3f votes=%d conf_sum=%.3f "
            "contrast=%.3f score=%.2f",
            x_center, y_matched, conf, votes, conf_sum, contrast, score,
        )
        if score > best_score:
            best_score = score
            best_x = x_center
            best_conf = conf

    # Subtract x0_crop: CV found the cropped piece position,
    # but the slider maps the full piece image position.
    best_x = max(best_x - x0_crop, 0)
    logger.debug(
        "CV notch detection: x=%d (x0=%d) confidence=%.3f",
        best_x, x0_crop, best_conf,
    )
    return best_x, float(best_conf)
