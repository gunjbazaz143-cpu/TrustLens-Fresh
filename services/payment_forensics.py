"""
Image forensics for payment screenshot authenticity.

Reports signals that OCR and EXIF cannot see. The two primary checks are
Error Level Analysis (ELA) and copy-move block matching.

IMPORTANT (calibration note): payment screenshots are text-heavy images with
large solid areas, and genuine screenshots routinely carry re-compression
(WhatsApp/Telegram/email) and repeated UI rows. Both detectors therefore return
graded evidence instead of a single extreme flag:

  * ela_analysis      - ratio is continuous; the scanner treats > 0.05 as
                        moderate and > 0.10 as strong evidence of a
                        re-encoded / composited region.
  * copy_move_analysis - the strongest signal is a DOMINANT displacement
                        vector (many verified block pairs sharing one offset),
                        which is the signature of a cloned/pasted region.
                        Scattered duplication from normal UI repetition does
                        not form such a cluster.

The scoring layer decides severity/contribution. Every function is defensive:
internal errors degrade to "no signal".
"""

import os
import tempfile
import uuid

import cv2
import numpy as np

_MAX_DIM = 1200


def _to_bgr(rgb: np.ndarray) -> np.ndarray:
    """Convert an (H, W, 3) uint8 RGB array to BGR, downscaled for speed."""
    h, w = rgb.shape[:2]
    scale = min(1.0, _MAX_DIM / max(h, w))
    if scale < 1.0:
        rgb = cv2.resize(rgb, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)


def _gray(rgb: np.ndarray) -> np.ndarray:
    """Return a downscaled grayscale version of an RGB array."""
    return cv2.cvtColor(_to_bgr(rgb), cv2.COLOR_BGR2GRAY)


def _jpeg(bgr: np.ndarray, quality: int) -> str:
    tmp = os.path.join(tempfile.gettempdir(), f"trustlens_ela_{uuid.uuid4().hex}.jpg")
    ok, buf = cv2.imencode(".jpg", bgr, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        raise OSError("JPEG encode failed")
    buf.tofile(tmp)
    return tmp


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def ela_analysis(rgb: np.ndarray, quality: int = 90, cell: int = 14) -> dict:
    """Error Level Analysis.

    Re-encodes the image twice at the same quality and compares. Content that
    carried a prior compression (edited / composited region) accumulates more
    error on the second pass and stands out against the mostly uniform error of
    a single-encode screenshot.

    Flagged only at an extreme anomaly ratio (safety-net threshold calibrated
    so normal re-compressed screenshots never trigger it).
    """
    try:
        bgr = _to_bgr(rgb)
        path_a = _jpeg(bgr, quality)
        try:
            a = cv2.imread(path_a, cv2.IMREAD_GRAYSCALE)
            path_b = _jpeg(a, quality)
            try:
                b = cv2.imread(path_b, cv2.IMREAD_GRAYSCALE)
                if a is None or b is None:
                    return {"ratio": 0.0, "mean": 0.0, "cv": 0.0, "flag": False}
                diff = np.abs(a.astype(np.float32) - b.astype(np.float32))
                h, w = diff.shape
                cw, ch = max(1, w // cell), max(1, h // cell)
                grid = cv2.resize(diff, (cw, ch), interpolation=cv2.INTER_AREA)
                if grid.size == 0:
                    return {"ratio": 0.0, "mean": 0.0, "cv": 0.0, "flag": False}
                mean = float(grid.mean())
                med = float(np.median(grid))
                thr = max(med * 4.0, 0.6)
                ratio = float((grid > thr).mean())
                cv = float(grid.std() / (mean + 1e-6))
                return {
                    "ratio": round(ratio, 5),
                    "mean": round(mean, 2),
                    "cv": round(cv, 2),
                    "flag": bool(ratio > 0.08),
                }
            finally:
                _remove(path_b)
        finally:
            _remove(path_a)
    except Exception:  # noqa: BLE001
        return {"ratio": 0.0, "mean": 0.0, "cv": 0.0, "flag": False}


def copy_move_analysis(
    rgb: np.ndarray,
    block: int = 24,
    stride: int = 12,
    std_min: float = 10.0,
) -> dict:
    """Copy-move detection via verified block-feature matching.

    Uniform blocks (solid backgrounds, common in UI screenshots) are ignored and
    candidate pairs must match pixel-content within a tight tolerance, so random
    coincidences do not count.

    A cloned/pasted region produces MANY matching block pairs that all share the
    same displacement vector (dx, dy). Genuine UI repetition (repeated buttons,
    rows, badges) also matches blocks, but at scattered offsets. The number of
    block-pairs sharing a single dominant offset is therefore a much more
    specific tamper signal than the raw duplicate-block count, and it is what
    drives the graded flags here. The raw counts are still returned for
    diagnostics.
    """
    try:
        g = _gray(rgb)
        h, w = g.shape
        if h < block or w < block:
            return {"matches": 0, "blocks": 0, "dup_ratio": 0.0, "offset_max": 0, "flag": False}
        features = {}
        for y in range(0, h - block + 1, stride):
            for x in range(0, w - block + 1, stride):
                cell = g[y:y + block, x:x + block].astype(np.float32)
                s = float(cell.std())
                if s < std_min:
                    continue
                key = (round(float(cell.mean()), 1), round(s, 1))
                features.setdefault(key, []).append((x // stride, y // stride))

        # Number of grid cells sampled (for a resolution-independent ratio).
        total_cells = max(1, ((h - block) // stride + 1) * ((w - block) // stride + 1))

        duplicated_blocks = 0
        features_hit = 0
        offset_counts = {}
        for key, coords in features.items():
            if len(coords) < 2:
                continue
            for i in range(len(coords)):
                for j in range(i + 1, len(coords)):
                    (x1, y1), (x2, y2) = coords[i], coords[j]
                    if abs(x1 - x2) + abs(y1 - y2) <= 3:
                        continue
                    b1 = g[y1 * stride:y1 * stride + block, x1 * stride:x1 * stride + block]
                    b2 = g[y2 * stride:y2 * stride + block, x2 * stride:x2 * stride + block]
                    if np.abs(b1.astype(np.float32) - b2.astype(np.float32)).mean() >= 4.0:
                        continue
                    duplicated_blocks += 2
                    dx, dy = x2 - x1, y2 - y1
                    offset_counts[(dx, dy)] = offset_counts.get((dx, dy), 0) + 1
            features_hit += 1

        offset_max = max(offset_counts.values()) if offset_counts else 0
        dup_ratio = round(duplicated_blocks / total_cells, 5)
        # A single consistent displacement with a large verified footprint is a
        # cloned-region signature; genuine scattered UI repetition rarely forms
        # such a dominant offset cluster.
        strong = bool(offset_max >= 60)
        moderate = bool(offset_max >= 25)
        return {
            "matches": features_hit,
            "blocks": duplicated_blocks,
            "dup_ratio": dup_ratio,
            "offset_max": offset_max,
            "flag": strong,
            "moderate": moderate,
        }
    except Exception:  # noqa: BLE001
        return {"matches": 0, "blocks": 0, "dup_ratio": 0.0, "offset_max": 0, "flag": False, "moderate": False}
