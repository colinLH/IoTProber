import sys
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "agent")]

from drift import (  # noqa: E402
    DEFAULT_HASH_DIM,
    DRIFT_SENSITIVITY,
    FEATURE_BACKEND_HASH_V2,
    USE_COLS,
    assign_group_splits,
    build_hashed_feature_matrix,
    calibrate_quantile_thresholds,
    remove_cross_type_ip_conflicts,
)


def _fingerprints():
    rows = []
    for ip, os_product in [("1.1.1.1", "linux"), ("2.2.2.2", None)]:
        row = {column: None for column in USE_COLS}
        row.update({
            "ip": ip,
            "as-asn": 64512,
            "as-name": "example network",
            "os-product": os_product,
            "service-distribution": "HTTP-80, HTTPS-443",
            "http-tags": "title camera login",
        })
        rows.append(row)
    return pd.DataFrame(rows)


def test_perspective_weights_are_configured_and_normalized():
    assert np.isclose(sum(DRIFT_SENSITIVITY.values()), 1.0)
    assert set(DRIFT_SENSITIVITY) == {
        "as", "whois", "os", "sw", "hw", "sd", "body", "htags",
        "hfavicons", "certificate", "dns",
    }


def test_hash_features_are_deterministic_and_missing_aware():
    frame = _fingerprints()
    first, p_idx = build_hashed_feature_matrix(frame, hash_dim=16)
    second, second_idx = build_hashed_feature_matrix(frame, hash_dim=16)
    assert p_idx == second_idx
    assert np.array_equal(first, second)
    assert first.dtype == np.float32
    assert first.shape == (2, len(DRIFT_SENSITIVITY) * 16)
    os_idx = p_idx["os"]
    assert not np.array_equal(first[0, os_idx], first[1, os_idx])


def test_group_split_never_separates_same_ip():
    ips = pd.Series(["1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3"])
    split = assign_group_splits(ips, seed=7)
    assert split[0] == split[2]
    assert np.array_equal(split, assign_group_splits(ips, seed=7))


def test_cross_type_conflicts_are_removed():
    frame = pd.DataFrame({
        "ip": ["1.1.1.1", "1.1.1.1", "2.2.2.2"],
        "device_type": ["CAMERA", "ROUTER", "NAS"],
    })
    cleaned, stats = remove_cross_type_ip_conflicts(frame)
    assert cleaned["ip"].tolist() == ["2.2.2.2"]
    assert stats == {"conflicting_ips": 1, "removed_rows": 2}


def test_class_quantile_thresholds_use_calibration_only():
    scores = np.arange(200, dtype=float)
    labels = np.asarray(["A"] * 100 + ["B"] * 100)
    global_threshold, class_thresholds, counts = calibrate_quantile_thresholds(
        scores, labels, quantile=0.99, min_class_size=30
    )
    assert global_threshold == 198.0
    assert class_thresholds == {"A": 99.0, "B": 199.0}
    assert counts == {"A": 100, "B": 100}


def test_backend_version_constant_is_stable():
    assert FEATURE_BACKEND_HASH_V2 == "perspective_hash_v2"
    assert DEFAULT_HASH_DIM > 0
