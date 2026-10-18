"""
Perspective-Aware Contrastive Autoencoder (PACA) for In-Class Concept Drift Detection
======================================================================================
Detects in-class concept drift where the device type label is unchanged but the
feature space has shifted. Perspective sensitivities come from the single
authoritative configuration file ``config/perspective_info.json``.

Loss = L_recon + λ · L_contrast

L_recon   = Σ_{p∈P} α_p · (1/|C_p|) · Σ_{k∈C_p} (x_k − x̂_k)²

L_contrast = (1/N) Σ_{(i,j)} [ y_ij · D_z(i,j)²
             + (1−y_ij) · max(0, m − D_z(i,j))² ]

where D_z is RMS distance in the bounded latent representation. Perspective
weights affect reconstruction and scoring, while contrastive structure is kept
independent of raw perspective dimensionality.
"""

import os
import json
import hashlib
import math
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from sklearn.preprocessing import LabelEncoder, StandardScaler, normalize
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction import FeatureHasher
from scipy.stats import median_abs_deviation
from collections import OrderedDict
import joblib
import logging
import random
import re
import time

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from path_config import (
    AGENT_DIR,
    CSV_DATA_DIR,
    DRIFT_OUTPUT_DIR,
    LOCAL_USED_FEATURES_FILE,
    PERSPECTIVE_INFO_FILE,
    RAG_DATA_DIR,
    ROOT_DIR,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ────────────────────────── Paths ──────────────────────────
BASE_DIR = AGENT_DIR
IPRAW_DIR = CSV_DATA_DIR
FEATURES_FILE = LOCAL_USED_FEATURES_FILE
PERSPECTIVE_FILE = PERSPECTIVE_INFO_FILE

DEVICE_TYPES = [
    "BUILDING_AUTOMATION", "CAMERA", "MEDICAL", "NAS", "NVR",
    "POWER_METER", "PRINTER", "ROUTER", "SCADA", "ALARM", "CONTROLLER",
]

EXCLUDED_PERSPECTIVES = {"http", "hpart", "overall"}

# ── Drift-sensitivity weights α_p ─────────────────────────
def _load_drift_sensitivity():
    """Read the authoritative perspective weights; do not duplicate config."""
    with open(PERSPECTIVE_FILE, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    weights = {
        name: float(entry["weight"])
        for name, entry in config.items()
        if name not in EXCLUDED_PERSPECTIVES and float(entry.get("weight", 0)) > 0
    }
    if not weights or any(
        not np.isfinite(value) or value <= 0 for value in weights.values()
    ):
        raise ValueError(f"Invalid perspective weights in {PERSPECTIVE_FILE}")
    return weights


# The JSON configuration is the single source of truth for sensitivity.
DRIFT_SENSITIVITY = _load_drift_sensitivity()

# Only for loading pre-v2 artifacts that did not persist their scoring weights.
LEGACY_DRIFT_SENSITIVITY = {
    "whois": 1.0, "as": 1.0, "dns": 0.9, "sd": 0.9,
    "htags": 0.8, "hfavicons": 0.8, "body": 0.7,
    "os": 0.3, "sw": 0.2, "hw": 0.2, "certificate": 0.3,
}

FEATURE_BACKEND_HASH_V2 = "perspective_hash_v2"
DEFAULT_HASH_DIM = 128
DEFAULT_MAX_FIELD_CHARS = 4096
DEFAULT_MAX_FIELD_TOKENS = 256
DEFAULT_SPLIT_RATIOS = OrderedDict(
    [("train", 0.70), ("val", 0.10), ("calibration", 0.10), ("test", 0.10)]
)
_MISSING_STRINGS = {"", "unknown", "none", "null", "nan", "[]", "{}"}
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:/-]{1,95}", re.IGNORECASE)

# ── Column lists (25 features from config/local_used_features.txt) ──
USE_COLS = [
    "ip",
    "as-asn", "as-name", "as-bgp_prefix", "as-country_code",
    "whois-network-handle", "whois-network-name",
    "whois-organization-handle", "whois-organization-name",
    "os-vendor", "os-product", "os-version",
    "sw-vendors", "sw-products", "sw-versions",
    "hw-vendors", "hw-products", "hw-versions",
    "service-distribution",
    "http-bodys", "http-tags", "http-favicon-urls",
    "cert-subjects", "cert-issuers", "tls-versions",
    "dns-reverse",
]

TEXT_FEATURES = [
    "as-name", "as-bgp_prefix",
    "whois-network-name", "whois-organization-name",
    "os-version",
    "sw-vendors", "sw-products", "sw-versions",
    "hw-vendors", "hw-products", "hw-versions",
    "service-distribution",
    "http-bodys", "http-tags", "http-favicon-urls",
    "cert-subjects", "cert-issuers", "tls-versions",
    "dns-reverse",
]

CAT_FEATURES = [
    "as-country_code",
    "whois-network-handle", "whois-organization-handle",
    "os-vendor", "os-product",
]

_TFIDF_MAX = {"http-bodys": 200, "http-tags": 200, "http-favicon-urls": 100}
_TFIDF_DEFAULT = 300


# ═══════════════════════════════════════════════════════════
# 1. Perspective Configuration
# ═══════════════════════════════════════════════════════════

def load_perspectives():
    with open(PERSPECTIVE_FILE, "r", encoding="utf-8") as f:
        pinfo = json.load(f)
    perspectives = OrderedDict()
    for pname, pdata in pinfo.items():
        if pname in EXCLUDED_PERSPECTIVES:
            continue
        perspectives[pname] = {
            "cols": pdata["cols"],
            "weight": float(pdata["weight"]),
        }
    return perspectives


# ═══════════════════════════════════════════════════════════
# 2. Data Loading & Feature Engineering
# ═══════════════════════════════════════════════════════════

def _comma_tokenizer(text):
    return [t.strip() for t in str(text).split(",") if t.strip()]


def load_ipraw(device_type, ip_filter=None, ipraw_dir=IPRAW_DIR):
    path = os.path.join(ipraw_dir, f"ipraw_{device_type}.csv")
    if not os.path.exists(path):
        return pd.DataFrame()
    parts = []
    for chunk in pd.read_csv(path, usecols=USE_COLS, chunksize=50_000, low_memory=False):
        if ip_filter is not None:
            chunk = chunk[chunk["ip"].isin(ip_filter)]
        if len(chunk):
            parts.append(chunk)
    return pd.concat(parts).drop_duplicates("ip", keep="first") if parts else pd.DataFrame()


def build_feature_matrix(df, vectorizers=None, cat_columns_map=None, fit=True):
    """Return (X_dense, perspective_indices, vectorizers, cat_columns_map)."""
    if vectorizers is None:
        vectorizers = {}
    if cat_columns_map is None:
        cat_columns_map = {}

    matrices, col_ranges, cur = [], {}, 0

    # TF-IDF
    for col in TEXT_FEATURES:
        df[col] = df[col].fillna("").astype(str)
        mx = _TFIDF_MAX.get(col, _TFIDF_DEFAULT)
        if fit:
            vec = TfidfVectorizer(tokenizer=_comma_tokenizer, token_pattern=None,
                                  max_features=mx, sublinear_tf=True)
            m = vec.fit_transform(df[col]).toarray()
            vectorizers[col] = vec
        else:
            m = vectorizers[col].transform(df[col]).toarray()
        col_ranges[col] = (cur, cur + m.shape[1]); cur += m.shape[1]
        matrices.append(m)

    # One-hot categorical
    for col in CAT_FEATURES:
        df[col] = df[col].fillna("UNK").astype(str)
        dum = pd.get_dummies(df[col], prefix=col)
        if fit:
            cat_columns_map[col] = list(dum.columns)
        else:
            dum = dum.reindex(columns=cat_columns_map[col], fill_value=0)
        m = dum.values.astype(np.float32)
        col_ranges[col] = (cur, cur + m.shape[1]); cur += m.shape[1]
        matrices.append(m)

    # Numeric: as-asn
    asn = pd.to_numeric(df["as-asn"], errors="coerce").fillna(0).values.reshape(-1, 1).astype(np.float32)
    col_ranges["as-asn"] = (cur, cur + 1); cur += 1
    matrices.append(asn)

    X = np.hstack(matrices)

    # Map perspective → column indices
    perspectives = load_perspectives()
    p_idx = {}
    for pname, pdata in perspectives.items():
        idx = []
        for c in pdata["cols"]:
            if c in col_ranges:
                s, e = col_ranges[c]
                idx.extend(range(s, e))
        if idx:
            p_idx[pname] = idx

    return X, p_idx, vectorizers, cat_columns_map


def _is_missing_value(value):
    """Use one missing-value contract for training and online inference."""
    if value is None:
        return True
    try:
        if pd.isna(value):
            return True
    except (TypeError, ValueError):
        pass
    return str(value).strip().lower() in _MISSING_STRINGS


def _hashed_feature_rows(df, cols, max_field_chars, max_field_tokens):
    """Yield sparse feature dictionaries without building giant text documents.

    Tokens are namespaced by their source column.  Explicit missing/present and
    length-bin tokens prevent a missing value from collapsing onto an unseen
    value, which was a major ambiguity in the legacy TF-IDF pipeline.
    """
    for values in df[cols].itertuples(index=False, name=None):
        features = {}
        for col, value in zip(cols, values):
            if _is_missing_value(value):
                features[f"{col}=__missing__"] = 1.0
                continue

            raw = str(value)
            clipped = raw[:max_field_chars].lower()
            tokens = _TOKEN_RE.findall(clipped)
            features[f"{col}=__present__"] = 1.0
            length_bin = min(15, int(math.log2(max(len(raw), 1))))
            features[f"{col}=__len_{length_bin}"] = 1.0
            if not tokens:
                features[f"{col}=__no_lexical_token__"] = 1.0
                continue
            for token in tokens[:max_field_tokens]:
                key = f"{col}={token}"
                features[key] = features.get(key, 0.0) + 1.0
        yield features


def build_hashed_feature_matrix(
    df,
    hash_dim=DEFAULT_HASH_DIM,
    max_field_chars=DEFAULT_MAX_FIELD_CHARS,
    max_field_tokens=DEFAULT_MAX_FIELD_TOKENS,
    perspective_columns=None,
    log_progress=True,
):
    """Build a bounded, OOV-safe, perspective-balanced float32 matrix.

    Every perspective receives exactly ``hash_dim`` dimensions.  This avoids
    the legacy 55,838-dimensional dense matrix (50,240 WHOIS dimensions alone)
    and prevents raw cardinality from silently deciding contrastive importance.
    FeatureHasher is stateless, so there is no train/test vocabulary leakage.
    """
    if perspective_columns is None:
        perspective_columns = OrderedDict(
            (name, list(entry["cols"]))
            for name, entry in load_perspectives().items()
        )
    n = len(df)
    p_idx = {}
    X = np.empty((n, len(perspective_columns) * hash_dim), dtype=np.float32)
    start = 0
    for pname, configured_cols in perspective_columns.items():
        cols = [c for c in configured_cols if c in df.columns]
        if not cols:
            continue
        hasher = FeatureHasher(
            n_features=hash_dim,
            input_type="dict",
            alternate_sign=False,
            dtype=np.float32,
        )
        sparse = hasher.transform(
            _hashed_feature_rows(df, cols, max_field_chars, max_field_tokens)
        )
        sparse = normalize(sparse, norm="l2", copy=False)
        end = start + hash_dim
        X[:, start:end] = sparse.toarray().astype(np.float32, copy=False)
        p_idx[pname] = list(range(start, end))
        start = end
        if log_progress:
            logger.info("  hashed perspective %-12s cols=%d dim=%d", pname, len(cols), hash_dim)
    return X[:, :start], p_idx


def assign_group_splits(ips, ratios=None, seed=20260925):
    """Deterministically split by IP so one device group cannot leak across sets."""
    ratios = OrderedDict(ratios or DEFAULT_SPLIT_RATIOS)
    if not ratios or any(v <= 0 for v in ratios.values()):
        raise ValueError("All split ratios must be positive")
    total = float(sum(ratios.values()))
    cumulative = []
    running = 0.0
    for name, ratio in ratios.items():
        running += ratio / total
        cumulative.append((name, running))

    assignments = []
    for ip in ips:
        payload = f"{seed}:{ip}".encode("utf-8", errors="replace")
        value = int.from_bytes(hashlib.blake2b(payload, digest_size=8).digest(), "big")
        unit = value / float(2**64)
        selected = cumulative[-1][0]
        for name, boundary in cumulative:
            if unit < boundary:
                selected = name
                break
        assignments.append(selected)
    return np.asarray(assignments, dtype=object)


def remove_cross_type_ip_conflicts(df):
    """Drop ambiguous IP groups rather than training contradictory pairs."""
    label_counts = df.groupby("ip", sort=False)["device_type"].nunique()
    conflict_ips = set(label_counts[label_counts > 1].index.astype(str))
    if not conflict_ips:
        return df.reset_index(drop=True), {"conflicting_ips": 0, "removed_rows": 0}
    keep = ~df["ip"].astype(str).isin(conflict_ips)
    cleaned = df.loc[keep].reset_index(drop=True)
    return cleaned, {
        "conflicting_ips": len(conflict_ips),
        "removed_rows": int((~keep).sum()),
    }


# ═══════════════════════════════════════════════════════════
# 3. Model
# ═══════════════════════════════════════════════════════════

class PerspectiveAwareCAE(nn.Module):
    def __init__(self, input_dim, hidden_dims=(128, 64), latent_dim=16):
        super().__init__()
        # Encoder
        layers = []
        d = input_dim
        for h in hidden_dims:
            layers += [nn.Linear(d, h), nn.ReLU(), nn.BatchNorm1d(h)]
            d = h
        layers.append(nn.Linear(d, latent_dim))
        self.encoder = nn.Sequential(*layers)
        # Decoder (symmetric)
        layers = []
        d = latent_dim
        for h in reversed(hidden_dims):
            layers += [nn.Linear(d, h), nn.ReLU(), nn.BatchNorm1d(h)]
            d = h
        layers.append(nn.Linear(d, input_dim))
        self.decoder = nn.Sequential(*layers)

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z), z


# ═══════════════════════════════════════════════════════════
# 4. Loss
# ═══════════════════════════════════════════════════════════

class PerspectiveWeightedLoss(nn.Module):
    def __init__(self, p_idx, sensitivity, lam=1.0, margin=2.0):
        super().__init__()
        self.p_idx = p_idx
        self.sens = sensitivity
        self.lam = lam
        self.margin = margin
        # pre-build index tensors (moved to device on first call)
        self._idx_tensors = {p: torch.tensor(idx, dtype=torch.long) for p, idx in p_idx.items()}
        self._device_set = False

    def _ensure_device(self, device):
        if not self._device_set:
            self._idx_tensors = {p: t.to(device) for p, t in self._idx_tensors.items()}
            self._device_set = True

    def recon_loss(self, x, x_hat):
        self._ensure_device(x.device)
        loss = torch.tensor(0.0, device=x.device)
        for p, idx_t in self._idx_tensors.items():
            alpha = self.sens.get(p, 0.5)
            loss = loss + alpha * F.mse_loss(x_hat[:, idx_t], x[:, idx_t])
        return loss

    def contrastive_loss(self, z, labels):
        """Standard contrastive loss in latent space.

        The legacy implementation contrasted reconstruction residuals across
        55k input dimensions, while inference only used reconstruction error.
        Latent contrast keeps class structure in the encoder without allowing a
        high-cardinality perspective to dominate by dimension count.
        """
        bs = z.size(0)
        half = bs // 2
        if half < 1:
            return torch.tensor(0.0, device=z.device)
        is_same = (labels[:half] == labels[half: 2 * half]).float()
        diff = z[:half] - z[half: 2 * half]
        dist = torch.sqrt(diff.pow(2).mean(dim=1) + 1e-10)
        l_same = is_same * dist.pow(2)
        l_diff = (1 - is_same) * F.relu(self.margin - dist).pow(2)
        return (l_same + l_diff).mean()

    def forward(self, x, x_hat, z, labels):
        lr = self.recon_loss(x, x_hat)
        lc = self.contrastive_loss(z, labels)
        return lr + self.lam * lc, lr, lc


# ═══════════════════════════════════════════════════════════
# 5. Dataset (pair-based)
# ═══════════════════════════════════════════════════════════

class PairDataset(Dataset):
    def __init__(self, X, y, similar_ratio=0.25):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = np.asarray(y)
        self.sr = similar_ratio
        self.n = len(X)
        self.lab2idx = {}
        for i, l in enumerate(self.y):
            self.lab2idx.setdefault(int(l), []).append(i)

    def __len__(self):
        return self.n

    def __getitem__(self, i):
        y1 = int(self.y[i])
        if np.random.random() < self.sr:
            cands = self.lab2idx[y1]
        else:
            others = [l for l in self.lab2idx if l != y1]
            cands = self.lab2idx[others[np.random.randint(len(others))]] if others else list(range(self.n))
        j = cands[np.random.randint(len(cands))]
        if j == i and len(cands) > 1:
            j = cands[(cands.index(j) + 1 + np.random.randint(len(cands) - 1)) % len(cands)]
        return self.X[i], y1, self.X[j], int(self.y[j])


# ═══════════════════════════════════════════════════════════
# 6. Training
# ═══════════════════════════════════════════════════════════

def _seed_everything(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def _seed_worker(worker_id):
    worker_seed = torch.initial_seed() % (2**32)
    np.random.seed(worker_seed)
    random.seed(worker_seed)


def _macro_mean(values, labels):
    return float(np.mean([values[labels == label].mean() for label in np.unique(labels)]))


def train_model(X, y, p_idx, hidden_dims=(256, 128), latent_dim=32,
                lam=0.1, margin=1.0, lr=1e-3, bs=2048, epochs=100,
                sim_ratio=0.5, device="cpu", save_path=None,
                data_parallel=True, X_val=None, y_val=None,
                patience=15, seed=20260925, amp=True):
    _seed_everything(seed)
    model = PerspectiveAwareCAE(X.shape[1], hidden_dims, latent_dim).to(device)
    # Split each batch across all visible GPUs (8-card box). The loss is
    # computed outside the model on the gathered outputs, so DataParallel is
    # sufficient here (no cross-rank gradient sync needed beyond DP's own).
    if data_parallel and str(device).startswith("cuda") and torch.cuda.device_count() > 1:
        logger.info(f"DataParallel across {torch.cuda.device_count()} GPUs")
        model = torch.nn.DataParallel(model)
    crit = PerspectiveWeightedLoss(p_idx, DRIFT_SENSITIVITY, lam, margin)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, patience=5, factor=0.5)
    n_workers = int(os.environ.get("DRIFT_NUM_WORKERS", "8"))
    class_counts = np.bincount(np.asarray(y, dtype=np.int64))
    sample_weights = 1.0 / np.maximum(class_counts[np.asarray(y, dtype=np.int64)], 1)
    generator = torch.Generator().manual_seed(seed)
    sampler = WeightedRandomSampler(
        torch.as_tensor(sample_weights, dtype=torch.double),
        num_samples=len(y), replacement=True, generator=generator,
    )
    loader = DataLoader(PairDataset(X, y, sim_ratio), batch_size=bs, sampler=sampler,
                        drop_last=True, num_workers=n_workers,
                        persistent_workers=n_workers > 0, pin_memory=str(device).startswith("cuda"),
                        worker_init_fn=_seed_worker, generator=generator)

    best = float("inf")
    best_epoch = 0
    stale_epochs = 0
    history = []
    use_amp = bool(amp and str(device).startswith("cuda"))
    for ep in range(epochs):
        model.train()
        tot_l, tot_r, tot_c, nb = 0, 0, 0, 0
        for x1, y1, x2, y2 in loader:
            xb = torch.cat([x1, x2]).to(device, non_blocking=True)
            yb = torch.cat([y1, y2]).to(device, non_blocking=True)
            opt.zero_grad(set_to_none=True)
            with torch.autocast(
                device_type="cuda", dtype=torch.bfloat16, enabled=use_amp,
            ):
                xh, z = model(xb)
                loss, lr_, lc_ = crit(xb, xh, z, yb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            tot_l += loss.item(); tot_r += lr_.item(); tot_c += lc_.item(); nb += 1

        train_avg = tot_l / max(nb, 1)
        if X_val is not None and len(X_val):
            val_scores, _ = compute_drift_scores(
                model, X_val, p_idx, device, batch_size=max(bs, 8192)
            )
            metric = _macro_mean(val_scores, np.asarray(y_val))
        else:
            metric = train_avg
        sched.step(metric)
        row = {
            "epoch": ep + 1,
            "train_loss": train_avg,
            "train_recon": tot_r / max(nb, 1),
            "train_contrast": tot_c / max(nb, 1),
            "val_macro_score": metric if X_val is not None else None,
            "lr": opt.param_groups[0]["lr"],
        }
        history.append(row)
        logger.info(
            "Epoch %d/%d loss=%.6f recon=%.6f contrast=%.6f val_macro=%.6f lr=%.2e",
            ep + 1, epochs, row["train_loss"], row["train_recon"],
            row["train_contrast"], metric, row["lr"],
        )
        if metric < best - 1e-8:
            best = metric
            best_epoch = ep + 1
            stale_epochs = 0
            if save_path:
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                # Strip the DataParallel "module." prefix so the checkpoint
                # loads into a plain PerspectiveAwareCAE at inference time.
                state = (model.module if isinstance(model, torch.nn.DataParallel)
                         else model).state_dict()
                torch.save({"state": state, "dim": X.shape[1],
                            "hidden": list(hidden_dims), "latent": latent_dim,
                            "p_idx": p_idx, "best_epoch": best_epoch,
                            "best_val_macro_score": best}, save_path)
        else:
            stale_epochs += 1
            if patience and stale_epochs >= patience:
                logger.info("Early stopping at epoch %d (best=%d)", ep + 1, best_epoch)
                break

    if save_path and os.path.exists(save_path):
        ckpt = torch.load(save_path, map_location="cpu", weights_only=False)
        target = model.module if isinstance(model, torch.nn.DataParallel) else model
        target.load_state_dict(ckpt["state"])
    logger.info("Training done. Best validation metric=%.6f at epoch %d", best, best_epoch)
    return model, history


# ═══════════════════════════════════════════════════════════
# 7. Drift Scoring & Detection
# ═══════════════════════════════════════════════════════════

def compute_drift_scores(
    model, X, p_idx, device="cpu", batch_size=None, sensitivity=None,
):
    """Return (total_scores, per_perspective_scores).

    Scores are computed in device-sized batches: the full reference matrix is
    ~80 GB (361k x 55k float32), far beyond one GPU, so a single .to(device)
    would OOM. CPU keeps the old single-shot behaviour unless batch_size is set.
    """
    model.eval()
    sensitivity = sensitivity or DRIFT_SENSITIVITY
    n = len(X)
    if batch_size is None:
        batch_size = 8192
    # Accumulate per-chunk so peak memory stays batch-sized. Materialising the
    # full (n x dim) reconstruction error would need ~80 GB per copy for the
    # reference set and silently OOM-killed the process after training.
    p_scores = {p: np.zeros(n, dtype=np.float32) for p in p_idx}
    total = np.zeros(n, dtype=np.float64)
    with torch.no_grad():
        for start in range(0, n, batch_size):
            end = min(start + batch_size, n)
            xb = torch.from_numpy(np.asarray(X[start:end], dtype=np.float32)).to(
                device, non_blocking=True
            )
            xh, _ = model(xb)
            xb_np = xb.detach().float().cpu().numpy()
            xh_np = xh.detach().float().cpu().numpy()
            err = (xb_np - xh_np) ** 2
            for p, idx in p_idx.items():
                ps = err[:, idx].mean(axis=1)
                p_scores[p][start:end] = ps
                total[start:end] += sensitivity.get(p, 0.5) * ps
            del xb, xh, xb_np, xh_np, err
    return total, p_scores


def detect_drift(ref_scores, test_scores, mad_thr=3.5):
    med = np.median(ref_scores)
    mad = median_abs_deviation(ref_scores)
    mad = max(mad, 1e-10)
    thr = med + mad_thr * mad
    return test_scores > thr, thr, med, mad


def explain_drift(ref_ps, test_ps, p_idx, mad_thr=3.5):
    expl = {}
    for p in p_idx:
        ref, test = ref_ps[p], test_ps[p]
        med = np.median(ref)
        mad = max(median_abs_deviation(ref), 1e-10)
        zs = (test - med) / mad
        a = DRIFT_SENSITIVITY.get(p, 0.5)
        expl[p] = {
            "median_ref": float(med), "mad_ref": float(mad),
            "mean_test": float(test.mean()), "mean_z": float(zs.mean()),
            "drift_ratio": float((zs > mad_thr).mean()),
            "alpha": a, "contribution": float(a * zs.mean()),
        }
    return dict(sorted(expl.items(), key=lambda x: x[1]["contribution"], reverse=True))


# ═══════════════════════════════════════════════════════════
# 8. Single-Device Inference (在线检测: 对单个查询设备打分)
# ═══════════════════════════════════════════════════════════

class DriftDetector:
    """
    加载训练好的 PACA 模型与预处理产物, 对单个 (或一批) 查询设备做 in-class concept drift 检测.
    Load a trained PACA model + preprocessing artifacts and score a single (or a few)
    queried device(s) for in-class concept drift:

        S(x) = Σ_p α_p · (1/|C_p|) Σ_{k∈C_p} (x_k − x̂_k)²
        drift  ⟺  S(x) > τ_type

    v2 thresholds are device-type-conditional clean-calibration quantiles. An
    unknown/missing type falls back to the held-out global calibration quantile.

    与训练完全一致地复用参考集拟合的 vectorizers / scaler / 阈值, 因此可在
    decision 流程的 first-stage 中对「查询设备」进行判定, 无需重新训练.
    """

    def __init__(self, model_dir=DRIFT_OUTPUT_DIR, torch_device="cpu"):
        self.device = torch_device
        art_path = os.path.join(model_dir, "paca_artifacts.pkl")
        ckpt_path = os.path.join(model_dir, "paca_model.pt")
        if not os.path.exists(art_path) or not os.path.exists(ckpt_path):
            raise FileNotFoundError(
                f"Missing PACA artifacts/model in {model_dir}. "
                f"Run run_drift_detection() first to train and persist them."
            )

        self.art = joblib.load(art_path)
        ckpt = torch.load(ckpt_path, map_location=torch_device, weights_only=True)
        self.model = PerspectiveAwareCAE(ckpt["dim"], ckpt["hidden"], ckpt["latent"]).to(torch_device)
        self.model.load_state_dict(ckpt["state"])
        self.model.eval()

        self.p_idx = self.art["p_idx"]
        self.threshold = self.art["threshold"]
        self.class_thresholds = self.art.get("class_thresholds", {})
        self.mad_thr = self.art.get("mad_thr", 3.5)
        self.ref_ps = self.art.get("ref_ps", {})
        self.perspective_stats = self.art.get("perspective_stats", {})
        self.feature_backend = self.art.get("feature_backend", "legacy_tfidf_v1")
        default_sensitivity = (
            DRIFT_SENSITIVITY
            if self.feature_backend == FEATURE_BACKEND_HASH_V2
            else LEGACY_DRIFT_SENSITIVITY
        )
        self.sensitivity = self.art.get("drift_sensitivity", default_sensitivity)
        self.perspective_columns = self.art.get("perspective_columns")
        self.class_aliases = self.art.get(
            "class_aliases", {"SMART_HOME_CONTROLLER": "CONTROLLER"}
        )
        logger.info(
            "DriftDetector ready (backend=%s, global τ=%.4f, class thresholds=%d).",
            self.feature_backend, self.threshold, len(self.class_thresholds),
        )

    def _prepare(self, fingerprint):
        """Accept a dict or DataFrame; build the feature matrix using the SAME
        fitted vectorizers/scaler/columns as training, so dimensions align."""
        if isinstance(fingerprint, dict):
            df = pd.DataFrame([fingerprint])
        else:
            df = fingerprint.copy()
        for col in USE_COLS:
            if col not in df.columns:
                df[col] = np.nan
        if self.feature_backend == FEATURE_BACKEND_HASH_V2:
            X, p_idx = build_hashed_feature_matrix(
                df,
                hash_dim=int(self.art["hash_dim"]),
                max_field_chars=int(self.art["max_field_chars"]),
                max_field_tokens=int(self.art["max_field_tokens"]),
                perspective_columns=self.perspective_columns,
                log_progress=False,
            )
            if p_idx != self.p_idx:
                raise ValueError("Feature perspective layout differs from training artifacts")
            return X

        X, _, _, _ = build_feature_matrix(
            df, vectorizers=self.art["vectorizers"],
            cat_columns_map=self.art["cat_columns_map"], fit=False,
        )
        return self.art["scaler"].transform(X)

    def detect_query_device(self, fingerprint, device_type=None):
        """
        判定单个查询设备是否发生 in-class concept drift.
        Decide whether one queried device has drifted in-class.

        Args:
            fingerprint: 查询设备的原始特征 dict (列名与 USE_COLS 对齐即可).
                         Raw feature dict of the queried device.

        Returns:
            {
                "drift_score": float S(x),
                "threshold":   float τ,
                "is_drift":    bool  (S(x) > τ),
                "per_perspective_z": {p: z-score},   # 可解释性: 各视角偏移程度
                "drifted_perspectives": [p, ...],    # z > γ 的视角
            }
        """
        X_s = self._prepare(fingerprint)
        score, ps = compute_drift_scores(
            self.model, X_s, self.p_idx, self.device,
            sensitivity=self.sensitivity,
        )
        s_val = float(score[0])

        normalized_type = str(device_type or "").strip().upper()
        normalized_type = self.class_aliases.get(normalized_type, normalized_type)
        threshold = float(self.class_thresholds.get(normalized_type, self.threshold))
        threshold_scope = normalized_type if normalized_type in self.class_thresholds else "global"

        # 逐 perspective z-score (相对同类 calibration 集), 用于可解释的漂移归因
        # Per-perspective z-scores vs reference, for interpretable drift attribution
        per_z, drifted = {}, []
        scoped_stats = self.perspective_stats.get(
            normalized_type, self.perspective_stats.get("__global__", {})
        )
        for p in self.p_idx:
            test_ps = float(ps[p][0])
            if p in scoped_stats:
                med = float(scoped_stats[p]["median"])
                mad = float(max(scoped_stats[p]["mad"], 1e-10))
                z = (test_ps - med) / mad
            else:
                ref = self.ref_ps.get(p)
                if ref is not None and len(ref) > 0:
                    med = float(np.median(ref))
                    mad = float(max(median_abs_deviation(ref), 1e-10))
                    z = (test_ps - med) / mad
                else:
                    z = 0.0
            per_z[p] = z
            if z > self.mad_thr:
                drifted.append(p)

        return {
            "drift_score": s_val,
            "threshold": threshold,
            "threshold_scope": threshold_scope,
            "is_drift": bool(s_val > threshold),
            "per_perspective_z": dict(sorted(per_z.items(), key=lambda x: x[1], reverse=True)),
            "drifted_perspectives": drifted,
        }


# ═══════════════════════════════════════════════════════════
# 9. Full Pipeline
# ═══════════════════════════════════════════════════════════

def run_drift_detection(
    ref_csv_dir, test_csv_dir,
    device_types=None, vendor_col="vendor", type_col="device_type",
    hidden_dims=(128, 64), latent_dim=16,
    lam=1.0, margin=2.0, lr=1e-3, bs=64, epochs=100,
    sim_ratio=0.25, mad_thr=3.5,
    output_dir=DRIFT_OUTPUT_DIR, torch_device="cpu",
    load_model_path=None,
):
    if device_types is None:
        device_types = DEVICE_TYPES
    os.makedirs(output_dir, exist_ok=True)

    # ── Load reference ──
    logger.info("Loading reference data ...")
    ref_frames = []
    for dt in device_types:
        df = load_ipraw(dt, ipraw_dir=ref_csv_dir)
        if not df.empty:
            df["device_type"] = dt; ref_frames.append(df)
            logger.info(f"  {dt}: {len(df)}")
    if not ref_frames:
        logger.error("No reference data."); return
    ref_df = pd.concat(ref_frames, ignore_index=True)
    if vendor_col in ref_df.columns:
        ref_df["class_label"] = ref_df[type_col] + "-" + ref_df[vendor_col].fillna("UNK").astype(str)
    else:
        ref_df["class_label"] = ref_df[type_col]

    # ── Feature matrix ──
    logger.info("Building features ...")
    X_ref, p_idx, vecs, cmap = build_feature_matrix(ref_df.copy(), fit=True)
    le = LabelEncoder(); y_ref = le.fit_transform(ref_df["class_label"])
    scaler = StandardScaler(); X_ref_s = scaler.fit_transform(X_ref)
    logger.info(f"Ref: {X_ref_s.shape}  classes={len(le.classes_)}")

    # ── Train (or reuse an existing checkpoint) ──
    mpath = os.path.join(output_dir, "paca_model.pt")
    if load_model_path:
        logger.info(f"Loading pretrained model from {load_model_path} (skipping training)")
        ck = torch.load(load_model_path, map_location="cpu", weights_only=False)
        model = PerspectiveAwareCAE(ck["dim"], tuple(ck["hidden"]), ck["latent"])
        model.load_state_dict(ck["state"])
        model = model.to(torch_device)
        if str(torch_device).startswith("cuda") and torch.cuda.device_count() > 1:
            logger.info(f"DataParallel across {torch.cuda.device_count()} GPUs")
            model = torch.nn.DataParallel(model)
    else:
        model, _ = train_model(X_ref_s, y_ref, p_idx, hidden_dims, latent_dim,
                               lam, margin, lr, bs, epochs, sim_ratio,
                               torch_device, mpath)

    # ── Reference scores ──
    ref_scores, ref_ps = compute_drift_scores(model, X_ref_s, p_idx, torch_device)

    # ── Persist preprocessing artifacts + robust threshold for single-device inference ──
    #    A queried device can later be scored via detect_query_device() without re-training.
    #    保存预处理器与鲁棒阈值, 供后续对单个查询设备做在线检测 (无需重新训练).
    ref_med = float(np.median(ref_scores))
    ref_mad = float(max(median_abs_deviation(ref_scores), 1e-10))
    ref_thr = ref_med + mad_thr * ref_mad
    artifacts = {
        "vectorizers": vecs,
        "cat_columns_map": cmap,
        "scaler": scaler,
        "p_idx": p_idx,
        "ref_scores": ref_scores,
        "ref_ps": ref_ps,
        "median": ref_med,
        "mad": ref_mad,
        "mad_thr": mad_thr,
        "threshold": ref_thr,
    }
    joblib.dump(artifacts, os.path.join(output_dir, "paca_artifacts.pkl"))
    logger.info(f"Saved preprocessing artifacts + threshold (τ={ref_thr:.4f}) → paca_artifacts.pkl")

    # ── Load test ──
    logger.info("Loading test data ...")
    test_frames = []
    for dt in device_types:
        df = load_ipraw(dt, ipraw_dir=test_csv_dir)
        if not df.empty:
            df["device_type"] = dt; test_frames.append(df)
            logger.info(f"  {dt}: {len(df)}")
    if not test_frames:
        logger.error("No test data."); return
    test_df = pd.concat(test_frames, ignore_index=True)
    if vendor_col in test_df.columns:
        test_df["class_label"] = test_df[type_col] + "-" + test_df[vendor_col].fillna("UNK").astype(str)
    else:
        test_df["class_label"] = test_df[type_col]

    X_test, _, _, _ = build_feature_matrix(test_df.copy(), vecs, cmap, fit=False)
    X_test_s = scaler.transform(X_test)

    # ── Detect ──
    test_scores, test_ps = compute_drift_scores(model, X_test_s, p_idx, torch_device)
    is_drift, thr, med, mad = detect_drift(ref_scores, test_scores, mad_thr)
    nd = int(is_drift.sum())
    logger.info(f"Threshold={thr:.4f}  drifted={nd}/{len(test_scores)} ({100*nd/len(test_scores):.1f}%)")

    # ── Explain ──
    expl = explain_drift(ref_ps, test_ps, p_idx, mad_thr)

    # ── Save ──
    res = test_df[["ip", "device_type"]].copy()
    res["drift_score"] = test_scores; res["is_drift"] = is_drift.astype(int)
    for p in p_idx:
        res[f"score_{p}"] = test_ps[p]
    res.to_csv(os.path.join(output_dir, "drift_results.csv"), index=False)

    with open(os.path.join(output_dir, "drift_explanations.json"), "w", encoding="utf-8") as f:
        json.dump({"threshold": float(thr), "median": float(med), "mad": float(mad),
                    "n_drift": nd, "n_total": len(test_scores), "perspectives": expl},
                   f, indent=2, ensure_ascii=False)

    csm = res.groupby("device_type").agg(total=("is_drift", "count"), drifted=("is_drift", "sum"),
                                          mean_score=("drift_score", "mean")).reset_index()
    csm["drift_ratio"] = csm["drifted"] / csm["total"]
    csm.to_csv(os.path.join(output_dir, "class_drift_summary.csv"), index=False)

    print("\n" + "=" * 60)
    print("Perspective Drift Explanations (by weighted contribution):")
    print("=" * 60)
    for p, e in expl.items():
        print(f"  {p:15s}  α={e['alpha']:.1f}  z={e['mean_z']:.2f}  "
              f"drift={e['drift_ratio']:.1%}  contrib={e['contribution']:.3f}")

    logger.info("Done.")
    return model, res, expl


# ═══════════════════════════════════════════════════════
# 10. Leakage-safe v2 training/evaluation pipeline
# ═══════════════════════════════════════════════════════

def _threshold_for_rows(labels, class_thresholds, global_threshold):
    return np.asarray(
        [class_thresholds.get(str(label), global_threshold) for label in labels],
        dtype=np.float64,
    )


def calibrate_quantile_thresholds(scores, labels, quantile=0.99, min_class_size=30):
    """Calibrate a target clean false-positive rate on a held-out split."""
    scores = np.asarray(scores, dtype=np.float64)
    labels = np.asarray(labels, dtype=object)
    global_threshold = float(np.quantile(scores, quantile, method="higher"))
    class_thresholds = {}
    class_counts = {}
    for label in sorted(set(labels.tolist())):
        selected = scores[labels == label]
        class_counts[str(label)] = int(len(selected))
        if len(selected) >= min_class_size:
            class_thresholds[str(label)] = float(
                np.quantile(selected, quantile, method="higher")
            )
    return global_threshold, class_thresholds, class_counts


def _build_perspective_stats(p_scores, labels):
    labels = np.asarray(labels, dtype=object)
    groups = {"__global__": np.ones(len(labels), dtype=bool)}
    groups.update({str(label): labels == label for label in sorted(set(labels.tolist()))})
    stats = {}
    for group, mask in groups.items():
        stats[group] = {}
        for perspective, values in p_scores.items():
            selected = np.asarray(values)[mask]
            stats[group][perspective] = {
                "median": float(np.median(selected)),
                "mad": float(max(median_abs_deviation(selected), 1e-10)),
                "n": int(len(selected)),
            }
    return stats


def _evaluation_table(scores, labels, class_thresholds, global_threshold):
    labels = np.asarray(labels, dtype=object)
    thresholds = _threshold_for_rows(labels, class_thresholds, global_threshold)
    detected = np.asarray(scores) > thresholds
    rows = []
    for label in sorted(set(labels.tolist())):
        mask = labels == label
        rows.append({
            "device_type": str(label),
            "n": int(mask.sum()),
            "threshold": float(class_thresholds.get(str(label), global_threshold)),
            "mean_score": float(np.mean(np.asarray(scores)[mask])),
            "median_score": float(np.median(np.asarray(scores)[mask])),
            "clean_fpr": float(np.mean(detected[mask])),
            "threshold_scope": "class" if str(label) in class_thresholds else "global",
        })
    rows.append({
        "device_type": "__macro__",
        "n": int(len(labels)),
        "threshold": float(global_threshold),
        "mean_score": float(np.mean(scores)),
        "median_score": float(np.median(scores)),
        "clean_fpr": float(np.mean([r["clean_fpr"] for r in rows])),
        "threshold_scope": "mixed",
    })
    return pd.DataFrame(rows), detected, thresholds


def _synthetic_drift_evaluation(
    model, test_df, p_idx, class_thresholds, global_threshold,
    hash_dim, max_field_chars, max_field_tokens, device, seed, max_per_class=300,
):
    """Stress-test three controlled shift families; not a substitute for temporal labels."""
    rng = np.random.default_rng(seed)
    samples = []
    for _, group in test_df.groupby("device_type", sort=True):
        take = min(max_per_class, len(group))
        chosen = rng.choice(group.index.to_numpy(), size=take, replace=False)
        samples.append(test_df.loc[chosen])
    base = pd.concat(samples, ignore_index=True)
    scenarios = OrderedDict([
        ("network", [
            "as-asn", "as-name", "as-bgp_prefix", "as-country_code",
            "whois-network-handle", "whois-network-name",
            "whois-organization-handle", "whois-organization-name", "dns-reverse",
        ]),
        ("service", [
            "service-distribution", "http-bodys", "http-tags", "http-favicon-urls",
        ]),
        ("firmware", [
            "os-vendor", "os-product", "os-version", "sw-vendors", "sw-products",
            "sw-versions", "hw-vendors", "hw-products", "hw-versions",
            "cert-subjects", "cert-issuers", "tls-versions",
        ]),
    ])
    reports = []
    detail_frames = []
    for scenario, cols in scenarios.items():
        shifted = base.copy()
        for col in cols:
            shifted[col] = shifted[col].astype(object)
        for row_pos, row_idx in enumerate(shifted.index):
            marker = hashlib.blake2b(
                f"{seed}:{scenario}:{row_pos}".encode(), digest_size=8
            ).hexdigest()
            for col in cols:
                shifted.at[row_idx, col] = f"synthetic-{scenario}-{col}-{marker}"
        X_shift, shifted_idx = build_hashed_feature_matrix(
            shifted, hash_dim, max_field_chars, max_field_tokens
        )
        if shifted_idx != p_idx:
            raise RuntimeError("Synthetic evaluation feature layout mismatch")
        scores, _ = compute_drift_scores(
            model, X_shift, p_idx, device, batch_size=8192
        )
        labels = shifted["device_type"].astype(str).to_numpy()
        thresholds = _threshold_for_rows(labels, class_thresholds, global_threshold)
        detected = scores > thresholds
        for label in sorted(set(labels.tolist())):
            mask = labels == label
            reports.append({
                "scenario": scenario,
                "device_type": label,
                "n": int(mask.sum()),
                "synthetic_tpr": float(detected[mask].mean()),
                "mean_score": float(scores[mask].mean()),
            })
        detail_frames.append(pd.DataFrame({
            "ip": shifted["ip"].astype(str),
            "device_type": labels,
            "scenario": scenario,
            "drift_score": scores,
            "threshold": thresholds,
            "is_drift": detected.astype(np.int8),
        }))
    return pd.DataFrame(reports), pd.concat(detail_frames, ignore_index=True)


def _file_manifest(data_dir, device_types):
    manifest = []
    for device_type in device_types:
        path = os.path.join(data_dir, f"ipraw_{device_type}.csv")
        if os.path.exists(path):
            stat = os.stat(path)
            manifest.append({
                "path": os.path.abspath(path),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
            })
    return manifest


def run_drift_training_v2(
    data_dir,
    device_types=None,
    output_dir=None,
    hidden_dims=(256, 128),
    latent_dim=32,
    hash_dim=DEFAULT_HASH_DIM,
    max_field_chars=DEFAULT_MAX_FIELD_CHARS,
    max_field_tokens=DEFAULT_MAX_FIELD_TOKENS,
    lam=0.1,
    margin=1.0,
    lr=1e-3,
    bs=2048,
    epochs=100,
    sim_ratio=0.5,
    threshold_quantile=0.99,
    split_ratios=None,
    seed=20260925,
    patience=15,
    torch_device="cuda",
):
    """Train and evaluate PACA v2 with leakage-safe splits and class calibration."""
    device_types = list(device_types or DEVICE_TYPES)
    output_dir = output_dir or os.path.join(ROOT_DIR, "drift_data", "autoencoder_drift_v2")
    split_ratios = OrderedDict(split_ratios or DEFAULT_SPLIT_RATIOS)
    os.makedirs(output_dir, exist_ok=True)
    _seed_everything(seed)

    if str(torch_device).startswith("cuda"):
        if not torch.cuda.is_available():
            raise RuntimeError("CUDA requested but unavailable")
        logger.info("CUDA devices visible: %d", torch.cuda.device_count())

    frames = []
    source_counts = {}
    logger.info("Loading static fingerprint corpus from %s", data_dir)
    for device_type in device_types:
        frame = load_ipraw(device_type, ipraw_dir=data_dir)
        if frame.empty:
            logger.warning("No data for %s", device_type)
            continue
        frame["device_type"] = device_type
        frames.append(frame)
        source_counts[device_type] = int(len(frame))
        logger.info("  %-22s %d", device_type, len(frame))
    if not frames:
        raise RuntimeError("No training data found")
    df = pd.concat(frames, ignore_index=True)
    raw_rows = len(df)
    df, conflicts = remove_cross_type_ip_conflicts(df)
    logger.info(
        "Removed %d rows from %d cross-type IP groups",
        conflicts["removed_rows"], conflicts["conflicting_ips"],
    )

    df["split"] = assign_group_splits(df["ip"].astype(str), split_ratios, seed)
    required_splits = set(split_ratios)
    if set(df["split"].unique()) != required_splits:
        raise RuntimeError("At least one requested split is empty")
    split_ip_sets = {
        name: set(df.loc[df["split"] == name, "ip"].astype(str))
        for name in split_ratios
    }
    for left in split_ip_sets:
        for right in split_ip_sets:
            if left < right and split_ip_sets[left] & split_ip_sets[right]:
                raise RuntimeError(f"IP leakage between {left} and {right}")

    logger.info("Building bounded hashed features for %d cleaned rows", len(df))
    X, p_idx = build_hashed_feature_matrix(
        df, hash_dim, max_field_chars, max_field_tokens
    )
    encoder = LabelEncoder()
    y = encoder.fit_transform(df["device_type"].astype(str))
    masks = {name: (df["split"].to_numpy() == name) for name in split_ratios}
    mpath = os.path.join(output_dir, "paca_model.pt")
    model, history = train_model(
        X[masks["train"]], y[masks["train"]], p_idx,
        hidden_dims=hidden_dims, latent_dim=latent_dim, lam=lam, margin=margin,
        lr=lr, bs=bs, epochs=epochs, sim_ratio=sim_ratio,
        device=torch_device, save_path=mpath, data_parallel=True,
        X_val=X[masks["val"]], y_val=y[masks["val"]],
        patience=patience, seed=seed, amp=True,
    )

    calibration_df = df.loc[masks["calibration"]].copy()
    test_df = df.loc[masks["test"]].copy()
    calibration_scores, calibration_ps = compute_drift_scores(
        model, X[masks["calibration"]], p_idx, torch_device, batch_size=8192
    )
    test_scores, test_ps = compute_drift_scores(
        model, X[masks["test"]], p_idx, torch_device, batch_size=8192
    )
    calibration_labels = calibration_df["device_type"].astype(str).to_numpy()
    test_labels = test_df["device_type"].astype(str).to_numpy()
    global_threshold, class_thresholds, calibration_counts = calibrate_quantile_thresholds(
        calibration_scores, calibration_labels, threshold_quantile
    )
    perspective_stats = _build_perspective_stats(calibration_ps, calibration_labels)
    test_table, test_detected, test_thresholds = _evaluation_table(
        test_scores, test_labels, class_thresholds, global_threshold
    )

    artifacts = {
        "schema_version": 2,
        "feature_backend": FEATURE_BACKEND_HASH_V2,
        "hash_dim": int(hash_dim),
        "max_field_chars": int(max_field_chars),
        "max_field_tokens": int(max_field_tokens),
        "p_idx": p_idx,
        "threshold": global_threshold,
        "class_thresholds": class_thresholds,
        "threshold_quantile": float(threshold_quantile),
        "calibration_counts": calibration_counts,
        "perspective_stats": perspective_stats,
        "mad_thr": 3.5,
        "class_names": encoder.classes_.tolist(),
        "class_aliases": {"SMART_HOME_CONTROLLER": "CONTROLLER"},
        "drift_sensitivity": dict(DRIFT_SENSITIVITY),
        "perspective_columns": {
            name: list(entry["cols"])
            for name, entry in load_perspectives().items()
        },
    }
    art_tmp = os.path.join(output_dir, "paca_artifacts.pkl.tmp")
    joblib.dump(artifacts, art_tmp)
    os.replace(art_tmp, os.path.join(output_dir, "paca_artifacts.pkl"))

    test_result = test_df[["ip", "device_type", "split"]].reset_index(drop=True)
    test_result["drift_score"] = test_scores
    test_result["threshold"] = test_thresholds
    test_result["is_drift"] = test_detected.astype(np.int8)
    for perspective in p_idx:
        test_result[f"score_{perspective}"] = test_ps[perspective]
    test_result.to_csv(os.path.join(output_dir, "test_results.csv"), index=False)
    test_table.to_csv(os.path.join(output_dir, "clean_test_metrics.csv"), index=False)
    pd.DataFrame(history).to_csv(os.path.join(output_dir, "training_history.csv"), index=False)
    pd.DataFrame([
        {"device_type": key, "threshold": value,
         "calibration_n": calibration_counts.get(key, 0)}
        for key, value in sorted(class_thresholds.items())
    ]).to_csv(os.path.join(output_dir, "class_thresholds.csv"), index=False)

    synthetic_summary, synthetic_details = _synthetic_drift_evaluation(
        model, test_df, p_idx, class_thresholds, global_threshold,
        hash_dim, max_field_chars, max_field_tokens, torch_device, seed,
    )
    synthetic_summary.to_csv(
        os.path.join(output_dir, "synthetic_drift_metrics.csv"), index=False
    )
    synthetic_details.to_csv(
        os.path.join(output_dir, "synthetic_drift_results.csv"), index=False
    )

    split_counts = (
        df.groupby(["split", "device_type"]).size().unstack(fill_value=0).to_dict("index")
    )
    checkpoint = torch.load(mpath, map_location="cpu", weights_only=False)
    manifest = {
        "schema_version": 2,
        "created_at_unix": time.time(),
        "data_dir": os.path.abspath(data_dir),
        "source_files": _file_manifest(data_dir, device_types),
        "source_counts": source_counts,
        "raw_rows": int(raw_rows),
        "cleaned_rows": int(len(df)),
        "conflicts": conflicts,
        "split_ratios": dict(split_ratios),
        "split_counts": split_counts,
        "split_unique_ips": {k: len(v) for k, v in split_ip_sets.items()},
        "split_ip_overlap_verified_zero": True,
        "feature_backend": FEATURE_BACKEND_HASH_V2,
        "input_dim": int(X.shape[1]),
        "hash_dim_per_perspective": int(hash_dim),
        "perspectives": list(p_idx),
        "seed": int(seed),
        "training": {
            "hidden_dims": list(hidden_dims), "latent_dim": latent_dim,
            "lambda": lam, "margin": margin, "lr": lr, "batch_size": bs,
            "epochs_requested": epochs, "epochs_ran": len(history),
            "best_epoch": checkpoint.get("best_epoch"),
            "best_val_macro_score": checkpoint.get("best_val_macro_score"),
            "similar_pair_ratio": sim_ratio, "patience": patience,
            "data_parallel_gpu_count": torch.cuda.device_count()
                if str(torch_device).startswith("cuda") else 0,
        },
        "calibration": {
            "target_clean_fpr": 1.0 - threshold_quantile,
            "quantile": threshold_quantile,
            "global_threshold": global_threshold,
            "class_thresholds": class_thresholds,
        },
        "limitations": [
            "Static corpus has no temporal or real drift labels.",
            "Synthetic perturbation metrics are stress tests, not real-world TPR estimates.",
            "Ground-truth vendor labels are absent; calibration is device-type conditional.",
        ],
    }
    with open(os.path.join(output_dir, "training_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    # End-to-end parity check: persisted model+artifacts must reproduce the
    # in-memory best-checkpoint score and threshold selection exactly.
    detector = DriftDetector(output_dir, torch_device="cpu")
    parity_n = min(32, len(test_df))
    for offset in range(parity_n):
        row = test_df.iloc[offset]
        got = detector.detect_query_device(row.to_dict(), row["device_type"])
        if not np.isclose(got["drift_score"], test_scores[offset], rtol=1e-5, atol=1e-6):
            raise RuntimeError("Persisted model/artifact score parity check failed")
        if not np.isclose(got["threshold"], test_thresholds[offset], rtol=0, atol=1e-12):
            raise RuntimeError("Persisted class-threshold parity check failed")

    logger.info(
        "PACA v2 complete: rows=%d input_dim=%d global_thr=%.6f macro_clean_fpr=%.4f",
        len(df), X.shape[1], global_threshold,
        float(test_table.loc[test_table.device_type == "__macro__", "clean_fpr"].iloc[0]),
    )
    return model, manifest, test_table, synthetic_summary


# ═══════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Leakage-safe PACA v2 drift training")
    ap.add_argument("--data_dir", default=RAG_DATA_DIR)
    ap.add_argument(
        "--output_dir",
        default=os.path.join(ROOT_DIR, "drift_data", "autoencoder_drift_v2"),
    )
    ap.add_argument("--device_types", nargs="+", default=DEVICE_TYPES)
    ap.add_argument("--hidden", type=int, nargs="+", default=[256, 128])
    ap.add_argument("--latent", type=int, default=32)
    ap.add_argument("--hash_dim", type=int, default=DEFAULT_HASH_DIM)
    ap.add_argument("--max_field_chars", type=int, default=DEFAULT_MAX_FIELD_CHARS)
    ap.add_argument("--max_field_tokens", type=int, default=DEFAULT_MAX_FIELD_TOKENS)
    ap.add_argument("--lam", type=float, default=0.1)
    ap.add_argument("--margin", type=float, default=1.0)
    ap.add_argument("--lr",        type=float, default=1e-3)
    ap.add_argument("--bs",        type=int, default=2048)
    ap.add_argument("--epochs",    type=int, default=100)
    ap.add_argument("--sim_ratio", type=float, default=0.5)
    ap.add_argument("--threshold_quantile", type=float, default=0.99)
    ap.add_argument("--patience", type=int, default=15)
    ap.add_argument("--seed", type=int, default=20260925)
    ap.add_argument("--device", default="cuda")
    a = ap.parse_args()
    run_drift_training_v2(
        data_dir=a.data_dir, device_types=a.device_types, output_dir=a.output_dir,
        hidden_dims=tuple(a.hidden), latent_dim=a.latent, hash_dim=a.hash_dim,
        max_field_chars=a.max_field_chars, max_field_tokens=a.max_field_tokens,
        lam=a.lam, margin=a.margin, lr=a.lr, bs=a.bs, epochs=a.epochs,
        sim_ratio=a.sim_ratio, threshold_quantile=a.threshold_quantile,
        seed=a.seed, patience=a.patience, torch_device=a.device,
    )
