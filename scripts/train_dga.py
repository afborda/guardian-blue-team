"""
Train a DGA (Domain Generation Algorithm) classifier and export to ONNX.

Dataset:
  - Legitimate: Tranco top-N (downloaded on first run, cached locally).
  - Malicious: synthetic DGAs generated from algorithms of three documented
    families — Conficker.C, Cryptolocker, Necurs. We don't ship a real
    ground-truth DGA dataset; the public ones (Netlab 360, DGArchive) are
    either gone or gated behind academic registration. Synthetic data
    generalizes worse than real samples but is fully reproducible.

Features: must match `src/intelligence/dga-features.ts` byte-for-byte. If
you change one, change the other and retrain.

Output:
  - models/dga.onnx          — sklearn LogisticRegression converted via skl2onnx
  - models/dga.meta.json     — bigram table, threshold, feature order

Usage:
    pip install scikit-learn skl2onnx onnxruntime numpy requests
    python scripts/train_dga.py --legit-count 10000 --dga-count 10000
"""

from __future__ import annotations

import argparse
import json
import math
import random
import string
import sys
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = REPO_ROOT / "models"
TRANCO_CACHE = MODELS_DIR / "tranco_top1m.csv"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

VOWELS = set("aeiouy")
DIGITS = set(string.digits)

# 27-character alphabet: a-z + '-'. Must match TS ALPHA_INDEX.
ALPHA = list(string.ascii_lowercase) + ["-"]
ALPHA_INDEX = {c: i for i, c in enumerate(ALPHA)}


# ───────────────────────────────────────────────────────────────────────────
# Feature extraction (mirror of src/intelligence/dga-features.ts)
# ───────────────────────────────────────────────────────────────────────────

FEATURE_ORDER = [
    "length",
    "entropy",
    "vowelRatio",
    "digitRatio",
    "hyphenRatio",
    "maxConsonantRun",
    "maxDigitRun",
    "charClasses",
    "bigramLL",
    "labelCount",
    "sldLength",
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def pick_sld(labels: list[str]) -> str:
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    candidates = labels[:-1]
    return max(candidates, key=len)


def bigram_log_likelihood(s: str, table: np.ndarray) -> float:
    """Mean log-prob of bigrams in s under English bigram distribution."""
    if len(s) < 2:
        return 0.0
    floor = float(table.min())
    total = 0.0
    count = 0
    for i in range(len(s) - 1):
        a = ALPHA_INDEX.get(s[i])
        b = ALPHA_INDEX.get(s[i + 1])
        if a is None or b is None:
            total += floor
        else:
            total += float(table[a, b])
        count += 1
    return total / count if count else 0.0


def extract_features(domain_raw: str, bigram_table: np.ndarray) -> dict[str, float]:
    domain = domain_raw.lower().rstrip(".")
    labels = domain.split(".")
    sld = pick_sld(labels)
    stripped = domain.replace(".", "")
    n = len(stripped) or 1

    vowels = digits = hyphens = lowers = 0
    max_cons_run = cur_cons_run = 0
    max_dig_run = cur_dig_run = 0

    for ch in stripped:
        is_digit = ch in DIGITS
        is_vowel = ch in VOWELS
        is_lower = "a" <= ch <= "z"
        is_hyphen = ch == "-"

        if is_vowel:
            vowels += 1
        if is_digit:
            digits += 1
            cur_dig_run += 1
            max_dig_run = max(max_dig_run, cur_dig_run)
        else:
            cur_dig_run = 0
        if is_hyphen:
            hyphens += 1
        if is_lower:
            lowers += 1

        if is_lower and not is_vowel:
            cur_cons_run += 1
            max_cons_run = max(max_cons_run, cur_cons_run)
        else:
            cur_cons_run = 0

    char_classes = (1 if lowers else 0) + (1 if digits else 0) + (1 if hyphens else 0)

    return {
        "length": float(len(stripped)),
        "entropy": shannon_entropy(stripped),
        "vowelRatio": vowels / n,
        "digitRatio": digits / n,
        "hyphenRatio": hyphens / n,
        "maxConsonantRun": float(max_cons_run),
        "maxDigitRun": float(max_dig_run),
        "charClasses": float(char_classes),
        "bigramLL": bigram_log_likelihood(sld, bigram_table),
        "labelCount": float(len(labels)),
        "sldLength": float(len(sld)),
    }


def features_to_vector(f: dict[str, float]) -> np.ndarray:
    return np.array([f[k] for k in FEATURE_ORDER], dtype=np.float32)


# ───────────────────────────────────────────────────────────────────────────
# Bigram table — built from the legitimate corpus
# ───────────────────────────────────────────────────────────────────────────

def build_bigram_table(domains: Iterable[str]) -> np.ndarray:
    """Build a 27×27 log-probability table from legit domains. Laplace
    smoothing keeps zero-count bigrams from blowing up the log."""
    counts = np.ones((27, 27), dtype=np.float64)  # +1 smoothing
    for d in domains:
        sld = pick_sld(d.lower().rstrip(".").split("."))
        for i in range(len(sld) - 1):
            a = ALPHA_INDEX.get(sld[i])
            b = ALPHA_INDEX.get(sld[i + 1])
            if a is not None and b is not None:
                counts[a, b] += 1
    # Row-normalize then log.
    row_sums = counts.sum(axis=1, keepdims=True)
    probs = counts / row_sums
    return np.log(probs).astype(np.float32)


# ───────────────────────────────────────────────────────────────────────────
# Tranco top-list (legitimate domains)
# ───────────────────────────────────────────────────────────────────────────

def fetch_tranco(limit: int) -> list[str]:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    if not TRANCO_CACHE.exists():
        print(f"Downloading Tranco top-1m from {TRANCO_URL}...", file=sys.stderr)
        with urllib.request.urlopen(TRANCO_URL) as resp:
            data = resp.read()
        with zipfile.ZipFile(BytesIO(data)) as zf:
            inner = next(n for n in zf.namelist() if n.endswith(".csv"))
            with zf.open(inner) as fh:
                TRANCO_CACHE.write_bytes(fh.read())
    domains = []
    with TRANCO_CACHE.open() as fh:
        for line in fh:
            _, domain = line.strip().split(",", 1)
            domains.append(domain)
            if len(domains) >= limit:
                break
    return domains


# ───────────────────────────────────────────────────────────────────────────
# Synthetic DGA generators
# ───────────────────────────────────────────────────────────────────────────

def gen_conficker(seed: int, count: int) -> list[str]:
    """Conficker.C-style: pseudo-random alpha strings, length 8-11, fixed TLDs."""
    rng = random.Random(seed)
    tlds = ["com", "net", "org", "info", "biz", "ws"]
    out = []
    for _ in range(count):
        ln = rng.randint(8, 11)
        s = "".join(rng.choice(string.ascii_lowercase) for _ in range(ln))
        out.append(f"{s}.{rng.choice(tlds)}")
    return out


def gen_cryptolocker(seed: int, count: int) -> list[str]:
    """Cryptolocker-style: 12-15 char domains using a/e/i/o/u distribution."""
    rng = random.Random(seed + 1)
    tlds = ["com", "net", "org", "co.uk", "info"]
    # Real Cryptolocker had skewed letter freq — mimic with a vowel-heavy alphabet.
    alphabet = "abcdefghijklmnopqrstuvwxyz" + "aeiou" * 2
    out = []
    for _ in range(count):
        ln = rng.randint(12, 15)
        s = "".join(rng.choice(alphabet) for _ in range(ln))
        out.append(f"{s}.{rng.choice(tlds)}")
    return out


def gen_necurs(seed: int, count: int) -> list[str]:
    """Necurs-style: variable length 7-21, mixes alpha + occasional digits."""
    rng = random.Random(seed + 2)
    tlds = ["com", "net", "biz", "ru", "pw", "xyz", "top"]
    out = []
    for _ in range(count):
        ln = rng.randint(7, 21)
        chars = []
        for _ in range(ln):
            if rng.random() < 0.05:
                chars.append(rng.choice(string.digits))
            else:
                chars.append(rng.choice(string.ascii_lowercase))
        out.append(f"{''.join(chars)}.{rng.choice(tlds)}")
    return out


def gen_synthetic_dga(count: int, seed: int = 42) -> list[str]:
    each = count // 3
    out = []
    out.extend(gen_conficker(seed, each))
    out.extend(gen_cryptolocker(seed, each))
    out.extend(gen_necurs(seed, count - 2 * each))
    random.Random(seed + 99).shuffle(out)
    return out


# ───────────────────────────────────────────────────────────────────────────
# Train + export
# ───────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--legit-count", type=int, default=10000)
    ap.add_argument("--dga-count", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", type=Path, default=MODELS_DIR / "dga.onnx")
    args = ap.parse_args()

    print("Loading legitimate domains (Tranco)...", file=sys.stderr)
    legit = fetch_tranco(args.legit_count)
    print(f"  loaded {len(legit)} legit domains", file=sys.stderr)

    print("Generating synthetic DGAs...", file=sys.stderr)
    dga = gen_synthetic_dga(args.dga_count, seed=args.seed)
    print(f"  generated {len(dga)} synthetic DGAs", file=sys.stderr)

    print("Building bigram table from legit corpus...", file=sys.stderr)
    bigram_table = build_bigram_table(legit)

    print("Extracting features...", file=sys.stderr)
    X_list, y_list = [], []
    for d in legit:
        X_list.append(features_to_vector(extract_features(d, bigram_table)))
        y_list.append(0)
    for d in dga:
        X_list.append(features_to_vector(extract_features(d, bigram_table)))
        y_list.append(1)
    X = np.vstack(X_list)
    y = np.array(y_list, dtype=np.int64)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.seed, stratify=y
    )

    print("Training LogisticRegression...", file=sys.stderr)
    clf = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=args.seed)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, y_pred, target_names=["legit", "dga"]), file=sys.stderr)
    print(f"AUC: {roc_auc_score(y_test, y_proba):.4f}", file=sys.stderr)

    # Export to ONNX.
    print("Exporting to ONNX...", file=sys.stderr)
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    initial_type = [("input", FloatTensorType([None, X.shape[1]]))]
    onnx_model = convert_sklearn(clf, initial_types=initial_type, target_opset=15)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(onnx_model.SerializeToString())

    meta_path = args.output.with_suffix(".meta.json")
    meta = {
        "bigramTable": bigram_table.flatten().tolist(),
        "threshold": 0.7,  # conservative — high precision over recall to limit FPs
        "featureOrder": FEATURE_ORDER,
        "trainedAt": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "positiveLabel": 1,
        "auc": float(roc_auc_score(y_test, y_proba)),
        "legitCount": len(legit),
        "dgaCount": len(dga),
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f"Wrote {args.output} and {meta_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
