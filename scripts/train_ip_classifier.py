"""
Train an IP threat classifier and export to ONNX.

Uses Guardian's own production data:
  - Positive class: IPs that appear in blocked_ips or in high/critical incidents
  - Negative class: IPs with only low/info events, never blocked, never in serious incidents

Features (must match src/intelligence/ip-features.ts FEATURE_ORDER byte-for-byte):
  totalEvents, distinctEventTypes, ratioHighCritical,
  hasBruteForce, hasLateralMovement, hasCryptoMining, hasProxyScanner,
  distinctPorts, distinctServers, eventsPerHour, hourEntropy,
  hadSuccess, wasRateLimited, wasEscalated, maxIncidentSeverity,
  abuseScore, totalReports, vtMalicious, usageTypeDatacenter

Usage:
    pip install scikit-learn skl2onnx onnxruntime numpy psycopg2-binary
    DATABASE_URL="postgresql://..." python3 scripts/train_ip_classifier.py

    # Or with the guardian .env file:
    export $(grep -v '#' .env | xargs)
    python3 scripts/train_ip_classifier.py
"""

from __future__ import annotations

import json
import math
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import psycopg2
import psycopg2.extras
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

REPO_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = REPO_ROOT / "models"

FEATURE_ORDER = [
    "totalEvents",
    "distinctEventTypes",
    "ratioHighCritical",
    "hasBruteForce",
    "hasLateralMovement",
    "hasCryptoMining",
    "hasProxyScanner",
    "distinctPorts",
    "distinctServers",
    "eventsPerHour",
    "hourEntropy",
    "hadSuccess",
    "wasRateLimited",
    "wasEscalated",
    "maxIncidentSeverity",
    "abuseScore",
    "totalReports",
    "vtMalicious",
    "usageTypeDatacenter",
]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def connect() -> psycopg2.extensions.connection:
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        print("ERROR: DATABASE_URL environment variable not set", file=sys.stderr)
        sys.exit(1)
    # Convert standard postgres:// to postgresql:// if needed
    if db_url.startswith("postgres://"):
        db_url = "postgresql://" + db_url[len("postgres://"):]
    return psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)


def count_entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


def extract_features(conn, ip: str, since: datetime) -> dict[str, float]:
    cur = conn.cursor()

    # ── Security events ───────────────────────────────────────────────────
    cur.execute("""
        SELECT event_type, severity, destination_port, server_id, timestamp
        FROM security_events
        WHERE source_ip = %s AND timestamp >= %s
    """, (ip, since))
    rows = cur.fetchall()

    if not rows:
        return {f: 0.0 for f in FEATURE_ORDER}

    total_events = len(rows)
    event_types = set()
    high_crit = 0
    has_brute = has_lateral = has_crypto = has_proxy = 0
    had_success = had_failure = 0
    ports = set()
    servers = set()
    hour_counts = [0] * 24
    timestamps = []

    for r in rows:
        et = r["event_type"] or ""
        sev = r["severity"] or "info"
        event_types.add(et)
        if sev in ("high", "critical"):
            high_crit += 1
        if et == "ssh_brute_force":
            has_brute = 1
        if et == "lateral_movement":
            has_lateral = 1
        if et == "crypto_mining":
            has_crypto = 1
        if et in ("proxy_scanner_burst", "proxy_scanner_detected"):
            has_proxy = 1
        if et in ("ssh_login_success", "ssh_key_login"):
            had_success = 1
        if et in ("ssh_failed_password", "ssh_invalid_user"):
            had_failure = 1
        if r["destination_port"]:
            ports.add(r["destination_port"])
        servers.add(r["server_id"])
        ts = r["timestamp"]
        if ts:
            timestamps.append(ts.timestamp())
            hour_counts[ts.hour] += 1

    if had_success and not had_failure:
        had_success = 0

    ratio_hc = high_crit / total_events if total_events else 0.0
    ts_range = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
    hours_active = max(1.0, ts_range / 3600)
    events_per_hour = total_events / hours_active
    hour_entropy = count_entropy(hour_counts)

    # ── Rate limits ───────────────────────────────────────────────────────
    cur.execute("""
        SELECT COUNT(*) AS cnt,
               COUNT(CASE WHEN escalated_at IS NOT NULL THEN 1 END) AS esc_cnt
        FROM rate_limited_ips WHERE ip = %s
    """, (ip,))
    rl = cur.fetchone()
    was_rate_limited = 1 if (rl and rl["cnt"] > 0) else 0
    was_escalated = 1 if (rl and rl["esc_cnt"] > 0) else 0

    # ── Incident severity ─────────────────────────────────────────────────
    cur.execute("""
        SELECT severity FROM soc_incidents
        WHERE source_ips::jsonb @> %s::jsonb
    """, (json.dumps([ip]),))
    inc_rows = cur.fetchall()
    max_inc_sev = max((SEVERITY_RANK.get(r["severity"], 0) for r in inc_rows), default=0)

    # ── Threat intel cache ────────────────────────────────────────────────
    cur.execute("""
        SELECT reputation_score, data FROM threat_intel_cache
        WHERE indicator = %s ORDER BY created_at DESC LIMIT 1
    """, (ip,))
    intel = cur.fetchone()
    abuse_score = int(intel["reputation_score"] or 0) if intel else 0
    intel_data = intel["data"] if intel else {}
    if isinstance(intel_data, str):
        intel_data = json.loads(intel_data)
    intel_data = intel_data or {}

    total_reports = int(intel_data.get("totalReports", 0))
    vt = intel_data.get("virusTotal") or {}
    vt_malicious = int(vt.get("malicious", 0))

    isp = (intel_data.get("isp") or "").lower()
    usage_type = (intel_data.get("usageType") or "").lower()
    datacenter = 1 if (
        "data center" in isp or "hosting" in isp or "transit" in isp or
        "data center" in usage_type or "hosting" in usage_type
    ) else 0

    return {
        "totalEvents": float(total_events),
        "distinctEventTypes": float(len(event_types)),
        "ratioHighCritical": ratio_hc,
        "hasBruteForce": float(has_brute),
        "hasLateralMovement": float(has_lateral),
        "hasCryptoMining": float(has_crypto),
        "hasProxyScanner": float(has_proxy),
        "distinctPorts": float(len(ports)),
        "distinctServers": float(len(servers)),
        "eventsPerHour": events_per_hour,
        "hourEntropy": hour_entropy,
        "hadSuccess": float(had_success),
        "wasRateLimited": float(was_rate_limited),
        "wasEscalated": float(was_escalated),
        "maxIncidentSeverity": float(max_inc_sev),
        "abuseScore": float(abuse_score),
        "totalReports": float(total_reports),
        "vtMalicious": float(vt_malicious),
        "usageTypeDatacenter": float(datacenter),
    }


def features_to_vector(f: dict[str, float]) -> np.ndarray:
    return np.array([f[k] for k in FEATURE_ORDER], dtype=np.float32)


def main() -> int:
    print("Connecting to database...", file=sys.stderr)
    conn = connect()
    cur = conn.cursor()
    since = datetime.utcnow() - timedelta(days=90)

    # ── Collect candidate IPs ─────────────────────────────────────────────
    print("Fetching active IPs (>=5 events in last 90 days)...", file=sys.stderr)
    cur.execute("""
        SELECT source_ip, COUNT(*) AS cnt
        FROM security_events
        WHERE source_ip IS NOT NULL AND source_ip != ''
          AND timestamp >= %s
          AND severity != 'info'
        GROUP BY source_ip
        HAVING COUNT(*) >= 5
        ORDER BY cnt DESC
        LIMIT 2000
    """, (since,))
    candidate_ips = [r["source_ip"] for r in cur.fetchall()]
    print(f"  Found {len(candidate_ips)} candidate IPs", file=sys.stderr)

    # ── Build label sets ──────────────────────────────────────────────────
    cur.execute("SELECT DISTINCT ip FROM blocked_ips")
    blocked_set = {r["ip"] for r in cur.fetchall()}

    cur.execute("""
        SELECT source_ips FROM soc_incidents
        WHERE severity IN ('high', 'critical')
    """)
    incident_ips: set[str] = set()
    for r in cur.fetchall():
        raw = r["source_ips"]
        if isinstance(raw, str):
            raw = json.loads(raw)
        if isinstance(raw, list):
            incident_ips.update(raw)

    cur.execute("SELECT ip FROM trusted_entities WHERE entity_type = 'ip'")
    trusted_set = {r["ip"] for r in cur.fetchall()}

    positive_set = blocked_set | incident_ips
    print(f"  Positive labels: {len(positive_set)} IPs (blocked + high/critical incidents)", file=sys.stderr)

    # ── Extract features ──────────────────────────────────────────────────
    X_list, y_list, ip_list = [], [], []
    skipped = 0

    for i, ip in enumerate(candidate_ips):
        if ip in trusted_set:
            continue
        if (i + 1) % 100 == 0:
            print(f"  Processing IP {i+1}/{len(candidate_ips)}...", file=sys.stderr)

        try:
            f = extract_features(conn, ip, since)
            vec = features_to_vector(f)
            label = 1 if ip in positive_set else 0

            # Skip IPs with zero events (shouldn't happen given HAVING >= 5)
            if f["totalEvents"] == 0:
                skipped += 1
                continue

            X_list.append(vec)
            y_list.append(label)
            ip_list.append(ip)
        except Exception as e:
            print(f"  Warning: failed to extract features for {ip}: {e}", file=sys.stderr)
            skipped += 1

    print(f"  Extracted features for {len(X_list)} IPs ({skipped} skipped)", file=sys.stderr)

    X = np.vstack(X_list)
    y = np.array(y_list, dtype=np.int64)

    pos_count = y.sum()
    neg_count = len(y) - pos_count
    print(f"  Class distribution: {pos_count} positive ({100*pos_count/len(y):.1f}%), {neg_count} negative", file=sys.stderr)

    if pos_count < 10:
        print("ERROR: Not enough positive examples (need >= 10). Collect more attack data first.", file=sys.stderr)
        return 1

    if neg_count < 10:
        print("ERROR: Not enough negative examples. Check event data.", file=sys.stderr)
        return 1

    # ── Train ─────────────────────────────────────────────────────────────
    print("\nTraining LogisticRegression...", file=sys.stderr)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # StandardScaler inside a pipeline — scaling is required for LogReg
    # (features have wildly different ranges: totalEvents 0-50000 vs booleans 0-1)
    clf = Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42, C=1.0)),
    ])
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("\nClassification report:", file=sys.stderr)
    print(classification_report(y_test, y_pred, target_names=["benign", "threat"]), file=sys.stderr)
    auc = roc_auc_score(y_test, y_proba)
    print(f"AUC: {auc:.4f}", file=sys.stderr)

    # Print top feature importances (LR coefficients after scaling)
    coefs = clf.named_steps["lr"].coef_[0]
    scale = clf.named_steps["scaler"].scale_
    abs_importance = np.abs(coefs / scale)
    ranked = sorted(zip(FEATURE_ORDER, abs_importance), key=lambda x: -x[1])
    print("\nTop feature importances:", file=sys.stderr)
    for fname, imp in ranked[:10]:
        print(f"  {fname:30s} {imp:.4f}", file=sys.stderr)

    # ── Export ONNX ───────────────────────────────────────────────────────
    print("\nExporting to ONNX...", file=sys.stderr)
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = MODELS_DIR / "ip_classifier.onnx"
    meta_path = MODELS_DIR / "ip_classifier.meta.json"

    initial_type = [("input", FloatTensorType([None, X.shape[1]]))]
    onnx_model = convert_sklearn(clf, initial_types=initial_type, target_opset=15)
    output_path.write_bytes(onnx_model.SerializeToString())

    meta = {
        "featureOrder": FEATURE_ORDER,
        "threshold": 0.6,
        "positiveLabel": 1,
        "trainedAt": datetime.utcnow().isoformat() + "Z",
        "auc": float(auc),
        "trainSize": int(len(X_train)),
        "testSize": int(len(X_test)),
        "posCount": int(pos_count),
        "negCount": int(neg_count),
    }
    meta_path.write_text(json.dumps(meta, indent=2))

    print(f"\nWrote {output_path}", file=sys.stderr)
    print(f"Wrote {meta_path}", file=sys.stderr)
    print(f"\nAUC: {auc:.4f} — copy models/ to the server and restart guardian", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
