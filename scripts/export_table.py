#!/usr/bin/env python3
"""Export Guardian tables to CSV or Parquet.

Usage:
  python3 export_table.py <table> <format> <output_path> [--days N] [--date YYYY-MM-DD]

  table:  events | incidents | blocked_ips | server_metrics
  format: csv | parquet
  output_path: absolute path to write the file

Env vars:
  DATABASE_URL  postgres connection string (required)
"""

import sys
import os
import argparse
from datetime import datetime, timezone, timedelta

import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor

QUERIES = {
    'events': """
        SELECT
            id, server_id, timestamp, event_type, severity,
            source_ip, target_user, raw_log, metadata,
            created_at
        FROM events
        {where}
        ORDER BY timestamp DESC
    """,
    'incidents': """
        SELECT
            id, title, description, severity, status,
            source_ip, server_id, event_count,
            first_seen, last_seen, resolved_at, created_at
        FROM incidents
        {where}
        ORDER BY last_seen DESC
    """,
    'blocked_ips': """
        SELECT
            id, ip, reason, server_id, blocked_at,
            unblocked_at, verified, method, created_at
        FROM blocked_ips
        {where}
        ORDER BY blocked_at DESC
    """,
    'server_metrics': """
        SELECT
            id, server_id, timestamp,
            cpu_percent, mem_used_percent, mem_used_mb,
            disk_used_percent, load_avg_1m, load_avg_5m,
            network_rx_bps, network_tx_bps,
            open_connections, tcp_syn_recv
        FROM server_metrics
        {where}
        ORDER BY timestamp DESC
    """,
}

TIMESTAMP_COL = {
    'events': 'timestamp',
    'incidents': 'last_seen',
    'blocked_ips': 'blocked_at',
    'server_metrics': 'timestamp',
}


def build_where(table: str, days: int | None, date: str | None) -> tuple[str, list]:
    col = TIMESTAMP_COL[table]
    if date:
        # Exact day filter
        start = datetime.strptime(date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        return f'WHERE {col} >= %s AND {col} < %s', [start, end]
    if days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return f'WHERE {col} >= %s', [cutoff]
    return '', []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('table', choices=list(QUERIES.keys()))
    parser.add_argument('format', choices=['csv', 'parquet'])
    parser.add_argument('output_path')
    parser.add_argument('--days', type=int, default=None,
                        help='Export last N days (default: all)')
    parser.add_argument('--date', default=None,
                        help='Export specific day YYYY-MM-DD')
    args = parser.parse_args()

    db_url = os.environ.get('DATABASE_URL', '')
    if not db_url or db_url.startswith('sqlite:'):
        print('[export] ERROR: DATABASE_URL must be a PostgreSQL connection string', file=sys.stderr)
        sys.exit(1)

    # psycopg2 expects postgresql:// not postgres://
    if db_url.startswith('postgres://'):
        db_url = 'postgresql://' + db_url[len('postgres://'):]

    where_clause, params = build_where(args.table, args.days, args.date)
    query = QUERIES[args.table].format(where=where_clause)

    print(f'[export] connecting to database', file=sys.stderr)
    try:
        conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    except Exception as e:
        print(f'[export] ERROR connecting: {e}', file=sys.stderr)
        sys.exit(1)

    try:
        with conn.cursor() as cur:
            print(f'[export] querying {args.table}...', file=sys.stderr)
            cur.execute(query, params or None)
            rows = cur.fetchall()
    finally:
        conn.close()

    print(f'[export] {len(rows)} rows fetched', file=sys.stderr)

    if not rows:
        df = pd.DataFrame()
    else:
        df = pd.DataFrame(list(rows))

    print(f'[export] writing {args.format} to {args.output_path}', file=sys.stderr)

    if args.format == 'csv':
        df.to_csv(args.output_path, index=False)
    else:
        # Parquet: convert object columns that contain dicts/lists to JSON strings
        for col in df.columns:
            if df[col].dtype == object:
                df[col] = df[col].apply(
                    lambda v: str(v) if isinstance(v, (dict, list)) else v
                )
        df.to_parquet(args.output_path, index=False, engine='pyarrow', compression='snappy')

    size_kb = os.path.getsize(args.output_path) / 1024
    print(f'[export] done — {size_kb:.1f} KB', file=sys.stderr)


if __name__ == '__main__':
    main()
