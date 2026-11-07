#!/usr/bin/env python3
"""Push collection runs (raw data + enriched check results) of one or more companies to Elasticsearch.

Two indices with the same mapping, so the raw identity data can feed dashboards on its own and the baseline results stay separate:

  entra-raw   data_type raw and meta     the data pulled from the tenant (one document per object) and the collection log
  entra-sca   data_type enriched         the baseline check results and their summaries

Both are organised like this:

  data_type     data_category                 doc_type         what it is  (check_result also carries the test details:
                                                               description, remediation, impact, links, and the
                                                               affected objects with their count)
  ------------  ----------------------------  ---------------  ------------------------------------------------
  raw           <data set name>               record           one document per object pulled from Entra
                                                               (CA_Policies, Users, Groups, RoleAssignments, ...)
  enriched      <framework>                   check_result     one document per baseline check (Passed/Failed/Skipped)
  enriched      check_summary                 check_summary    counts per framework for the run
  meta          collection_log                collection_log   one document per data set: status, rows, error, duration

Every document carries the same timeline and ownership fields: "@timestamp" (when the data was collected; the same for
the whole run, so a run is one point on the timeline), "run_id", "batch_id", "company_id", "company_name", "tenant_id",
plus "checked_at" for enriched documents and "pushed_at". Raw records are stored in the "raw" field with the "flattened" type, so changing Graph schemas never
cause mapping explosions, and every key stays searchable (raw.conditions.users.includeUsers: "All").

Document IDs are deterministic (run + category + object), so pushing the same run twice overwrites instead of duplicating.

Connection settings (also read from the .env file): --es-url / ES_URL, --api-key / ES_API_KEY or --username / ES_USERNAME + ES_PASSWORD, --ca-certs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterator

import paths

INDEX_BODY: dict[str, Any] = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 1},
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "@timestamp": {"type": "date"},
            "run_id": {"type": "keyword"},
            "batch_id": {"type": "keyword"},
            "company_id": {"type": "keyword"},
            "company_name": {"type": "keyword"},
            "app": {"type": "keyword"},
            "tenant_id": {"type": "keyword"},
            "tenant_name": {"type": "keyword"},
            "tool_version": {"type": "keyword"},
            "auth_mode": {"type": "keyword"},
            "data_type": {"type": "keyword"},
            "data_category": {"type": "keyword"},
            "doc_type": {"type": "keyword"},
            "dataset": {"type": "keyword"},
            "record_id": {"type": "keyword"},
            "record_index": {"type": "integer"},
            "raw": {"type": "flattened"},
            "rule_id": {"type": "keyword"},
            "reference_id": {"type": "keyword"},
            "framework": {"type": "keyword"},
            "title": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
            "severity": {"type": "keyword"},
            "area": {"type": "keyword"},
            "nist": {"type": "keyword"},
            "outcome": {"type": "keyword"},
            "required_licence": {"type": "keyword"},
            "references": {"type": "keyword"},
            "origin": {"type": "keyword", "ignore_above": 512},
            "workloads": {"type": "keyword"},
            "count_pass": {"type": "integer"},
            "count_fail": {"type": "integer"},
            "count_not_assessable": {"type": "integer"},
            "count_not_applicable": {"type": "integer"},
            "score": {"type": "integer"},
            "status": {"type": "keyword"},
            "passed": {"type": "boolean"},
            "expected": {"type": "text"},
            "actual": {"type": "text"},
            "reason": {"type": "text"},
            "description": {"type": "text"},
            "remediation": {"type": "text"},
            "impact": {"type": "text"},
            "links": {"properties": {"text": {"type": "text"}, "url": {"type": "keyword", "ignore_above": 2048}}},
            "affected_count": {"type": "integer"},
            "affected": {"type": "keyword", "ignore_above": 512},
            "checked_at": {"type": "date"},
            "pushed_at": {"type": "date"},
            "count_total": {"type": "integer"},
            "count_passed": {"type": "integer"},
            "count_failed": {"type": "integer"},
            "count_skipped": {"type": "integer"},
            "endpoint": {"type": "keyword"},
            "rows": {"type": "integer"},
            "error": {"type": "text"},
            "duration_seconds": {"type": "float"},
        },
    },
}


def doc_id(*parts: Any) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def build_actions(run_dir: Path, raw_index: str, sca_index: str, include_raw: bool, include_enriched: bool) -> Iterator[dict]:
    manifest = load_json(run_dir / "manifest.json")
    run_id = manifest["run_id"]
    company_id = manifest.get("company_id") or "unknown"
    base = {
        "@timestamp": manifest["collected_at"],
        "run_id": run_id,
        "batch_id": manifest.get("batch_id"),
        "company_id": manifest.get("company_id"),
        "company_name": manifest.get("company_name"),
        "app": manifest.get("app"),
        "tenant_id": manifest.get("tenant_id"),
        "tenant_name": manifest.get("tenant_name"),
        "tool_version": manifest.get("tool_version"),
        "workloads": manifest.get("workloads"),
        "auth_mode": manifest.get("auth_mode"),
        "pushed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

    def action(doc: dict, *id_parts: Any) -> dict:
        body = {k: v for k, v in {**base, **doc}.items() if v is not None}
        index = sca_index if body.get("data_type") == "enriched" else raw_index
        return {"_op_type": "index", "_index": index, "_id": doc_id(company_id, run_id, *id_parts), "_source": body}

    # meta: what was collected in this run
    for entry in manifest.get("datasets", []):
        yield action({"data_type": "meta", "data_category": "collection_log", "doc_type": "collection_log",
                      "dataset": entry["dataset"], "endpoint": entry.get("endpoint"), "status": entry["status"],
                      "rows": entry.get("rows"), "error": entry.get("error") or None,
                      "duration_seconds": entry.get("duration_seconds")}, "collection_log", entry["dataset"])

    if include_raw:
        for f in sorted((run_dir / "raw").glob("*.json")):
            dataset = f.stem
            for i, rec in enumerate(load_json(f)):
                rid = rec.get("id") if isinstance(rec, dict) else None
                yield action({"data_type": "raw", "data_category": dataset, "doc_type": "record", "dataset": dataset,
                              "record_id": str(rid) if rid else f"{dataset}-{i}", "record_index": i, "raw": rec},
                             "raw", dataset, rid or i, i)

    if include_enriched:
        results_file = run_dir / "enriched" / "check_results.json"
        summary_file = run_dir / "enriched" / "check_summary.json"
        if not results_file.exists():
            sys.exit(f"{results_file} not found - run entra_checks.py first (or use --only raw)")
        results = load_json(results_file)
        checked_at = results.get("checked_at")
        for r in results["results"]:
            yield action({"data_type": "enriched", "data_category": r["framework"], "doc_type": "check_result",
                          "rule_id": r["rule_id"], "reference_id": r["reference_id"], "framework": r["framework"],
                          "title": r["title"], "severity": r["severity"], "status": r["status"],
                          "area": r.get("area"), "nist": r.get("nist") or None, "outcome": r.get("outcome"),
                          "required_licence": r.get("required_licence") or None, "references": r.get("references") or None, "origin": r.get("origin") or None,
                          "passed": True if r["status"] == "Passed" else False if r["status"] == "Failed" else None,
                          "expected": r["expected"], "actual": r["actual"] or None, "reason": r["reason"] or None,
                          "dataset": r["dataset"] or None, "checked_at": checked_at,
                          "description": (r.get("details") or {}).get("description"),
                          "remediation": (r.get("details") or {}).get("remediation"),
                          "impact": (r.get("details") or {}).get("impact"),
                          "links": (r.get("details") or {}).get("links") or None,
                          "affected_count": r.get("affected_count") if r["status"] == "Failed" else None,
                          "affected": r.get("affected") or None}, "check_result", r["rule_id"])
        if summary_file.exists():
            summary_doc = load_json(summary_file)
            for a in summary_doc.get("areas", []):
                yield action({"data_type": "enriched", "data_category": "check_summary", "doc_type": "area_summary", "area": a["area"],
                              "count_total": a["total"], "count_pass": a["pass"], "count_fail": a["fail"],
                              "count_not_assessable": a["not_assessable"], "count_not_applicable": a["not_applicable"],
                              "score": a["score"], "checked_at": checked_at}, "area_summary", a["area"])
            for s in summary_doc["summary"]:
                yield action({"data_type": "enriched", "data_category": "check_summary", "doc_type": "check_summary",
                              "framework": s["framework"], "count_total": s["total"], "count_passed": s["passed"],
                              "count_failed": s["failed"], "count_skipped": s["skipped"], "checked_at": checked_at},
                             "check_summary", s["framework"])


def run_dirs_from_args(args: argparse.Namespace) -> list[Path]:
    dirs = [Path(d) for d in (args.run_dir or [])]
    if args.last_run:
        last = Path(args.last_run) / "last_run.json"
        if not last.exists():
            sys.exit(f"{last} not found - run entra_collect.py first")
        dirs += [Path(r["run_dir"]) for r in load_json(last)["runs"] if r.get("status") == "ok"]
    if not dirs:
        sys.exit("give --run-dir (one or more run folders) or --last-run <output-dir>")
    return dirs


def connect(args: argparse.Namespace):
    from elasticsearch import Elasticsearch

    if not args.es_url:
        sys.exit("--es-url (or ES_URL) is required")
    kw: dict[str, Any] = {}
    if args.api_key:
        kw["api_key"] = args.api_key
    elif args.username:
        kw["basic_auth"] = (args.username, args.password or os.environ.get("ES_PASSWORD", ""))
    if args.ca_certs:
        kw["ca_certs"] = args.ca_certs
    if args.insecure:
        kw["verify_certs"] = False
    return Elasticsearch(args.es_url, request_timeout=120, **kw)


def main(argv=None) -> int:
    env_file = paths.env_file()
    if env_file.exists():  # ES_URL, ES_API_KEY ... may live in the same .env as the app secrets; real environment variables win
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.strip().partition("=")
            key = key.removeprefix("export ").strip()
            if sep and key and not key.startswith("#"):
                os.environ.setdefault(key, value.strip().strip("\"'"))
    env = os.environ.get
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", nargs="+", help="one or more run folders created by entra_collect.py (and checked by entra_checks.py)")
    ap.add_argument("--last-run", metavar="OUTPUT_DIR", help="push every company of the latest batch listed in OUTPUT_DIR/last_run.json")
    ap.add_argument("--raw-index", default=env("ES_RAW_INDEX", "entra-raw"), help="index for raw data and the collection log (default: entra-raw)")
    ap.add_argument("--sca-index", default=env("ES_SCA_INDEX", "entra-sca"), help="index for check results and summaries (default: entra-sca)")
    ap.add_argument("--only", choices=["all", "raw", "enriched"], default="all", help="what to push (default: all)")
    ap.add_argument("--es-url", default=env("ES_URL"))
    ap.add_argument("--api-key", default=env("ES_API_KEY"))
    ap.add_argument("--username", default=env("ES_USERNAME"))
    ap.add_argument("--password", default=env("ES_PASSWORD"))
    ap.add_argument("--ca-certs", default=env("ES_CA_CERTS"), help="CA certificate file for https")
    ap.add_argument("--insecure", action="store_true", help="do not verify the server certificate (testing only)")
    ap.add_argument("--no-create-index", action="store_true", help="do not create the index/mapping if it is missing")
    ap.add_argument("--batch-size", type=int, default=500)
    ap.add_argument("--dry-run", metavar="FILE", help="do not connect; write the bulk actions to FILE (NDJSON) instead")
    args = ap.parse_args(argv)

    run_dirs = run_dirs_from_args(args)

    def all_actions() -> Iterator[dict]:
        for run_dir in run_dirs:
            yield from build_actions(run_dir, args.raw_index, args.sca_index, args.only in ("all", "raw"), args.only in ("all", "enriched"))

    actions = all_actions()

    if args.dry_run:
        counts: dict[str, int] = {}
        with open(args.dry_run, "w", encoding="utf-8") as fh:
            for a in actions:
                fh.write(json.dumps({"index": {"_index": a["_index"], "_id": a["_id"]}}) + "\n")
                fh.write(json.dumps(a["_source"], ensure_ascii=False) + "\n")
                key = f"{a['_index']}/{a['_source'].get('company_id')}/{a['_source']['data_category']}"
                counts[key] = counts.get(key, 0) + 1
        for k in sorted(counts):
            print(f"{k:<75}{counts[k]:>7}")
        print(f"\nDry run: {sum(counts.values())} documents written to {args.dry_run}")
        return 0

    from elasticsearch import helpers

    client = connect(args)
    if not args.no_create_index:
        for index in dict.fromkeys((args.raw_index, args.sca_index)):
            if not client.indices.exists(index=index):
                client.indices.create(index=index, settings=INDEX_BODY["settings"], mappings=INDEX_BODY["mappings"])
                print(f"Created index {index}")
            else:  # additive: adds fields introduced by newer versions of this script to an existing index
                client.indices.put_mapping(index=index, properties=INDEX_BODY["mappings"]["properties"])
    ok, errors = helpers.bulk(client, actions, chunk_size=args.batch_size, max_chunk_bytes=10 * 1024 * 1024,
                              raise_on_error=False, stats_only=False)
    print(f"Indexed {ok} documents into {args.raw_index} / {args.sca_index}")
    if errors:
        print(f"{len(errors)} documents failed; first error:\n{json.dumps(errors[0], indent=2, default=str)[:1500]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
