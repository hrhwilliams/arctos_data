#!/usr/bin/env python3
"""Resumable, verified CSV import into a fresh Lupinus Elasticsearch index."""
import argparse
import concurrent.futures
import csv
import datetime
import fcntl
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import threading
import time

import requests

DATE_FORMAT = "strict_date_optional_time||yyyy-MM-dd||yyyy-MM||yyyy"
# Nested fields and event dates are built in transform() from the JSON columns.
FIELDS = {
    "guid": {"type": "keyword"},
    "guid_prefix": {"type": "keyword"},
    "type": {"type": "keyword"},
    "collection_object_id": {"type": "keyword"},
    "cataloged_item_type": {"type": "keyword"},
    "cat_num": {"type": "text"},
    "institution_acronym": {"type": "keyword"},
    "collection_cde": {"type": "keyword"},
    "relatedinformation": {"type": "text"},
    "parts": {"type": "keyword"},
    "has_tissue": {"type": "keyword"},
    "collectors": {"type": "keyword"},
    "identifiedby": {"type": "text"},
    "kingdom": {"type": "keyword"},
    "phylum": {"type": "keyword"},
    "family": {"type": "keyword"},
    "genus": {"type": "keyword"},
    "species": {"type": "keyword"},
    "subspecies": {"type": "keyword"},
    "scientific_name": {"type": "text"},
    "taxon_rank": {"type": "keyword"},
    "continent_ocean": {"type": "keyword"},
    "country": {"type": "keyword"},
    "state_prov": {"type": "keyword"},
    "county": {"type": "keyword"},
    "dec_lat": {"type": "float"},
    "dec_long": {"type": "float"},
    "datum": {"type": "text"},
    "coordinateuncertaintyinmeters": {"type": "float"},
    "year": {"type": "integer"},
    "month": {"type": "integer"},
    "day": {"type": "integer"},

    "events": {
        "type": "nested",
        "properties": {
            "specimen_event_id": {"type": "long", "ignore_malformed": True},
            "specimen_event_type": {"type": "keyword"},
            "synthesized": {"type": "boolean"},
            "began_date": {"type": "date", "format": DATE_FORMAT, "ignore_malformed": True},
            "ended_date": {"type": "date", "format": DATE_FORMAT, "ignore_malformed": True},
            "verbatim_date": {"type": "text", "index": False},
            "higher_geog": {"type": "text"},
            "habitat": {"type": "text"},
            "verificationstatus": {"type": "keyword"},
            "spec_locality": {"type": "text"},
            "locality_name": {"type": "text"},
            "locality_search_terms": {"type": "keyword", "normalizer": "lc"},
            "locality_id": {"type": "long", "ignore_malformed": True},
            "coordinates": {"type": "geo_point", "ignore_malformed": True},
            "coordinate_error_m": {"type": "float", "ignore_malformed": True},
            "collecting_method": {"type": "keyword"},
            "collecting_source": {"type": "keyword"},
        },
    },
    "event_date_min": {"type": "date", "format": DATE_FORMAT, "ignore_malformed": True},
    "event_date_max": {"type": "date", "format": DATE_FORMAT, "ignore_malformed": True},

    "detected": {"type": "keyword"},
    "not_detected": {"type": "keyword"},
    "examined_for": {"type": "keyword"},
    "not_examined_for": {"type": "keyword"},

    "attributedetail": {
        "type": "nested",
        "properties": {
            "attribute_type": {"type": "keyword", "normalizer": "lc"},
            "attribute_value": {"type": "keyword", "normalizer": "lc"},
            "attribute_method": {"type": "text", "fields": {"keyword": {"type": "keyword", "normalizer": "lc"}}},
            "attribute_remark": {"type": "text"},
            "attribute_determiner": {"type": "keyword", "normalizer": "lc"},
            "attribute_date": {"type": "date", "format": DATE_FORMAT, "ignore_malformed": True},
            "attribute_units": {"type": "keyword", "normalizer": "lc"},
        },
    },

    "partdetail": {
        "type": "nested",
        "properties": {
            "part_name": {"type": "keyword", "normalizer": "lc"},
            "disposition": {"type": "keyword", "normalizer": "lc"},
            "condition": {"type": "keyword", "normalizer": "lc"},
            "part_count": {"type": "integer", "ignore_malformed": True},
            "part_barcode": {"type": "keyword"},
            "container_path": {"type": "text"},
            "part_remark": {"type": "text"},
            "partID": {"type": "keyword", "index": False},
            "parentPartID": {"type": "keyword", "index": False},
            "part_attributes": {"type": "flattened"},
        },
    },

    "agents": {
        "type": "nested",
        "properties": {
            "agent_id": {"type": "keyword"},
            "agent_name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "agent_role": {"type": "keyword"},
            "agent_order": {"type": "integer", "ignore_malformed": True},
        },
    },

    "relations": {
        "type": "nested",
        "properties": {
            "relationship": {"type": "keyword"},
            "related_guid": {"type": "keyword"},
            "related_identifier": {"type": "keyword"},
            "related_identifier_type": {"type": "keyword"},
            "related_identification": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "related_geography": {"type": "text"},
            "related_phylum": {"type": "keyword", "normalizer": "lc"},
            "related_family": {"type": "keyword", "normalizer": "lc"},
            "related_genus": {"type": "keyword", "normalizer": "lc"},
            "related_species": {"type": "keyword", "normalizer": "lc"},
        },
    },
}
RETRY_STATUSES = {429, 502, 503, 504}
csv.field_size_limit(100_000_000)


def log(event, **fields):
    print(json.dumps({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "event": event, **fields}), flush=True)


def save_json(path, value):
    temp = Path(str(path) + ".tmp")
    with temp.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def add_ignore_above(props):
    """
    Adds ignore_above to (potentially nested) keywords
    """
    return {name: {**({"ignore_above": 8191} if spec["type"] == "keyword" else {}), **spec,
                   **({"properties": add_ignore_above(spec["properties"])} if "properties" in spec else {}),
                   **({"fields": add_ignore_above(spec["fields"])} if "fields" in spec else {})}
            for name, spec in props.items()}


def fingerprint(path):
    stat = path.stat()
    return {"path": str(path.resolve()), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def raw_json_to_nested(value):
    """
    Expands a raw JSON value into a list of dicts so that it can be parsed as
    a nested ES field
    """
    items = json.loads(value) if value and value.strip() else []
    return [item for item in (items if isinstance(items, list) else [items]) if isinstance(item, dict)]


def transform(row, types):
    # Keep every original column in _source; only explicitly mapped fields are indexed.
    doc = dict(row)
    corrections = {}
    doc["has_tissue"] = row.get("has_tissue") or row.get("has_tissues", "")
    doc["continent_ocean"] = row.get("continent_ocean") or row.get("continent") or row.get("ocean", "")
    for name, spec in FIELDS.items():
        kind = spec["type"]
        if name == "type" or name not in doc:
            continue
        value = (doc[name] or "").strip()
        if kind in ("integer", "float"):
            try:
                parsed = (int(value) if kind == "integer" else float(value)) if value else None
                if parsed is not None and (not math.isfinite(parsed) or
                        (kind == "integer" and not -2147483648 <= parsed <= 2147483647) or
                        (kind == "float" and abs(parsed) > 3.4028234663852886e38)):
                    raise ValueError("Numeric value outside mapped range")
                doc[name] = parsed
            except ValueError:
                doc[name] = None
                corrections[name] = value
        elif name == "collectors":
            doc[name] = [part.strip() for part in value.split(",") if part.strip()]
        else:
            doc[name] = value
    for name in ("detected", "not_detected", "examined_for", "not_examined_for"):
        if name in doc:
            doc[name] = [part.strip() for part in (doc[name] or "").split(";") if part.strip()]
    parsed, json_originals = {}, {}
    for column in ("partdetail", "attributedetail", "json_locality", "collector_agents", "related_record_cache"):
        try:
            parsed[column] = raw_json_to_nested(row.get(column))
        except ValueError:
            parsed[column] = []
            json_originals[column] = row[column]
    doc["partdetail"] = parsed["partdetail"]
    doc["attributedetail"] = parsed["attributedetail"]
    doc["events"] = parsed["json_locality"]
    began = [event["began_date"] for event in doc["events"] if event.get("began_date")]
    ended = [event["ended_date"] for event in doc["events"] if event.get("ended_date")]
    if began:
        doc["event_date_min"] = min(began)
    if ended:
        doc["event_date_max"] = max(ended)
    doc["agents"] = [{("agent_id" if key == "agent_identifier" else key): value for key, value in agent.items()}
                     for agent in parsed["collector_agents"]]
    if json_originals:
        doc["_csv_json_originals"] = json_originals
    if corrections:
        doc["_csv_numeric_originals"] = corrections
    if types.get(doc.get("guid_prefix")):
        doc["type"] = types[doc["guid_prefix"]]
    return doc


class API:
    def __init__(self, url, user, password, verify=True):
        self.url = url.rstrip("/")
        self.auth = (user, password)
        self.verify = verify
        self.local = threading.local()

    def request(self, method, path, *, body=None, raw=None, allowed=(), retry=True):
        if not hasattr(self.local, "session"):
            self.local.session = requests.Session()
            self.local.session.auth = self.auth
            self.local.session.verify = self.verify
        for attempt in range(8):
            try:
                headers = {"Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"} if raw is not None else {}
                response = self.local.session.request(method, self.url + path, json=body,
                    data=raw, headers=headers, timeout=(15, 180), allow_redirects=False)
                if response.status_code in RETRY_STATUSES and retry and attempt < 7:
                    log("retry_http", status=response.status_code, attempt=attempt + 1)
                    time.sleep(min(2 ** attempt, 30))
                    continue
                if response.status_code in allowed:
                    return None
                if not 200 <= response.status_code < 300:
                    raise RuntimeError(f"{method} {path}: HTTP {response.status_code}: {response.text[:800]}")
                return response.json() if response.content else {}
            except (requests.ConnectionError, requests.Timeout):
                if not retry or attempt == 7:
                    raise RuntimeError(f"{method} {path}: connection failed after retries") from None
                log("retry_connection", attempt=attempt + 1)
                time.sleep(min(2 ** attempt, 30))

    def bulk(self, payload, expected):
        packed = gzip.compress(payload, compresslevel=1)
        for attempt in range(8):
            result = self.request("POST", "/_bulk", raw=packed)
            items = result.get("items", [])
            if len(items) != expected:
                raise RuntimeError("Bulk response item count does not match request")
            failures = [item["index"] for item in items if item["index"]["status"] >= 300]
            permanent = [item for item in failures if item["status"] not in RETRY_STATUSES]
            if permanent:
                errors = [{"id": x.get("_id"), "status": x["status"], "error": x.get("error")} for x in permanent[:3]]
                raise RuntimeError("Bulk indexing failed: " + json.dumps(errors)[:1800])
            if not failures:
                return
            if attempt == 7:
                raise RuntimeError("Bulk item retries exhausted")
            log("retry_bulk", failed=len(failures), attempt=attempt + 1)
            time.sleep(min(2 ** attempt, 30))


def batches(path, state, types, index, max_rows, max_bytes):
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        header = next(csv.reader(iter(stream.readline, ""), strict=True))
        if len(header) != len(set(header)):
            raise RuntimeError("Duplicate CSV header names")
        if state["offset"]:
            stream.seek(state["offset"])
        reader = csv.DictReader(iter(stream.readline, ""), fieldnames=header, restkey="_extra", strict=True)
        rows = state["rows"]
        parts, byte_count, chunk_rows = [], 0, 0
        for row in reader:
            rows += 1
            if "_extra" in row or any(value is None for value in row.values()):
                raise RuntimeError(f"CSV column mismatch at data row {rows}")
            doc = transform(row, types)
            action = json.dumps({"index": {"_index": index, "_id": str(rows)}}, separators=(",", ":"))
            encoded = (action + "\n" + json.dumps(doc, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
            parts.append(encoded)
            byte_count += len(encoded)
            chunk_rows += 1
            if chunk_rows >= max_rows or byte_count >= max_bytes:
                yield b"".join(parts), chunk_rows, rows, stream.tell()
                parts, byte_count, chunk_rows = [], 0, 0
        if parts:
            yield b"".join(parts), chunk_rows, rows, stream.tell()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--url", default="https://huxley.bnhm.berkeley.edu:1113")
    parser.add_argument("--connect-url", help="Optional HTTPS transport URL for a verified SSH tunnel")
    parser.add_argument("--ca-cert", type=Path)
    parser.add_argument("--user", default="elastic")
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--index", required=True)
    parser.add_argument("--types", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--batch-rows", type=int, default=1000)
    parser.add_argument("--batch-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if not args.url.startswith("https://") or (args.connect_url and not args.connect_url.startswith("https://")):
        raise RuntimeError("An HTTPS endpoint is required")
    if args.workers < 1:
        raise RuntimeError("At least one worker required")
    source = fingerprint(args.csv)
    # An active decompressor has the file open for writing; do not load a partial input.
    for fd_dir in Path("/proc").glob("[0-9]*/fd"):
        try:
            if fd_dir.parent.stat().st_uid != os.getuid():
                continue
            for fd in fd_dir.iterdir():
                if fd.resolve() == args.csv.resolve():
                    info = (fd_dir.parent / "fdinfo" / fd.name).read_text()
                    flags = next(line.split()[1] for line in info.splitlines() if line.startswith("flags:"))
                    if int(flags, 8) & 3:
                        raise RuntimeError("CSV is still open for writing; wait for decompression to finish")
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue
    secret = None
    for line in args.env_file.read_text().splitlines():
        match = re.match(r"\s*(?:export\s+)?elastic\s*=\s*(.*?)\s*$", line)
        if match:
            secret = match.group(1)
            if len(secret) > 1 and secret[0] == secret[-1] and secret[0] in "\"'":
                secret = secret[1:-1]
            break
    if not secret:
        raise RuntimeError("The env file must define elastic with the Elasticsearch password")
    api = API(args.connect_url or args.url, args.user, secret, str(args.ca_cert) if args.ca_cert else True)
    info = api.request("GET", "/")
    log("connected", node=info.get("name"), cluster=info.get("cluster_name"), version=info.get("version", {}).get("number"))
    health = api.request("GET", "/_cluster/health")
    log("cluster_health", **health)
    disk = api.request("GET", "/_nodes/stats/fs?filter_path=nodes.*.name,nodes.*.fs.total")
    log("cluster_disk", stats=disk)
    if health.get("status") == "red":
        raise RuntimeError("Cluster health is red")
    types_bytes = args.types.read_bytes()
    types = json.loads(types_bytes)
    identity = {"source": source, "url": args.url.rstrip("/"), "index": args.index,
                "types_sha256": hashlib.sha256(types_bytes).hexdigest(), "schema_version": 1}
    existing = api.request("GET", "/" + args.index, allowed=(404,))
    public_index = api.request("GET", "/arctos", allowed=(404,))
    log("preflight", source=source, target_exists=existing is not None,
        arctos_exists=public_index is not None, mapped_fields=len(FIELDS), type_mappings=len(types))
    if args.preflight:
        return
    args.state.parent.mkdir(parents=True, exist_ok=True)
    lock = Path(str(args.state) + ".lock").open("w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if args.state.exists():
        state = json.loads(args.state.read_text())
        if state["identity"] != identity:
            raise RuntimeError("Source/config changed; cannot resume this checkpoint")
    else:
        if existing is not None:
            raise RuntimeError("Target index already exists without a checkpoint; refusing overwrite")
        state = {"identity": identity, "rows": 0, "offset": 0, "status": "prepared"}
        save_json(args.state, state)
    if existing is None:
        if state["rows"]:
            raise RuntimeError("Checkpoint target index is missing")
        props = add_ignore_above(FIELDS)
        api.request("PUT", "/" + args.index, body={
            "settings": {"analysis": {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}},
                         "number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "-1"},
            "mappings": {"dynamic": False, "_meta": {"arctos_csv_import": identity}, "properties": props}})
        log("index_created", index=args.index)
    elif existing[args.index].get("mappings", {}).get("_meta", {}).get("arctos_csv_import") != identity:
        raise RuntimeError("Index metadata does not match this import")
    if state.get("status") == "complete":
        log("already_complete", rows=state["rows"])
        return
    state.pop("error", None)
    state["status"] = "loading"
    save_json(args.state, state)
    start, start_rows, last_log = time.monotonic(), state["rows"], 0
    pending = []

    def commit(future, total, offset):
        nonlocal last_log
        future.result()
        if fingerprint(args.csv) != source:
            raise RuntimeError("Source CSV changed during import")
        state.update(rows=total, offset=offset)
        save_json(args.state, state)
        elapsed = time.monotonic() - start
        if elapsed - last_log >= 30 or last_log == 0:
            log("progress", rows=total, bytes_read=offset, source_bytes=source["size"],
                percent=round(100 * offset / source["size"], 2), rows_per_second=round((total - start_rows) / max(elapsed, 0.001), 1))
            last_log = elapsed

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            for payload, count, total, offset in batches(args.csv, state, types, args.index, args.batch_rows, args.batch_bytes):
                pending.append((pool.submit(api.bulk, payload, count), total, offset))
                if len(pending) >= args.workers:
                    commit(*pending.pop(0))
            for item in pending:
                commit(*item)
        if fingerprint(args.csv) != source:
            raise RuntimeError("Source CSV changed during import")
        try:
            api.request("PUT", "/" + args.index + "/_settings", body={"index": {"refresh_interval": "1s"}})
        except RuntimeError as error:
            if "HTTP 403:" not in str(error):
                raise
            log("settings_restore_required", reason="Apache proxy blocks PUT; restore refresh_interval through SSH")
        api.request("POST", "/" + args.index + "/_refresh")
        count = api.request("GET", "/" + args.index + "/_count")["count"]
        if count != state["rows"]:
            raise RuntimeError(f"Verification failed: {state['rows']} CSV rows but {count} indexed documents")
        sample = api.request("POST", "/" + args.index + "/_search", body={"size": 1, "_source": ["guid", "scientific_name", "guid_prefix", "type"]})
        if count and not sample.get("hits", {}).get("hits"):
            raise RuntimeError("Search verification failed")
        # Publish only when no pre-existing arctos index/alias would be changed.
        if api.request("GET", "/arctos", allowed=(404,)) is None:
            api.request("POST", "/_aliases", body={"actions": [{"add": {"index": args.index, "alias": "arctos"}}]})
            log("alias_created", alias="arctos", index=args.index)
        alias_count = api.request("GET", "/arctos/_count", allowed=(404,))
        state.update(status="complete", verified_count=count, arctos_count=alias_count,
                     completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        save_json(args.state, state)
        log("complete", index=args.index, rows=state["rows"], verified_count=count, arctos_count=alias_count)
    except BaseException as error:
        state.update(status="failed", error=str(error)[:2000])
        save_json(args.state, state)
        log("failed", error=str(error)[:2000], committed_rows=state["rows"])
        raise


if __name__ == "__main__":
    main()
