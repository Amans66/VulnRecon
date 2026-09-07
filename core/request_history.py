"""
Thread-safe request/response history store.

Records all HTTP requests and responses for:
  - Finding validation (reproducing requests)
  - Evidence capture (request/response in reports)
  - HAR export
  - Deduplication
"""

import uuid
import hashlib
import threading
import time
from collections import deque
from datetime import datetime, timezone


class RequestHistory:
    """Thread-safe circular buffer storing request/response pairs."""

    MAX_ENTRIES = 10000

    def __init__(self):
        self._entries = deque(maxlen=self.MAX_ENTRIES)
        self._index = {}  # request_id -> position
        self._lock = threading.Lock()

    def record(self, method, url, headers=None, body=None,
               response_status=0, response_headers=None,
               response_body_snippet="", elapsed=0.0):
        """
        Record a request/response pair.
        Returns: request_id (str)
        """
        request_id = uuid.uuid4().hex[:12]
        entry = {
            "id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method.upper(),
            "url": url,
            "request_headers": dict(headers) if headers else {},
            "request_body": str(body)[:2000] if body else "",
            "response_status": response_status,
            "response_headers": dict(response_headers) if response_headers else {},
            "response_body_snippet": str(response_body_snippet)[:2000],
            "response_body_hash": hashlib.md5(
                str(response_body_snippet).encode(errors='ignore')
            ).hexdigest() if response_body_snippet else "",
            "elapsed": round(elapsed, 4),
        }

        with self._lock:
            self._entries.append(entry)
            self._index[request_id] = entry

        return request_id

    def get(self, request_id):
        """Get a request/response record by ID."""
        with self._lock:
            return self._index.get(request_id)

    def query(self, url=None, method=None, status=None, param=None):
        """
        Query history with optional filters.
        Returns: List of matching entries.
        """
        with self._lock:
            results = list(self._entries)

        if url:
            results = [e for e in results if url in e["url"]]
        if method:
            results = [e for e in results if e["method"] == method.upper()]
        if status:
            results = [e for e in results if e["response_status"] == status]
        if param:
            results = [e for e in results
                       if param in e["url"] or param in e.get("request_body", "")]

        return results

    def get_for_url(self, url):
        """Get all request/response records for a specific URL."""
        return self.query(url=url)

    def size(self):
        """Number of recorded entries."""
        with self._lock:
            return len(self._entries)

    def clear(self):
        """Clear all history."""
        with self._lock:
            self._entries.clear()
            self._index.clear()

    def get_all(self):
        """Return all entries as a list."""
        with self._lock:
            return list(self._entries)

    def export_har(self):
        """Export history in HAR (HTTP Archive) 1.2 format."""
        with self._lock:
            entries_copy = list(self._entries)

        har_entries = []
        for entry in entries_copy:
            har_entry = {
                "startedDateTime": entry["timestamp"],
                "time": int(entry["elapsed"] * 1000),
                "request": {
                    "method": entry["method"],
                    "url": entry["url"],
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in entry["request_headers"].items()
                    ],
                    "queryString": [],
                    "bodySize": len(entry.get("request_body", "")),
                    "postData": {
                        "mimeType": "application/x-www-form-urlencoded",
                        "text": entry.get("request_body", ""),
                    } if entry.get("request_body") else {},
                },
                "response": {
                    "status": entry["response_status"],
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in entry.get("response_headers", {}).items()
                    ],
                    "content": {
                        "size": len(entry.get("response_body_snippet", "")),
                        "mimeType": entry.get("response_headers", {}).get(
                            "content-type", "text/html"
                        ),
                        "text": entry.get("response_body_snippet", ""),
                    },
                    "bodySize": len(entry.get("response_body_snippet", "")),
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": int(entry["elapsed"] * 1000),
                    "receive": 0,
                },
            }
            har_entries.append(har_entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "VulnerabilityScanner",
                    "version": "6.0",
                },
                "entries": har_entries,
            }
        }


# ── Singleton ──
request_history = RequestHistory()
