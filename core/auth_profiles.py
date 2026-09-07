"""
Multi-profile authentication for authorized security testing.

Supports testing the same endpoints across different privilege levels
to detect IDOR, privilege escalation, and broken access control.

Credential data is NEVER written to logs, reports, or any output.
"""

import json
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AuthProfile:
    """Represents a single authentication context for testing."""
    name: str                               # e.g., "admin", "user1", "unauthenticated"
    role: str = "unauthenticated"           # "admin", "normal", "privileged", "unauthenticated"
    auth_type: str = "none"                 # "cookie", "bearer", "basic", "header", "none"
    credentials: Dict = field(default_factory=dict)   # {username, password} — NEVER logged
    session_cookies: Dict = field(default_factory=dict)  # {name: value}
    auth_headers: Dict = field(default_factory=dict)     # {header_name: value}
    is_authenticated: bool = False

    def __post_init__(self):
        self.is_authenticated = self.auth_type != "none"

    def __repr__(self):
        """NEVER expose credentials in repr."""
        return (f"AuthProfile(name='{self.name}', role='{self.role}', "
                f"auth_type='{self.auth_type}', authenticated={self.is_authenticated})")


class AuthProfileManager:
    """Manages authentication profiles and executes authenticated requests."""

    def __init__(self):
        self._profiles: Dict[str, AuthProfile] = {}
        self._lock = threading.Lock()

        # Always include unauthenticated profile
        self.add_profile(AuthProfile(
            name="unauthenticated",
            role="unauthenticated",
            auth_type="none",
        ))

    def add_profile(self, profile: AuthProfile):
        """Register an authentication profile."""
        with self._lock:
            self._profiles[profile.name] = profile

    def get_profile(self, name: str) -> Optional[AuthProfile]:
        """Get a profile by name."""
        with self._lock:
            return self._profiles.get(name)

    def get_all(self) -> List[AuthProfile]:
        """Return all registered profiles."""
        with self._lock:
            return list(self._profiles.values())

    def get_authenticated(self) -> List[AuthProfile]:
        """Return only authenticated profiles."""
        with self._lock:
            return [p for p in self._profiles.values() if p.is_authenticated]

    def load_from_file(self, path: str):
        """
        Load profiles from a JSON file.
        Format:
        {
          "profiles": [
            {"name": "user1", "role": "normal", "auth_type": "cookie",
             "session_cookies": {"session": "abc123"}},
            {"name": "admin", "role": "admin", "auth_type": "bearer",
             "auth_headers": {"Authorization": "Bearer xyz"}}
          ]
        }
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for entry in data.get("profiles", []):
                profile = AuthProfile(
                    name=entry.get("name", "unknown"),
                    role=entry.get("role", "normal"),
                    auth_type=entry.get("auth_type", "none"),
                    credentials=entry.get("credentials", {}),
                    session_cookies=entry.get("session_cookies", {}),
                    auth_headers=entry.get("auth_headers", {}),
                )
                self.add_profile(profile)

            return True
        except Exception as e:
            print(f"[!] Failed to load auth profiles from {path}: {e}")
            return False

    def _apply_auth(self, profile: AuthProfile, kwargs: dict) -> dict:
        """Apply authentication context to request kwargs."""
        kwargs = dict(kwargs)  # Don't mutate original

        # Apply cookies
        if profile.session_cookies:
            cookies = kwargs.get("cookies", {})
            cookies.update(profile.session_cookies)
            kwargs["cookies"] = cookies

        # Apply auth headers
        if profile.auth_headers:
            headers = kwargs.get("headers", {})
            headers.update(profile.auth_headers)
            kwargs["headers"] = headers

        # Apply basic auth
        if profile.auth_type == "basic" and profile.credentials:
            kwargs["auth"] = (
                profile.credentials.get("username", ""),
                profile.credentials.get("password", ""),
            )

        return kwargs

    def make_request(self, profile: AuthProfile, method: str, url: str, **kwargs):
        """
        Execute an HTTP request with the given profile's auth context.
        Uses core.http_client internally.
        """
        from core.http_client import get, post, head

        kwargs = self._apply_auth(profile, kwargs)

        method = method.upper()
        if method == "GET":
            return get(url, **kwargs)
        elif method == "POST":
            return post(url, **kwargs)
        elif method == "HEAD":
            return head(url, **kwargs)
        else:
            # Fallback to GET for unsupported methods
            return get(url, **kwargs)

    def compare_responses(self, url: str, method: str = "GET",
                          profiles: List[str] = None) -> dict:
        """
        Execute the same request across multiple profiles and compare responses.

        Returns dict with:
          - profile_results: {name: {status, body_hash, content_length, has_data}}
          - differences: list of detected differences
          - potential_issues: list of potential access control issues
        """
        target_profiles = []
        if profiles:
            for name in profiles:
                p = self.get_profile(name)
                if p:
                    target_profiles.append(p)
        else:
            target_profiles = self.get_all()

        if len(target_profiles) < 2:
            return {"profile_results": {}, "differences": [], "potential_issues": []}

        results = {}
        for profile in target_profiles:
            try:
                response = self.make_request(profile, method, url)
                body = response.text
                results[profile.name] = {
                    "status": response.status_code,
                    "body_hash": hashlib.md5(body.encode(errors='ignore')).hexdigest(),
                    "content_length": len(body),
                    "has_data": len(body) > 100 and response.status_code == 200,
                    "role": profile.role,
                }
            except Exception:
                results[profile.name] = {
                    "status": 0,
                    "body_hash": "",
                    "content_length": 0,
                    "has_data": False,
                    "role": profile.role,
                }

        # Analyze differences
        differences = []
        potential_issues = []
        unauth = results.get("unauthenticated", {})

        for name, data in results.items():
            if name == "unauthenticated":
                continue

            # If authenticated and unauthenticated get same response
            if unauth and data["body_hash"] == unauth.get("body_hash"):
                if data["status"] == 200 and unauth.get("status") == 200:
                    differences.append(
                        f"'{name}' ({data['role']}) gets same response as unauthenticated"
                    )

        # Check if low-privilege users can access same data as high-privilege
        admin_results = {k: v for k, v in results.items()
                         if v.get("role") in ("admin", "privileged")}
        normal_results = {k: v for k, v in results.items()
                          if v.get("role") == "normal"}

        for admin_name, admin_data in admin_results.items():
            for normal_name, normal_data in normal_results.items():
                if (admin_data["body_hash"] == normal_data["body_hash"]
                        and admin_data["has_data"]):
                    potential_issues.append(
                        f"'{normal_name}' (normal) gets same data as "
                        f"'{admin_name}' (admin) — possible privilege escalation"
                    )

        # Unauthenticated accessing protected resources
        if unauth.get("has_data"):
            for name, data in results.items():
                if name != "unauthenticated" and data.get("has_data"):
                    if unauth["body_hash"] == data["body_hash"]:
                        potential_issues.append(
                            f"Unauthenticated access returns same data as '{name}' "
                            f"({data['role']}) — possible broken access control"
                        )

        return {
            "profile_results": results,
            "differences": differences,
            "potential_issues": potential_issues,
        }

    def has_multiple_profiles(self) -> bool:
        """Check if multiple auth profiles are configured."""
        return len(self._profiles) > 1

    def summary(self) -> str:
        """Human-readable summary of configured profiles."""
        with self._lock:
            lines = [f"Auth Profiles ({len(self._profiles)}):"]
            for p in self._profiles.values():
                status = "✓ Authenticated" if p.is_authenticated else "○ Unauthenticated"
                lines.append(f"  [{p.role}] {p.name}: {status} ({p.auth_type})")
            return "\n".join(lines)
