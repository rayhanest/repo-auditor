"""
cache.py — Simple file-based scan cache.

How it works:
  - Stores scan results as JSON files in a .audit-cache/ directory.
  - Each repo gets a file named {owner}__{repo}.json.
  - Cache entries expire after a configurable TTL (default: 24 hours).
  - If a cached result exists and isn't expired, it's reused instead of re-scanning.

Why:
  - Re-running the tool on the same list shouldn't re-clone and re-scan repos
    that were just audited. Saves time and API rate limits.
"""

import json
import time
from pathlib import Path

# Default cache directory (relative to where the tool is run)
CACHE_DIR = Path(".audit-cache")

# Default TTL: 24 hours in seconds
DEFAULT_TTL = 24 * 60 * 60


def _cache_path(owner: str, repo: str) -> Path:
    """Return the cache file path for a given repo."""
    return CACHE_DIR / f"{owner}__{repo}.json"


def get_cached_result(owner: str, repo: str, ttl: int = DEFAULT_TTL) -> dict | None:
    """
    Look up a cached scan result for the given repo.

    Args:
        owner: GitHub org/user (e.g., "docker")
        repo: Repository name (e.g., "compose")
        ttl: Time-to-live in seconds. Cache entries older than this are ignored.

    Returns:
        The cached result dict, or None if not found / expired.
    """
    path = _cache_path(owner, repo)

    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    # Check expiration
    cached_at = data.get("_cached_at", 0)
    if time.time() - cached_at > ttl:
        return None  # Expired

    return data


def save_result(owner: str, repo: str, result: dict) -> None:
    """
    Save a scan result to the cache.

    Adds a _cached_at timestamp to a copy before writing (does not mutate the input).
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    to_cache = {**result, "_cached_at": time.time()}
    path = _cache_path(owner, repo)

    try:
        path.write_text(json.dumps(to_cache, indent=2, default=str))
    except OSError as e:
        # Non-fatal — just skip caching
        print(f"  WARNING: Could not write cache for {owner}/{repo}: {e}")


def clear_cache() -> int:
    """
    Remove all cached results.

    Returns:
        Number of cache files removed.
    """
    if not CACHE_DIR.exists():
        return 0

    count = 0
    for f in CACHE_DIR.iterdir():
        if f.suffix == ".json":
            f.unlink()
            count += 1
    return count
