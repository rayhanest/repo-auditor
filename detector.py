"""
detector.py — Detect package managers and languages from a cloned repo.

How it works:
  - Walks the repo directory looking for known lockfiles/manifest files.
  - Maps each file to its package manager.
  - Languages come from the GitHub API (handled in github_api.py), but we also
    detect them here as a fallback from file extensions.
"""

import os
from pathlib import Path

# Maps filename -> package manager name
PACKAGE_MANAGER_FILES = {
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "package.json": "npm/yarn/pnpm",
    "go.sum": "go modules",
    "go.mod": "go modules",
    "Cargo.lock": "cargo",
    "Cargo.toml": "cargo",
    "poetry.lock": "poetry",
    "Pipfile.lock": "pipenv",
    "requirements.txt": "pip",
    "setup.py": "pip",
    "pyproject.toml": "pip/poetry",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Gemfile.lock": "bundler",
    "Gemfile": "bundler",
    "composer.lock": "composer",
    "composer.json": "composer",
    "mix.lock": "mix",
    "pubspec.lock": "pub",
    "Package.resolved": "swift pm",
    "packages.config": "nuget",
    "Directory.Packages.props": "nuget",
    "*.csproj": "nuget",
}

# Maps file extension -> language (fallback if GitHub API unavailable)
EXTENSION_TO_LANGUAGE = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".swift": "Swift",
    ".ex": "Elixir",
    ".dart": "Dart",
    ".scala": "Scala",
}


def detect_package_managers(repo_path: str) -> list[str]:
    """
    Walk the repo and return a deduplicated list of package managers found.

    Only searches top 2 directory levels to stay fast.
    """
    found = set()
    repo = Path(repo_path)

    for root, dirs, files in os.walk(repo):
        # Skip hidden dirs and common non-source dirs
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in ("node_modules", "vendor", "dist", "build", "__pycache__")
        ]

        # Limit depth to 2 levels from repo root
        depth = len(Path(root).relative_to(repo).parts)
        if depth > 2:
            dirs.clear()
            continue

        for filename in files:
            if filename in PACKAGE_MANAGER_FILES:
                found.add(PACKAGE_MANAGER_FILES[filename])
            # Handle wildcard patterns (e.g., *.csproj)
            elif filename.endswith(".csproj"):
                found.add("nuget")

    # Deduplicate: if we found a lockfile, prefer the specific manager
    # e.g., if both "npm/yarn/pnpm" and "npm" are present, keep just "npm"
    specific = {pm for pm in found if "/" not in pm}
    generic = {pm for pm in found if "/" in pm}

    # Only keep generic entries if no specific one covers them
    for g in generic:
        options = set(g.split("/"))
        if not options & specific:
            # No specific match found — keep the generic entry
            specific.add(g)

    return sorted(specific)


def detect_languages_from_files(repo_path: str) -> list[str]:
    """
    Fallback language detection by scanning file extensions.

    Returns top languages found (by file count).
    """
    counts: dict[str, int] = {}
    repo = Path(repo_path)

    for root, dirs, files in os.walk(repo):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in ("node_modules", "vendor", "dist", "build", "__pycache__")
        ]

        # Limit depth
        depth = len(Path(root).relative_to(repo).parts)
        if depth > 3:
            dirs.clear()
            continue

        for filename in files:
            ext = Path(filename).suffix.lower()
            if ext in EXTENSION_TO_LANGUAGE:
                lang = EXTENSION_TO_LANGUAGE[ext]
                counts[lang] = counts.get(lang, 0) + 1

    # Return languages sorted by file count (most files first)
    sorted_langs = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [lang for lang, _ in sorted_langs]
