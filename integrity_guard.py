#!/usr/bin/env python3
"""integrity-guard — file integrity monitoring for critical directories.

Records a cryptographic baseline of a directory tree, then detects any file
that is later added, modified, deleted, or has its permissions or ownership
changed. This is the host-based detection layer that catches web shells
dropped into a webroot, tampering with system binaries, and unauthorised
configuration edits.

Standard library only.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

CHUNK_SIZE = 1024 * 1024  # hash in 1 MiB chunks so large files stay cheap

DEFAULT_EXCLUDES = [
    "*.log", "*.tmp", "*.swp", "*.pyc", "__pycache__/*",
    ".git/*", "node_modules/*", "*.sock", "*.pid",
]


@dataclass
class Change:
    kind: str          # added | modified | deleted | permissions | owner
    path: str
    detail: str


def file_digest(path: str) -> str:
    """SHA-256 of a file's contents, streamed so memory stays flat."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def is_excluded(relative_path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(relative_path, pattern) for pattern in patterns)


def snapshot(root: str, excludes: list[str], follow_symlinks: bool = False) -> dict:
    """Walk a tree and record hash, size, mode, and ownership for each file."""
    root = os.path.abspath(root)
    files: dict[str, dict] = {}
    skipped: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # Prune excluded directories so we never descend into them.
        dirnames[:] = [
            d for d in dirnames
            if not is_excluded(os.path.relpath(os.path.join(dirpath, d), root) + "/*",
                               excludes)
        ]
        for name in filenames:
            full = os.path.join(dirpath, name)
            relative = os.path.relpath(full, root)
            if is_excluded(relative, excludes):
                continue
            try:
                info = os.lstat(full)
                if stat.S_ISLNK(info.st_mode) and not follow_symlinks:
                    files[relative] = {
                        "sha256": "symlink:" + os.readlink(full),
                        "size": 0,
                        "mode": oct(stat.S_IMODE(info.st_mode)),
                        "uid": info.st_uid,
                        "gid": info.st_gid,
                    }
                    continue
                files[relative] = {
                    "sha256": file_digest(full),
                    "size": info.st_size,
                    "mode": oct(stat.S_IMODE(info.st_mode)),
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                }
            except (OSError, PermissionError) as exc:
                skipped.append(f"{relative}: {exc.strerror or exc}")

    return {
        "root": root,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "excludes": excludes,
        "file_count": len(files),
        "skipped": skipped,
        "files": files,
    }


def compare(baseline: dict, current: dict) -> list[Change]:
    """Diff two snapshots into a list of changes."""
    changes: list[Change] = []
    old_files = baseline["files"]
    new_files = current["files"]

    for path in sorted(set(new_files) - set(old_files)):
        changes.append(Change("added", path,
                              f"new file, {new_files[path]['size']} bytes"))

    for path in sorted(set(old_files) - set(new_files)):
        changes.append(Change("deleted", path, "file no longer present"))

    for path in sorted(set(old_files) & set(new_files)):
        old, new = old_files[path], new_files[path]
        if old["sha256"] != new["sha256"]:
            changes.append(Change(
                "modified", path,
                f"content changed ({old['size']} -> {new['size']} bytes)"))
        if old["mode"] != new["mode"]:
            changes.append(Change(
                "permissions", path, f"mode {old['mode']} -> {new['mode']}"))
        if old["uid"] != new["uid"] or old["gid"] != new["gid"]:
            changes.append(Change(
                "owner", path,
                f"owner {old['uid']}:{old['gid']} -> {new['uid']}:{new['gid']}"))

    return changes


# Changes ranked by how much they usually matter during an investigation.
SEVERITY = {
    "added": "high",        # a dropped web shell looks exactly like this
    "modified": "high",
    "deleted": "medium",
    "permissions": "medium",
    "owner": "medium",
}


def print_changes(changes: list[Change], baseline: dict, current: dict) -> None:
    print(f"\n  Baseline : {baseline['file_count']} files, "
          f"taken {baseline['created_at']}")
    print(f"  Current  : {current['file_count']} files")
    print(f"  Changes  : {len(changes)}\n")

    if not changes:
        print("  Integrity verified — no changes detected.\n")
        return

    for change in changes:
        severity = SEVERITY.get(change.kind, "low").upper()
        print(f"  [{severity:<6}] {change.kind:<12} {change.path}")
        print(f"           {change.detail}")
    print()


def load_baseline(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_baseline(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="File integrity monitoring for critical directories.")
    parser.add_argument("command", choices=["init", "check", "update"],
                        help="init: record a baseline | check: compare against it "
                             "| update: accept current state as the new baseline")
    parser.add_argument("directory", help="directory tree to monitor")
    parser.add_argument("-b", "--baseline", default="baseline.json",
                        help="baseline file path (default baseline.json)")
    parser.add_argument("-e", "--exclude", action="append", default=[],
                        help="glob to exclude; repeatable")
    parser.add_argument("--no-default-excludes", action="store_true",
                        help="do not apply the built-in exclude list")
    parser.add_argument("--follow-symlinks", action="store_true",
                        help="follow symbolic links while walking")
    parser.add_argument("-o", "--output", help="write the change report as JSON")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.directory):
        print(f"Not a directory: {args.directory}", file=sys.stderr)
        return 2

    excludes = list(args.exclude)
    if not args.no_default_excludes:
        excludes += DEFAULT_EXCLUDES

    if args.command == "init":
        data = snapshot(args.directory, excludes, args.follow_symlinks)
        save_baseline(data, args.baseline)
        print(f"\n  Baseline recorded: {data['file_count']} files -> "
              f"{args.baseline}")
        if data["skipped"]:
            print(f"  Skipped {len(data['skipped'])} unreadable path(s).")
        print()
        return 0

    try:
        baseline = load_baseline(args.baseline)
    except OSError:
        print(f"No baseline at {args.baseline}. Run 'init' first.",
              file=sys.stderr)
        return 2

    current = snapshot(args.directory, baseline.get("excludes", excludes),
                       args.follow_symlinks)
    changes = compare(baseline, current)
    print_changes(changes, baseline, current)

    if args.output:
        payload = {
            "checked_at": current["created_at"],
            "root": current["root"],
            "change_count": len(changes),
            "changes": [vars(c) for c in changes],
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"  Report written to {args.output}\n")

    if args.command == "update":
        save_baseline(current, args.baseline)
        print(f"  Baseline updated -> {args.baseline}\n")
        return 0

    # 'check' exits non-zero when the tree drifted, for cron and CI.
    return 1 if changes else 0


if __name__ == "__main__":
    raise SystemExit(main())
