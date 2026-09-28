#!/usr/bin/env python3
"""
generate_registry.py - derives registry-v2.json and the PEP 503 simple/
index from the *verified* attestations of published releases in the builds
repo. Nothing in the output is typed by hand: an asset only appears if
  1. its Sigstore bundle verifies against the wheel's digest,
  2. it was signed by a workflow on the allowlist (generator-policy.json),
  3. every required predicate type verified, and
  4. the release contains the source archive the upstream-source predicate
     names (digest cross-checked when the API exposes it).
Everything recorded about the security model (policy_version, upstream
commit, ...) is read out of the verified predicate, not from tags or notes.

The trigger (schedule / dispatch / repository_dispatch) carries no trust;
it only says "look again". Already-verified assets are carried over from
the prior registry (whose own attestation the workflow checks first), so
only new assets are downloaded.
"""
import argparse
import base64
import email.parser
import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def gh(args, stdout=None):
    return subprocess.run(["gh", *args], text=True, stdout=stdout or subprocess.PIPE,
                          stderr=subprocess.PIPE)


def warn(msg):
    print(f"::warning::{msg}")


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_wheel(filename):
    """PEP 427 name -> dict, or None if it isn't a wheel name."""
    if not filename.endswith(".whl"):
        return None
    parts = filename[:-4].split("-")
    if len(parts) not in (5, 6):
        return None
    return {"name": normalize(parts[0]), "version": parts[1],
            "wheel_tag": "-".join(parts[-3:])}


def parse_revision(tag, version):
    """Release tag `<prefix>-v<version>[.postN]` -> N (0 if absent), or
    None if the tag doesn't match the wheel's own version. The version comes
    from the wheel, so an upstream `.post1` version is never confused with
    our revision suffix."""
    m = re.fullmatch(r".+-v" + re.escape(version) + r"(?:\.post(\d+))?", tag)
    if not m:
        return None
    return int(m.group(1) or 0)


def list_releases(repo):
    r = gh(["api", "--paginate", f"repos/{repo}/releases?per_page=100"])
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(f"could not list releases of {repo}")
    dec, s, i, out = json.JSONDecoder(), r.stdout, 0, []
    while i < len(s):
        while i < len(s) and s[i].isspace():
            i += 1
        if i >= len(s):
            break
        obj, i = dec.raw_decode(s, i)
        out.extend(obj if isinstance(obj, list) else [obj])
    return [x for x in out if not x.get("draft") and not x.get("prerelease")]


def download_asset(repo, asset, dest):
    with open(dest, "wb") as fh:
        r = gh(["api", "-H", "Accept: application/octet-stream",
                f"repos/{repo}/releases/assets/{asset['id']}"], stdout=fh)
    if r.returncode != 0:
        raise RuntimeError(f"download of {asset['name']} failed: {r.stderr}")


def walk_predicates(obj, ptype):
    if isinstance(obj, dict):
        if obj.get("predicateType") == ptype and isinstance(obj.get("predicate"), dict):
            yield obj["predicate"]
        for v in obj.values():
            yield from walk_predicates(v, ptype)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_predicates(v, ptype)


def predicate_from_bundle(bundle, ptype, sha):
    """Fallback if gh's JSON output has no predicate: read the DSSE payload
    of the bundle line(s) of this type whose subject is exactly this wheel.
    Only trusted when exactly one such statement exists."""
    found = []
    for line in bundle.read_text().splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)["dsseEnvelope"]["payload"]
            st = json.loads(base64.b64decode(payload))
        except (KeyError, ValueError):
            continue
        if st.get("predicateType") == ptype and any(
                s.get("digest", {}).get("sha256") == sha for s in st.get("subject", [])):
            found.append(st.get("predicate", {}))
    return found[0] if len(found) == 1 else None


REQUIRED_FIELDS = ("policy_version", "upstream_repo", "upstream_tag", "upstream_commit",
                   "snapshot_archive_name", "snapshot_archive_sha256")


def verify_asset(repo, wheel, bundle, sha, policy):
    """Returns (workflow_file, upstream_predicate, verified_predicate_types)
    or None. The type list is what actually passed verification here, not a
    copy of the policy file."""
    for wf in policy["workflows"]:
        signer = f"{repo}/.github/workflows/{wf}"
        upstream = None
        ok = True
        verified = []
        for pt in policy["required_predicates"]:
            r = gh(["attestation", "verify", str(wheel), "--bundle", str(bundle),
                    "--repo", repo, "--signer-workflow", signer,
                    "--predicate-type", pt, "--format", "json"])
            if r.returncode != 0:
                ok = False
                break
            verified.append(pt)
            if pt == policy["upstream_predicate"]:
                try:
                    upstream = next(walk_predicates(json.loads(r.stdout), pt), None)
                except ValueError:
                    upstream = None
                if upstream is None:
                    upstream = predicate_from_bundle(bundle, pt, sha)
        if ok and upstream and all(upstream.get(k) for k in REQUIRED_FIELDS):
            return wf, upstream, verified
    return None


def wheel_metadata(wheel):
    with zipfile.ZipFile(wheel) as z:
        meta = next((n for n in z.namelist()
                     if n.count("/") == 1 and n.endswith(".dist-info/METADATA")), None)
        if meta is None:
            return None
        return email.parser.Parser().parsestr(z.read(meta).decode("utf-8"), headersonly=True)


def process_release(repo, rel, prior_assets, policy, work, stats):
    tag = rel["tag_name"]
    assets = {a["name"]: a for a in rel.get("assets", [])}
    entries, revision = {}, None
    for name, asset in sorted(assets.items()):
        info = parse_wheel(name)
        if not info:
            continue
        rev = parse_revision(tag, info["version"])
        if rev is None:
            warn(f"{tag}: tag does not match wheel version {info['version']} ({name}) - skipped")
            continue
        digest = (asset.get("digest") or "").removeprefix("sha256:") or None
        prev = prior_assets.get(name)
        if prev and digest and prev.get("sha256") == digest:
            entries[name], revision = prev, rev
            stats["carried"] += 1
            continue

        bundle_asset = assets.get(f"{name}.attestations.jsonl")
        if not bundle_asset:
            warn(f"{tag}: {name} has no attestation bundle - not listed")
            stats["refused"] += 1
            continue
        wheel, bundle = work / name, work / f"{name}.attestations.jsonl"
        try:
            download_asset(repo, asset, wheel)
            download_asset(repo, bundle_asset, bundle)
            sha = sha256_file(wheel)
            if digest and sha != digest:
                warn(f"{tag}: {name} downloaded digest != release digest - not listed")
                stats["refused"] += 1
                continue
            result = verify_asset(repo, wheel, bundle, sha, policy)
            if not result:
                warn(f"{tag}: {name} failed attestation verification - not listed")
                stats["refused"] += 1
                continue
            wf, up, verified_types = result
            arch = assets.get(up["snapshot_archive_name"])
            if not arch:
                warn(f"{tag}: {name} source archive {up['snapshot_archive_name']} missing - not listed")
                stats["refused"] += 1
                continue
            arch_digest = (arch.get("digest") or "").removeprefix("sha256:")
            if arch_digest and arch_digest != up["snapshot_archive_sha256"]:
                warn(f"{tag}: {name} source archive digest != predicate - not listed")
                stats["refused"] += 1
                continue
            meta = wheel_metadata(wheel)
            if meta is None or (meta["Version"] or "").strip() != info["version"]:
                warn(f"{tag}: {name} METADATA version mismatch - not listed")
                stats["refused"] += 1
                continue
            entries[name] = {
                "name": info["name"],
                "version": info["version"],
                "wheel_tag": info["wheel_tag"],
                "sha256": sha,
                "requires_python": (meta["Requires-Python"] or "").strip() or None,
                "signer_workflow": f".github/workflows/{wf}",
                "provenance": {
                    "policy_version": up["policy_version"],
                    "predicate_types": verified_types,
                },
                "upstream": {"repo": up["upstream_repo"], "tag": up["upstream_tag"],
                             "commit": up["upstream_commit"]},
            }
            revision = rev
            stats["verified"] += 1
        except Exception as e:  # never let one bad asset sink the run
            warn(f"{tag}: {name}: {e} - not listed")
            stats["refused"] += 1
        finally:
            wheel.unlink(missing_ok=True)
            bundle.unlink(missing_ok=True)
    if not entries:
        return None
    return {"revision": revision, "assets": entries}


def build_registry(repo, policy, prior, work, only_tag):
    prior_assets = {}
    for tag, rel in (prior.get("releases") or {}).items():
        for n, a in rel.get("assets", {}).items():
            prior_assets[(tag, n)] = a
    stats = {"carried": 0, "verified": 0, "refused": 0}
    releases = {}
    for rel in list_releases(repo):
        tag = rel["tag_name"]
        if only_tag and tag != only_tag:
            continue
        per = {n: a for (t, n), a in prior_assets.items() if t == tag}
        out = process_release(repo, rel, per, policy, work, stats)
        if out:
            releases[tag] = out
    print(f"assets: carried={stats['carried']} verified={stats['verified']} refused={stats['refused']}")
    return {"schema": 2, "builds_repo": repo, "releases": releases}


def select_files(reg):
    """project -> filename -> (tag, entry). One file per filename: highest
    policy_version wins, then highest revision (date-prefixed policy strings
    sort correctly as plain strings)."""
    best = {}
    for tag, rel in reg["releases"].items():
        for fn, e in rel["assets"].items():
            key = (e["provenance"]["policy_version"], rel["revision"])
            cur = best.get((e["name"], fn))
            if cur is None or key > cur[0]:
                best[(e["name"], fn)] = (key, tag, e)
    projects = {}
    for (proj, fn), (_, tag, e) in best.items():
        projects.setdefault(proj, {})[fn] = (tag, e)
    return projects


def render_indexes(reg, simple_dir):
    repo = reg["builds_repo"]
    projects = select_files(reg)
    simple_dir.mkdir(parents=True, exist_ok=True)
    head = ('<!DOCTYPE html>\n<html><head><meta charset="utf-8">'
            '<meta name="pypi:repository-version" content="1.0">'
            '<title>{t}</title></head><body>\n<h1>{t}</h1>\n')
    root = head.format(t="python-wheels simple index")
    for proj in sorted(projects):
        root += f'<a href="{proj}/">{proj}</a><br>\n'
    (simple_dir / "index.html").write_text(root + "</body></html>\n")
    for proj, files in projects.items():
        page = head.format(t=html.escape(proj))
        for fn in sorted(files):
            tag, e = files[fn]
            url = f"https://github.com/{repo}/releases/download/{tag}/{fn}#sha256={e['sha256']}"
            rp = f' data-requires-python="{html.escape(e["requires_python"])}"' if e.get("requires_python") else ""
            page += f'<a href="{html.escape(url)}"{rp}>{html.escape(fn)}</a><br>\n'
        (simple_dir / proj).mkdir(exist_ok=True)
        (simple_dir / proj / "index.html").write_text(page + "</body></html>\n")
    for d in simple_dir.iterdir():
        if d.is_dir() and d.name not in projects and (d / "index.html").exists():
            print(f"removing stale index for {d.name}")
            shutil.rmtree(d)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--policy", default="generator-policy.json")
    p.add_argument("--registry", default="registry-v2.json")
    p.add_argument("--simple-dir", default="simple")
    p.add_argument("--work", default="/tmp/registry-work")
    p.add_argument("--only-tag", default=None, help="debug: only process this release tag")
    p.add_argument("--dry-run", action="store_true", help="verify and report, write nothing")
    args = p.parse_args()

    policy = json.loads(Path(args.policy).read_text())
    reg_path = Path(args.registry)
    prior = json.loads(reg_path.read_text()) if reg_path.exists() else {}
    if prior.get("schema") != 2:
        prior = {}
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)

    reg = build_registry(policy["builds_repo"], policy, prior, work, args.only_tag)
    changed = json.dumps(reg, sort_keys=True) != json.dumps(prior, sort_keys=True)
    print(f"registry changed: {changed}")
    if args.dry_run:
        print(json.dumps(reg, indent=2, sort_keys=True))
    elif changed:
        reg_path.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n")
        render_indexes(reg, Path(args.simple_dir))

    gh_out = __import__("os").environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"changed={'true' if changed and not args.dry_run else 'false'}\n")


if __name__ == "__main__":
    main()
