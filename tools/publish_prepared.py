"""Publish already signed artifacts; never load a private signing key or PAT."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO = "kasyanovea17-crypto/Markirovkaplus-updates"
PUBLIC_KEY = "kTstgdiCKV7IZGhxGwWjOVI4LMB2OqtN1ZZp+wkboMk="
INSTALLER = "MarkirovkaPlusInstaller.exe"
ASSETS = (INSTALLER, "latest.json", "build_metadata.json", "BUILD_VERIFICATION.txt", "FROZEN_SMOKE.txt")
ARCHIVE_NAMES = {INSTALLER, "build_metadata.json", "BUILD_VERIFICATION.txt", "FROZEN_SMOKE.txt", "FROZEN_SMOKE.runtime.log"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def version(value):
    require(bool(re.fullmatch(r"v?\d+\.\d+\.\d+", value)), "Unexpected release version")
    return tuple(map(int, value.removeprefix("v").split(".")))


def verify_manifest(data, expected_version, public_key=PUBLIC_KEY):
    require(data.get("version") == expected_version, "Manifest version mismatch")
    require(data.get("installerUrl") == INSTALLER, "Unexpected installer location")
    require(data.get("signatureAlg") == "ed25519", "Signed Ed25519 manifest required")
    payload = {k: v for k, v in data.items() if k not in ("signature", "signatureAlg")}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = str(data.get("signature") or "")
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key)).verify(raw, encoded)


def verify_files(folder, descriptor):
    manifest = json.loads((folder / "latest.json").read_text(encoding="utf-8-sig"))
    verify_manifest(manifest, descriptor["version"])
    installer = folder / INSTALLER
    require(installer.stat().st_size == manifest["size"] >= 1024 * 1024, "Installer size mismatch")
    require(digest(installer) == manifest["sha256"] == descriptor["installer_sha256"], "Installer SHA256 mismatch")
    with installer.open("rb") as stream:
        require(stream.read(2) == b"MZ", "Not a Windows executable")
    metadata = json.loads((folder / "build_metadata.json").read_text(encoding="utf-8-sig"))
    require(metadata.get("sourceCommit") == descriptor["source_commit"], "Source commit mismatch")
    require(metadata.get("version") == descriptor["version"], "Build version mismatch")
    require(metadata.get("sha256") == manifest["sha256"] and metadata.get("size") == manifest["size"], "Metadata mismatch")
    require(all(metadata.get(k) == "passed" for k in ("pytest", "sqlcipher", "codeOwnerUi", "frozenSmoke")), "Missing build checks")
    smoke = (folder / "FROZEN_SMOKE.txt").read_text(encoding="utf-8-sig")
    require("FROZEN_SMOKE: PASSED" in smoke and "appVersion=" + descriptor["version"] in smoke, "Frozen smoke mismatch")
    require("PASS startup log: no initialization errors" in smoke, "Startup smoke failed")
    build = (folder / "BUILD_VERIFICATION.txt").read_text(encoding="utf-8-sig")
    require("BUILD RESULT: PASSED" in build, "Build transcript failed")
    return manifest


class StripCrossHostAuth(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and urlparse(newurl).netloc != urlparse(req.full_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


OPENER = build_opener(StripCrossHostAuth())


def request(url, *, method="GET", data=None, authenticated=False, content_type="application/json"):
    headers = {"User-Agent": "MarkirovkaPlus-prepared-release", "Accept": "application/vnd.github+json"}
    if authenticated:
        require(urlparse(url).hostname in ("api.github.com", "uploads.github.com"), "Refusing credential to unexpected host")
        token = os.environ.get("GH_TOKEN", "")
        require(bool(token), "Missing workflow token")
        headers.update(Authorization="Bearer " + token, **{"X-GitHub-Api-Version": "2026-03-10"})
    if data is not None:
        headers["Content-Type"] = content_type
    return OPENER.open(Request(url, data=data, headers=headers, method=method), timeout=240)


def api(suffix, *, method="GET", payload=None, allow_missing=False, authenticated=True):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    try:
        with request("https://api.github.com/repos/" + REPO + suffix, method=method, data=data, authenticated=authenticated) as response:
            return json.load(response)
    except HTTPError as exc:
        if allow_missing and exc.code == 404:
            return None
        raise RuntimeError(f"GitHub {method} {suffix}: HTTP {exc.code}") from None


def download(url, path, size, expected_digest, *, authenticated=False):
    count = 0
    sha = hashlib.sha256()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with request(url, authenticated=authenticated) as response, path.open("wb") as target:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                require(count <= size, "Download larger than expected")
                sha.update(chunk)
                target.write(chunk)
    except HTTPError as exc:
        # Do not include temporary artifact URL or authentication in logs.
        raise RuntimeError(f"Artifact download HTTP {exc.code}") from None
    require(count == size and sha.hexdigest() == expected_digest, "Download size/SHA256 mismatch")


def unpack(archive, destination, descriptor, manifest_path):
    require(archive.stat().st_size == descriptor["archive_size"], "Archive size mismatch")
    require(digest(archive) == descriptor["archive_sha256"], "Archive SHA256 mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        require(len(bundle.namelist()) == len(ARCHIVE_NAMES) and set(bundle.namelist()) == ARCHIVE_NAMES, "Unexpected archive paths")
        require(bundle.testzip() is None, "Archive CRC mismatch")
        for name in ARCHIVE_NAMES:
            (destination / name).write_bytes(bundle.read(name))
    (destination / "latest.json").write_bytes(manifest_path.read_bytes())
    return verify_files(destination, descriptor)


def check_release(release, expected_tag, marker, *, allow_published=False):
    require(release.get("tag_name") == expected_tag, "Unexpected release tag")
    require(marker in (release.get("body") or ""), "Existing release belongs to another source")
    require(allow_published or release.get("draft") is True, "Published releases are never overwritten")


def verify_remote(release, expected, destination, descriptor, *, public):
    assets = api(f"/releases/{release['id']}/assets?per_page=100", authenticated=not public)
    indexed = {asset["name"]: asset for asset in assets}
    require(set(indexed) == set(ASSETS), "Release asset set mismatch")
    for name in ASSETS:
        asset, item = indexed[name], expected[name]
        require(asset["size"] == item["size"] and asset.get("state") == "uploaded", "Incomplete release asset")
        url = asset["browser_download_url"] if public else f"https://api.github.com/repos/{REPO}/releases/assets/{asset['id']}"
        # GitHub's asset API needs the binary media type; use the public URL for
        # published assets and a dedicated authenticated request for drafts.
        if public:
            download(url, destination / name, item["size"], item["sha256"])
        else:
            destination.mkdir(parents=True, exist_ok=True)
            headers = {"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/octet-stream", "User-Agent": "MarkirovkaPlus-prepared-release"}
            sha, count = hashlib.sha256(), 0
            with OPENER.open(Request(url, headers=headers), timeout=240) as response, (destination / name).open("wb") as out:
                while chunk := response.read(1024 * 1024):
                    count += len(chunk)
                    require(count <= item["size"], "Draft download larger than expected")
                    sha.update(chunk)
                    out.write(chunk)
            require(count == item["size"] and sha.hexdigest() == item["sha256"], "Draft asset mismatch")
    verify_files(destination, descriptor)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("descriptor", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    descriptor = json.loads(args.descriptor.read_text(encoding="utf-8"))
    release_version = descriptor["version"]
    version(release_version)
    tag = "v" + release_version
    marker = "Source commit: " + descriptor["source_commit"]
    manifest_path = args.descriptor.with_name("latest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    verify_manifest(manifest, release_version)
    expected = descriptor["assets"]
    require(set(expected) == set(ASSETS), "Unexpected expected asset list")
    scratch = Path("publish-work")
    scratch.mkdir(exist_ok=True)
    if not args.verify_only:
        require(os.environ.get("GITHUB_REPOSITORY") == REPO, "Wrong publication repository")
        existing = api("/releases/tags/" + tag, allow_missing=True)
        if existing and not existing.get("draft"):
            check_release(existing, tag, marker, allow_published=True)
            verify_remote(existing, expected, scratch / "existing-public", descriptor, public=True)
            print("PUBLISHED VERIFIED (unchanged): " + existing["html_url"])
            return
        latest = api("/releases/latest")
        require(version(latest["tag_name"]) < version(tag), "Same or newer release is already latest")
    archive = args.archive or scratch / "prepared.zip"
    if args.archive is None:
        url = descriptor["archive_url"]
        parsed = urlparse(url)
        require(parsed.scheme == "https" and parsed.hostname.endswith(".oaiusercontent.com") and not parsed.username, "Unexpected artifact host")
        download(url, archive, descriptor["archive_size"], descriptor["archive_sha256"])
    folder = scratch / "prepared"
    unpack(archive, folder, descriptor, manifest_path)
    for name in ASSETS:
        require((folder / name).stat().st_size == expected[name]["size"] and digest(folder / name) == expected[name]["sha256"], "Expected asset hash mismatch")
    print("PREPARED RELEASE VERIFIED: " + release_version + "; " + manifest["sha256"])
    if args.verify_only:
        return
    body = f"Маркировка+ {release_version}\n\n{marker}\n\n" + "\n".join("- " + note for note in manifest.get("notes", []))
    body += "\n\nПервый переход со старых версий выполните установщиком вручную: изменён ключ подписи. Старый публичный ключ сохранён.\n\nSHA256: " + manifest["sha256"]
    release = existing or api("/releases", method="POST", payload={"tag_name": tag, "target_commitish": os.environ["GITHUB_SHA"], "name": "Маркировка+ " + release_version, "body": body, "draft": True, "prerelease": False, "make_latest": "false"})
    check_release(release, tag, marker)
    assets = api(f"/releases/{release['id']}/assets?per_page=100")
    require(set(asset["name"] for asset in assets).issubset(ASSETS), "Unexpected existing draft assets")
    existing_assets = {asset["name"]: asset for asset in assets}
    upload = f"https://uploads.github.com/repos/{REPO}/releases/{release['id']}/assets"
    for name in ASSETS:
        if name in existing_assets:
            item = existing_assets[name]
            require(item.get("state") == "uploaded" and item.get("size") == expected[name]["size"] and item.get("digest") == "sha256:" + expected[name]["sha256"], "Existing draft asset differs; no overwrite performed")
            continue
        content_type = "application/json" if name.endswith(".json") else "application/octet-stream"
        with request(upload + "?name=" + quote(name), method="POST", data=(folder / name).read_bytes(), authenticated=True, content_type=content_type) as response:
            require(response.status == 201, "Upload failed")
        print("UPLOADED: " + name)
    verify_remote(release, expected, scratch / "draft-verify", descriptor, public=False)
    latest = api("/releases/latest")
    require(version(latest["tag_name"]) < version(tag), "Latest changed during publication")
    release = api(f"/releases/{release['id']}", method="PATCH", payload={"draft": False, "prerelease": False, "make_latest": "true"})
    for attempt in range(4):
        try:
            verify_remote(release, expected, scratch / "public-verify", descriptor, public=True)
            break
        except (HTTPError, RuntimeError):
            if attempt == 3:
                raise
            time.sleep(5 * (attempt + 1))
    require(api("/releases/latest", authenticated=False)["tag_name"] == tag, "Latest promotion not visible")
    print("PUBLISHED VERIFIED: " + release["html_url"])


if __name__ == "__main__":
    main()
