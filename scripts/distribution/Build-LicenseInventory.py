"""Create a traceable dependency inventory from `cargo metadata --locked` JSON.

This records declarations and shipped license texts. It does not determine legal
compatibility, and missing license texts remain explicit review items.
"""
import argparse
import hashlib
import json
from pathlib import Path


def build(metadata_path: Path, output: Path):
    metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
    output.mkdir(parents=True, exist_ok=True)
    packages = []
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        directory = Path(package["manifest_path"]).parent
        candidates = set()
        for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*", "license*", "License*"):
            candidates.update(directory.glob(pattern))
        if package.get("license_file"):
            candidates.add(directory / package["license_file"])
        texts = []
        for source in sorted(candidates):
            if not source.is_file() or source.is_symlink() or source.stat().st_size > 1048576:
                continue
            content = source.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            destination = output / "texts" / (digest + ".txt")
            destination.parent.mkdir(exist_ok=True)
            destination.write_bytes(content)
            texts.append({"filename": source.name, "sha256": digest, "path": "texts/" + destination.name})
        packages.append({"name": package["name"], "version": package["version"],
                         "declared_license": package.get("license"),
                         "repository": package.get("repository"), "license_texts": texts,
                         "review_required": not bool(texts) or not bool(package.get("license"))})
    inventory = {"schema": "relayne-dependency-license-inventory-v1",
                 "metadata_sha256": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
                 "legal_approval": False, "packages": packages}
    (output / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    lines = ["# Third-party dependency inventory", "",
             "Generated from locked Cargo metadata. License declarations and available texts are evidence, not a legal compatibility approval. Review additional binary/system dependencies separately.", "",
             "| Package | Version | Declared license | License text |", "|---|---|---|---|"]
    for item in packages:
        links = ", ".join(f"[{entry['filename']}]({entry['path']})" for entry in item["license_texts"]) or "Missing: review required"
        lines.append(f"| {item['name']} | {item['version']} | {item['declared_license'] or 'Not declared'} | {links} |")
    (output / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    notices = ["Relayne third-party notices", "Generated inventory; unresolved declarations/texts still require review."]
    for item in packages:
        notices.append("\n" + "=" * 72 + f"\n{item['name']} {item['version']}\nDeclared license: {item['declared_license'] or 'Not declared'}\nRepository: {item['repository'] or 'Not declared'}\n")
        if not item["license_texts"]:
            notices.append("License text not available in this package metadata. Review required.\n")
        for entry in item["license_texts"]:
            notices.append((output / entry["path"]).read_text(encoding="utf-8", errors="replace"))
    (output / "NOTICES.txt").write_text("\n".join(notices), encoding="utf-8")
    return len(packages), sum(item["review_required"] for item in packages)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    count, missing = build(args.metadata, args.output)
    print(f"Inventoried {count} packages; {missing} require license declaration/text review.")
