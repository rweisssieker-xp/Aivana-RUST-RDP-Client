"""Heuristic review queue for German runtime strings; not a proof of localization."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GERMAN = re.compile(r"[äöüÄÖÜß]|\b(?:nicht|kein|keine|keinen|keiner|fehlt|Fehler|Datei|Dateien|Rechner|Auftrag|Aufträge|Freigabe|Beleg|Belege|Prüfung|gueltig|ungueltig|fuer|pruefen|waehlen|auswaehlen|gespeichert|abgebrochen|verfuegbar|erforderlich|vorhanden|entfernen|erneut|erfolgreich|Benutzer|Passwort|Wiederherstellung|Ziel|Quelle|muss|darf|werden|wurde)\b")
LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')

def scan(paths):
    findings = []
    for path in paths:
        if "tests" in path.stem or path.name == "localization.rs":
            continue
        source = path.read_text(encoding="utf-8").split("#[cfg(test)]", 1)[0]
        for match in LITERAL.finditer(source):
            value = match.group()[1:-1]
            if GERMAN.search(value):
                findings.append({"file": str(path.relative_to(ROOT)).replace("\\", "/"),
                                 "line": source.count("\n", 0, match.start()) + 1, "literal": value})
    return findings

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    paths = [ROOT / p for p in args.paths] if args.paths else sorted((ROOT / "src").rglob("*.rs"))
    findings = scan(paths)
    print(json.dumps({"total_candidates": len(findings), "findings": findings[args.offset:args.offset+args.limit]}, ensure_ascii=False, indent=2))
