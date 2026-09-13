# KI-generierte Anwendungstests

Im Bereich **Klon → Produktion** und im Recovery-Schritt **Generalprobe** kann Relayne aus einer Störungsbeschreibung und einem beschriebenen Anwendungsablauf HTTP-Erfolgskriterien vorschlagen. Bei einem Recovery-Fall ist dessen gespeicherte Störungsbeschreibung vorbefüllt und vor dem Versand bearbeitbar.

## Ablauf

1. Den exakten Windows-Dienst festlegen. **KI-Anwendungstests vorschlagen** öffnen.
2. Störung und erwarteten Ablauf beschreiben. Benötigt werden das HTTP-/HTTPS-Protokoll, der Port, öffentliche GET-Pfade, erwartete erfolgreiche Statuscodes und charakteristische Antworttexte. Beispiel: „HTTP auf Port 8080. GET /health liefert 200 und ready. GET /catalog liefert 200 und items. Beide Aufrufe verändern keine Daten.“
3. Die sichtbaren Texte prüfen und dem Versand an OpenAI zustimmen. **Anwendungstests mit KI entwerfen** sendet ausschließlich Dienstname, Störung und Ablaufbeschreibung. Verwendet werden das konfigurierte OpenAI-Modell und `OPENAI_API_KEY`. Es werden keine Profile, Bildschirme, Zugangsdaten oder Generalprobenbelege automatisch angehängt. In die Texte gehören keine Geheimnisse.
4. Bis zu vier vorgeschlagene Schritte mit Begründungen und Annahmen prüfen. Wenn Informationen fehlen, zeigt Relayne diese an und ermöglicht keine Übernahme. Die KI soll fehlende Endpunkte oder Antworttexte nicht erfinden; Vorschläge bleiben ungeprüfte Hypothesen.
5. Bestätigen, dass Port, TLS, Pfade und Antwortmerkmale korrekt sind und die GET-Aufrufe keine Daten verändern. **Geprüfte Tests übernehmen** ersetzt die bisherigen HTTP-Prüfschritte und speichert den Entwurf lokal verschlüsselt. Anschließend lassen sich die Kriterien im bestehenden Editor bearbeiten.
6. Ziel und Klon zuordnen und eine neue Generalprobe ausdrücklich freigeben. Die Übernahme selbst startet weder Verbindung noch Anwendungstest noch Dienständerung.

## Grenzen und Nachweise

Vorschläge enthalten ausschließlich relative öffentliche Pfade am bereits vom Operator zugeordneten Host, einen gemeinsamen Port und eine gemeinsame TLS-Einstellung. Jeder Schritt prüft einen Status von 200–299 und ein nicht leeres wörtliches Antwortmerkmal. Befehle, frei gewählte Hosts, zusätzliche Methoden oder Authentifizierungsparameter sind im Vorschlagsschema ausgeschlossen. Querystrings, Fragmente, kodierte oder mehrdeutige Pfade werden abgewiesen. Ob ein GET-Endpunkt fachlich tatsächlich keine Daten verändert, muss der Betreiber prüfen.

Änderungen an Beschreibung, Modell oder Entwurf verwerfen offene Vorschläge und setzen die Zustimmung zurück. Ein verworfener oder verspäteter KI-Vorschlag kann keine Tests übernehmen. Eine bereits gesendete Anfrage kann beim Anbieter noch laufen; es gibt keine automatische Wiederholung. Antworten sind auf 256 KiB und Anfragen auf 90 Sekunden begrenzt. Unvollständige Antworten, Ablehnungen, Tool-Aufrufe und mehrdeutige Nachrichten werden nicht übernommen.

Eine Übernahme entfernt bisherige Belegverweise, Ausführungsfreigaben, Gastpasswort und HTTP-Laufzeitwerte aus dem Entwurf. Dienst und Zielzuordnung bleiben erhalten. Bei offener Ausführungsprüfung, laufender Generalprobe oder gesperrtem Speicher ist die Übernahme blockiert. Ein Speicherfehler nach Übernahme sperrt die Ausführung. Die bestehenden Produktionsprüfungen und die Ein-Stunden-Frist gelten weiter.

Die Eingabebeschreibungen und nicht übernommene Vorschläge werden für diesen Assistenten nur im Arbeitsspeicher gehalten; der ursprüngliche Recovery-Fall unterliegt weiterhin seiner bestehenden Speicherung. Nach Übernahme werden die ausführbaren Kriterien im verschlüsselten Generalprobenentwurf gespeichert. Ein KI-Vorschlag ist kein Erfolgsnachweis. Erfolgreiche Wiederherstellung wird weiterhin ausschließlich durch tatsächliche Dienst- und HTTP-Belege festgestellt.

Diese erste Erweiterung nutzt vom Operator beschriebenes Verhalten. Sie analysiert keine Bildschirmaufzeichnungen automatisch und unterstützt keine beliebigen Browser-, Login- oder Skriptabläufe als KI-Vorschlag.

## Verifikation am 12.09.2026

`cargo test --offline -- --test-threads=1`: **387 Anwendungstests und 16 Team-Tests bestanden**, keine Fehler; fünf bestehende manuelle Tests ausgelassen. Zehn neue Tests decken Vorschlagsschema, fehlende Angaben, unerlaubte Felder/Pfade, Antwortgrenzen, Tool-/Refusal-Antworten, sichtbaren Versandkontext, veraltete Antworten, Entwurfsbindung, Freigabenentzug und die Darstellung von Vorschlägen bei 640/1440 logischen Pixeln ab. Domain- und Übernahmelogik wurden zunächst mit erwarteten fehlschlagenden Tests geprüft und anschließend implementiert.

`cargo build --offline --bins`, Formatprüfung der betroffenen Rust-Dateien und Whitespace-Prüfung bestanden. Bestehende Dead-Code-Warnungen bleiben. Die [native Einbindung](gui-concepts/relayne-ai-application-tests.png) wurde aufgenommen und visuell geprüft. Eine separate Codeprüfung fand keine offenen Befunde im neuen Ablauf. Kein kostenpflichtiger OpenAI-Aufruf und keine reale WinRM-/Hyper-V-Verbindung wurden für diese Verifikation gestartet; Modellqualität und End-to-End-Verhalten am echten Anbieter bleiben separat zu prüfen.
