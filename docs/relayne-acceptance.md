# Relayne – Implementierung und Abnahme, 11. September 2026

## 2026-09-13 — Distribution / Auslieferung / Distribution / Distribuzione

[Mehrsprachiger Auslieferungsstand und Prüfergebnisse / Multilingual distribution status and verification / État multilingue et vérification / Stato multilingue e verifica](distribution/README.md)

455 Anwendungstests + 16 Teamtests bestanden, 0 Fehler, 5 ignoriert. Beide Programme gebaut. Keine Live-Verbindungen; das Paket bleibt ausdrücklich eine unsignierte Entwicklungsauslieferung. Die vollständige Übersetzung der älteren Fachansichten und Dokumente steht weiterhin aus.

## Aktualisierung vom 12. September 2026

**Arbeitsmodus: ausschließlich Entwicklung.** Die neue [vergleichende Ursachenanalyse](relayne-differential-diagnosis.md) wird lokal mit Simulationen, bewachten Adapter-Ersatzimplementierungen und Loopback-HTTP geprüft. Externe Abnahme ist derzeit nicht vorgesehen und blockiert die weitere Entwicklung nicht. Vorhandene RDP-Hosts werden nicht verwendet.

Der vollständige, ungefilterte Offline-Gesamtlauf besteht mit **443 Anwendungstests und 16 Team-Tests**, ohne Fehler; fünf bestehende Live-/Installationsprüfungen bleiben ignoriert. Beide Programme wurden erfolgreich gebaut. Der zuvor im Gesamtlauf auftretende native OCR-Absturz ist durch eine prozessweite MTA-Nutzungsreferenz behoben. Ein Regressionstest mit 35 Sekunden Pause zwischen kurzlebigen OCR-Workern reproduzierte den Fehler vor der Korrektur und besteht danach.

Zusätzlich sind [Änderungs- und Fehlerexperimente im Klon](relayne-change-trials.md) integriert: Starttypänderung eines Anwendungsdienstes, HTTP-Nachweis, reproduzierter Dienstausfall, Reparatur und verifizierter Checkpoint-Rückweg. Der erste unterstützte Änderungstyp ist Automatic ↔ Manual; beliebige Updates oder Installationen sind damit nicht abgenommen. Die [erweiterten Recovery-Funktionen](recovery-platform-expansion.md) bleiben separat dokumentiert.

**Live-Abnahme weiterhin offen:** Lokal wurden weder ein Hyper-V-Modul bzw. VMMS-Dienst noch ein eingerichteter Relayne-Klon gefunden. Vorhandene RDP-Profile allein belegen keine Eignung als Testhost. Reale VM-, Prüfpunkt- oder Dienständerungen benötigen einen eindeutig bestimmten Testhost, den passenden Relayne-Klon und die Gastzugänge in der Anwendung. Die folgenden Abschnitte dokumentieren frühere Entwicklungsstände.

## Aktueller erweiterter Stand

[Funktionsumfang und Grenzen](relayne-expanded-usps.md): signierte Reparaturpakete, automatische Klon-/Produktionsvergleiche, mehrstufige HTTP-Anmeldung mit JSON-Prüfung und getrennten Laufzeit-Slots, erweiterte Wiederherstellung, Icon-Prozeduren als Workflows, komprimierte Bildfreigabe mit Einzeltasten, Windows-RemoteApp, Gateway-Zustimmung/PAA sowie OIDC-Unternehmensanmeldung mit Browser/PKCE sind integriert.

**Ergänzung: ganzzahlige JSON-Prüfungen.** Klon und Produktion vergleichen jetzt auch ganze Zahlen im Bereich ±9007199254740991 typstreng. Der erweiterte gemeinsame Login-/Cookie-/JSON-Test besteht mit zehn Antwortvarianten je Adapter (Rust und tatsächliches Gast-PowerShell-Skript mit VM-/Dienstmodellen), einschließlich Grenzwerten, falschen Zahlen, String-/Bool-/null-Verwechslungen, Dezimal- und Exponentialnotation sowie Wiederherstellung nach Fehlern. Zusätzlich bestehen **11 HTTP-Regressionstests**, darunter die neue Validierung unzulässiger Erwartungen. Logs: `C:/temp/relayne-integer-parity.log`, `C:/temp/relayne-integer-http-regression.log`. Der folgende Gesamtlauf dokumentiert den Stand vor dieser Ergänzung; er wurde dafür nicht vollständig wiederholt.

`cargo test --offline --bins -- --test-threads=1` bestand mit **341 Anwendungstests und 16 Teamtests, 0 Fehlern**. Fünf Tests werden im normalen Lauf ausgelassen: vier authentifizierte externe RDP-/Gateway-/Legacy-Prüfungen sowie der installierte Windows-Control-Test. Letzterer wurde separat ausdrücklich ausgeführt: **1/1 bestanden**, echter ActiveX-Host und echte Konfiguration, ohne `Connect`, Authentifizierung oder externen Prozess. Die vier externen Live-Prüfungen bleiben offen.

`cargo test --offline --manifest-path vendor/ironrdp-mstsgu/Cargo.toml --features native-tls` besteht mit **8/8 Gatewaytests**. Darunter echte lokale NTLM-Protokollfixtures, Zustimmung/Abbruch und die genaue PAA-Tunnelcodierung. Teamtests prüfen echte RSA-Signaturen, Rollen, Widerruf, PKCE, einen tatsächlichen Loopback-Callback und komprimierte Frame-Grenzen.

Die Windows-Integration führt echte Änderungen ausschließlich an eindeutigen Testdateien und HKCU-Testschlüsseln aus: 1-MiB-Dateiänderung, gelöschte Datei mit originalen Sicherheitsmetadaten wiederherstellen, DACL ändern/zurücksetzen sowie alle sechs Registrytypen einschließlich leerer MULTI_SZ-Werte. HTTP-Produktionsadapter und generiertes Gastskript durchlaufen dieselbe lokale Login-/Cookie-/JSON-Sequenz mit Erfolg und absichtlicher Fehlerassertion. Die VM-/Dienst-Cmdlets bleiben dabei bewachte Modelle. Workflowtests prüfen Parameter vor jeder früheren Mutation, alte Prüfschritt-Tokens, Abbruch und fehlgeschlagene UI-Prozeduren.

Prüflogs dieser lokalen Abnahme: `C:/temp/relayne-release-tests.log`, `C:/temp/relayne-team-final-tests.log`, `C:/temp/relayne-gateway-tests.log`, `C:/temp/relayne-activex-test.log`. `git diff --check` ist sauber. Reale Hyper-V-/WinRM-/RDP-/SSH-/Gateway- und IdP-Anmeldung sowie physische Monitorfälle sind damit nicht abgenommen. Der Entwicklungsrechner stellt `Get-VM` nicht bereit.

Der aktuelle Build beider Programme (`cargo build --offline --bins`) ist erfolgreich. Nicht blockierende Dead-Code-Warnungen bleiben. Native Aufnahmen bei 2160 × 1536 Pixeln wurden visuell geprüft: [Workflows](gui-concepts/relayne-workflow-expanded.png), [Team](gui-concepts/relayne-team-expanded.png), [Klonfreigabe](gui-concepts/relayne-promotion-expanded.png) und [Wiederherstellung](gui-concepts/relayne-changes-expanded.png). Die Ansichten zeigen echte lokale Leer-/Vorlagenzustände ohne simulierte Erfolgsbelege oder Remote-Verbindungsaufbau. Client und Teamserver müssen wegen des komprimierten Bildformats gemeinsam aktualisiert werden.

## Frühere Entwicklungsstände

**Aktuelle Weiterentwicklung:** [Klon → Produktion](relayne-promotion.md) verbindet gebundene Hyper-V-Testbelege mit freigegebenen Windows-Dienständerungen. **311 Anwendungstests + 8 Team-Tests bestanden**, vier bestehende Live-Tests ausgelassen. Echte Hyper-V-/WinRM-Abnahme bleibt offen. Die folgenden Zahlen dokumentieren frühere Stände.

**Neuester Stand:** Zusätzliche Änderungs-, Testlabor-, Workflow-, Rekonstruktions- und Paketfunktionen sind integriert. **304 Anwendungstests + 8 Team-Tests bestanden**, vier Live-Tests ausgelassen. [Aktueller Erweiterungsumfang und Abnahmegrenzen](relayne-next-usps.md). Die nachfolgenden Zahlen gehören zu früheren Entwicklungsständen.

**Aktualisierung:** Die sechs erweiterten Arbeitsabläufe sind inzwischen integriert. Aktueller Gesamtlauf: **279 Anwendungstests + 8 Team-Tests bestanden**, Build beider Binärdateien erfolgreich; vier authentifizierte Live-Tests weiterhin ausgelassen. Maßgeblich für den neuen Umfang ist [Sechs integrierte Arbeitsabläufe](relayne-six-usps.md). Die folgenden Abschnitte dokumentieren zusätzlich den vorausgehenden Stand; dessen Einschränkung auf ausschließlich manuell gebundene OCR-Anker wurde durch automatisches Vormachen und geprüfte Gesamtabläufe erweitert.

## Implementiert und lokal geprüft

- Neuer sichtbarer Produktname **Relayne** in Oberfläche, Fenstern, Berichten und Startdatei `target/debug/relayne.exe`. Der interne Cargo-Paketname und die bisherigen Aivana-Speicherpfade/Umgebungsvariablen bleiben kompatibel. Kein Löschen oder Verschieben bestehender Profile/Zugangsdaten.
- Lokale Windows-OCR, genaue Wortpositionen, explizite semantische Klickanker mit Kontext und Sperre bei Mehrdeutigkeit/veraltetem Bild. OCR-Suche in Aufzeichnungen; automatische heuristische Schwärzung vor Bild-/Indexspeicherung.
- Bearbeitbare Auftragsplanung aus natürlicher Sprache per optionalem OpenAI-Aufruf sowie ehrliche lokale Vorlagen. Keine automatisch ausgeführten Modellbefehle.
- Windows-Dienstreparatur mit Ausgangszustand, Abhängigkeitsprüfung, expliziter Freigabe, dauerhaftem Laufjournal, technischer Nachprüfung und unterstützter Wiederherstellung des vorherigen Dienstzustands. Erfolg und beide Fehler-/Wiederherstellungspfade mit lokalem PowerShell-Dienstmodell ausgeführt.
- Durchsuchbare Erfahrungen einschließlich fehlgeschlagener/unterbrochener Schritte und Voraussetzungen. Ursachenhypothesen anhand deklarierter Rechnerabhängigkeiten mit referenzierten Belegen.
- Tatsächlicher Team-Dienst mit SQLite, authentifizierter API, serverseitigen Rollen, widerrufbaren Tokens, Revisionskonflikten und atomarem Audit. Native Team-Oberfläche.
- Eingebettetes SSH-PTY-Terminal; individuelle Remote-Monitorfenster mit gespeicherter Position, identischem Bild-/Eingabeausschnitt und korrektem Fokuswechsel.
- RD Gateway mit SSPI_NTLM, externem MFA-Wartefenster, temporär angezeigten Serverhinweisen und individuellen Zielports. RemoteApp startet über den Windows-RDP-Client in einem separaten Fenster.

## Verifikation

- `cargo test --offline -- --test-threads=1`: Anwendung **247 bestanden, 0 fehlgeschlagen, 4 Live-Tests ignoriert**; Team-Binary **3 bestanden, 0 fehlgeschlagen**.
- `cargo test --offline -p ironrdp-mstsgu --lib`: **4 bestanden**, einschließlich tatsächlichem lokalem SSPI-Challenge-Austausch, Frame-Grenzprüfungen und Unicode-Serverhinweisen.
- `cargo build --offline --bins`: erfolgreich. Nicht blockierende Dead-Code-Warnungen bleiben, unter anderem gemeinsam genutzte Servertypen im Desktop-Binary und ältere Metrikfelder.
- Abschließend nach der Begrenzung des Terminal-Layouts und Bereinigung abgeschlossener Reparaturjobs: GUI-Renderingtest **1/1**, Planung-/Reparaturtests **8/8** erneut bestanden; Desktop-Binary erneut gebaut.
- Native Renderer-Aufnahme [Relayne Startbildschirm](gui-concepts/relayne-implemented.png) visuell geprüft: Name und neue Navigation sichtbar, Mission-Startbereich lesbar. Aufnahmemodus beendet die Anwendung selbst; es wurde keine Remote-Verbindung gestartet.
- Native Windows-OCR am generierten, nicht vertraulichen Bild, DPAPI-Aufzeichnungs-Roundtrip, echte lokale PTY-Ausgabe, HTTP-Loopback mit Rechte-/Widerrufs-/Weiterleitungsprüfungen und generierte Reparaturskripte gegen bewachte PowerShell-Fakes wurden tatsächlich ausgeführt.

## Noch nicht vollständig umgesetzt oder extern abgenommen

- **Eingebettetes RemoteApp/RAIL** ist nicht implementiert; der funktionierende Weg nutzt ein separates Windows-Fenster.
- **Interaktive Gateway-Einwilligung, Browser-/Token-MFA, In-Band-OTP und alter RPC-Gateway-Transport** sind nicht implementiert. Extern bestätigte MFA kann über den unterstützten Gateway-Transport abgewartet werden.
- Semantische Erkennung arbeitet mit OCR-Wörtern und optionalem Kontext, nicht mit allgemeinem Bildverständnis oder textlosen Icons. Automatische Schwärzung ist heuristisch und kein Nachweis vollständiger Geheimniserkennung.
- Dienst-Rollback stellt nur den unterstützten Laufzustand des Dienstes wieder her; keine allgemeine Maschinenwiederherstellung oder automatische Bestätigung fachlicher Anwendungsgesundheit.
- Für echte **RDP-/Gateway-/RemoteApp-/WinRM-/SSH-Interoperabilität und mehrere physische Monitore** fehlt die Live-Abnahme in einer geeigneten Umgebung. Der zuvor fehlgeschlagene Login wurde nicht wiederholt. Die vier vorhandenen authentifizierten Live-Tests bleiben ausgelassen.
- Der Team-Dienst ist implementiert und lokal getestet, aber nicht extern bereitgestellt; produktiver Betrieb benötigt eine administrierte Instanz mit TLS-Zugriff. Der neue Cloud-Planungsaufruf wurde nicht mit einem kostenpflichtigen Live-API-Aufruf abgenommen.

Diese Grenzen sind offen ausgewiesen; die gesamte ursprüngliche Wunschliste wird nicht als vollständig produktiv abgenommen bezeichnet.

## Verifikation am 12.09.2026

`cargo test --offline -- --test-threads=1`: 443 Anwendungstests und 16 Teamtests bestanden, 0 Fehler, 5 bestehende Tests ignoriert, 0 ausgefiltert. `cargo build --offline --bins` erfolgreich; bestehende Dead-Code-Warnungen bleiben bestehen. Die native Oberfläche wurde anhand der gekennzeichneten Dev-Simulation visuell geprüft (Screenshot: `docs/gui-concepts/relayne-differential-diagnosis.png`).

Ausschließlich Entwicklungsprüfungen: Simulationen, Testdoubles und lokales Loopback-HTTP. Keine Verbindung zu gespeicherten RDP-Hosts, keine Live-Hyper-V-Abnahme und keine externen Modellaufrufe.
## Dev-Szenariovergleich: Verifikation am 12.09.2026

`cargo test --offline diagnostic -- --test-threads=1`: **24 Tests bestanden, 0 Fehler**; gezielter Diagnose-Regressionslauf, 428 Anwendungstests und 16 Teamtests ausgefiltert. Vier neue Tests prüfen den Szenariovergleich, unvollständige Evidenz und die Oberfläche ohne Fall-/Jobänderung. Der zuvor dokumentierte vollständige Gesamtlauf bleibt ein früherer Stand.

`cargo build --offline --bin relayne` erfolgreich (51 bestehende Warnungen). Formatprüfung und `git diff --check` erfolgreich. Native Ansicht visuell geprüft: [Dev-Szenariovergleich](gui-concepts/relayne-diagnostic-comparison.png), sieben von sieben Simulationserwartungen erfüllt. Ausschließlich Dev; keine Live-Hosts oder externen Modellaufrufe.

## Prüfungsvorschau: Verifikation am 12.09.2026

`cargo test --offline diagnostic -- --test-threads=1`: **28 Tests bestanden, 0 Fehler**; gezielter Diagnose-Regressionslauf, 428 Anwendungstests und 16 Teamtests ausgefiltert. Vier neue Tests decken drei hypothetische Ergebnisse, unveränderte Originalfälle, Widersprüche, ausgeschöpfte Versuche, abgelaufene Evidenz und Rendering bei 640/1440 Pixeln ab.

`cargo build --offline --bin relayne`, Formatprüfung und `git diff --check` erfolgreich; 51 bestehende Build-Warnungen. Die native Ansicht wurde aufgenommen und der sichtbare Einstieg in die Vorschau geprüft: [Prüfungsvorschau](gui-concepts/relayne-diagnostic-foresight.png). Der gesamte Vorschauinhalt ist in der scrollbaren Diagnoseansicht erreichbar. Ausschließlich lokale Entwicklungsprüfungen, keine Live-Hosts und keine externen Modellaufrufe. Kein erneuter vollständiger Gesamttest für diese begrenzte Erweiterung.
