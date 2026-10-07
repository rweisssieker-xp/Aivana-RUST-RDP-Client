# Security Investigator – technische Abnahme

Stand: 05.10.2026. Diese Datei beschreibt Entwicklungstests, keine produktive Betriebsfreigabe oder gemessene SOC-Wirtschaftlichkeit. Die untenstehenden ursprünglichen Testzahlen und Ergebnisse dokumentieren den damaligen Lauf; neue Collector-, Response- und Pilotfunktionen benötigen eigene Entwicklungsprüfungen sowie unabhängig davon Live-Betriebsnachweise.

## Implementierte Komponenten

| Bereich | Implementierung / Grenze |
|---|---|
| FR-01, FR-05 | Feste Graph-v1.0-Verträge für Defender-Alarme und Entra-Sign-ins; OAuth, begrenzte GET-Abfragen, Schema-/Pagination-/Scope-Prüfung. Zielmandant, Lizenz und tatsächlich gewährte Rechte benötigen Live-Abnahme. |
| FR-02, FR-03 | SQLite-Queue, transaktionale stabile Schlüssel, Prozess-/Job-Leases, persistierte Cursor und Budgetstände. Pausierte A1-Aufträge lassen manuelle Wiederherstellungsproben passieren. |
| FR-04, FR-06–09 | Deterministisches Login-/Password-Spray-Playbook, drei Hypothesen, Gegenbelege, aktuelle/alte Belegversionen, Quellenlücken und manuell belegter Geschäftskontext. Kein freier Modell-/KQL-Agent. |
| FR-10–14 | Rollen-/Mandantenprüfung, versionierte Review und selbst bestätigte Übergabe, unabhängige technische Verifikation, Budgets, Web/MCP mit gemeinsamer API, JSON-/Markdown-Berichte. |
| FR-19–22, FR-25–26 | Versioniertes Lagebild, offene Fragen, typisierte Bewertungen, befristete Risk-Owner-Entscheidungen, Wiederanlaufnachweise, Maßnahmen und Fristen/Eskalationen. |
| FR-23–24 | Zusätzliche lokale Dienstleister-Aufträge/Abnahme und Standortbewertungen. Automatische externe Auftragssynchronisation ist nicht enthalten. |
| Abschnitte 20–23 | Dringlichkeit unabhängig von Evidenzstärke, lokale Outbox plus explizit konfigurierte interne Webhooks, Stop/Deferral/Retry, monatliche/fallbezogene Kostenreserven, Release-/Shadow-/Canary-Nachweise und Rollback-Sperre. |

## Aktualisierter Implementierungsstand, 05.10.2026

| Ergänzung | Implementierter Umfang | Noch erforderlicher Nachweis |
|---|---|---|
| Read-only-Collector | Konfigurierbare, standardmäßig deaktivierte Pfade für Entra-Token-Kontext, Defender-Prozessdaten, Log-Analytics Storage-/Netzwerkdaten und begrenzte AD-CS/LDAP-Prüfungen. feste Quellen-/Abfragegrenzen; kein beliebiges KQL. AD-CS CA-Ausstellungsrichtlinien sind nicht vollständig abgedeckt. | Zieltenant-Zugriff, effektive Berechtigungen, Lizenzen, Retention, Datenqualität und fachliche Abdeckung müssen live verifiziert werden. |
| FR-18/A2 | Optionaler, standardmäßig deaktivierter Graph-Executor nur für `revokeSignInSessions`; exakter kurzlebiger Challenge, unabhängige Ed25519-Signaturen, At-most-once-Zustellung und streng definierte Ziele. Kritische/Tier-0-Ziele benötigen zusätzliche Signaturen. | Keine Live-Reaktion wurde dadurch belegt. Eine organisatorische Freigabe, Zieltenant-Konfiguration, kontrollierte Abnahme und Wiederanlaufverfahren sind weiterhin separat notwendig. |
| FR-18/A3 | Nicht als allgemein verfügbarer Wirkungsumfang implementiert; bleibt optional/deaktiviert. | Jede Erweiterung benötigt ein eigenes Sicherheitskonzept und eine gesonderte Freigabe. |
| Pilot-Evidenz | `pilot.status`, `pilot.record` und `pilot.report` mit unveränderlichen, tenantgebundenen, auditierten menschlichen Messungen; JSON-/Markdown-Export, Frischeprüfung und nach Falltyp sowie Vollständigkeit geschichtete Median-/p95-Kosten und -Zeiten. Beobachtungen verändern keine A1-Freigabe. | Messungen müssen aus genehmigten echten Pilotläufen und prüfbaren Artefakten kommen. Die Implementierung selbst liefert keine gemessenen Werte oder Produktionsreife. |
| Secret-Referenzinventar | PowerShell-Skript listet syntaktisch gültige Referenznamen für Benutzer, aktivierte Source-/Collector-/Response-Pfade und konfigurierte Notification-Referenzen; es inspiziert keine Secret-Werte. | Namensinventar belegt weder Credential-Gültigkeit noch Berechtigung oder Erreichbarkeit. |

Die ursprüngliche Abnahmetabelle und lokale Testzählung oben erfassen nicht automatisch diese Ergänzungen. Ein lokaler Build/Testlauf ist getrennt von Live-Abnahme zu dokumentieren; die noch offenen Live-Nachweise stehen unten.

## Ausgeführte Prüfungen

- Eigenständiger Investigator: **61 Rust-Tests bestanden**, keine fehlgeschlagenen Tests im abschließenden vollständigen Lauf. Dazu gehören Referenzfall, isolierte HTTP-/MCP-Aufrufe, Mandanten-/Rollenspoofing, Host/Origin-Schutz, unzulässige interne Aktionen, Pagination-Scope, Budget-/Laufzeitgrenzen, Neustart, Worker-Leases und Pausierung.
- Native Relayne-Oberfläche: `cargo check --bin relayne` erfolgreich. Der Render-Test `mission_and_tools_render_at_narrow_and_wide_sizes_without_connections` einschließlich Investigator-Navigation besteht.
- Web-JavaScript: Syntaxprüfung mit Node; Oberfläche zusätzlich im lokalen Browser angemeldet und Referenzfall visuell kontrolliert. Belege werden über `textContent` ausgegeben; der Token verbleibt im Browser-Arbeitsspeicher und verschwindet beim Abmelden.
- Ausführbare Investigator-Datei gebaut; CLI-Referenzfall erzeugt 42 eindeutige Ereignisse aus 43 Lieferungen. Wiederholte Lieferung eines Quellereignisses erhält eigene Abrufzeitpunkte.
- Keine Microsoft-Tenant-Abfrage, produktive Fernverbindung, externe Benachrichtigung oder Security-Reaktion wurde während dieser Entwicklung ausgeführt.

## PRD-Pflichtfälle

| Fall | Nachweis |
|---|---|
| Login erfolgreich, Ressourcenaufruf blockiert | Referenzfall erhält getrennte Belegreferenzen; Exfiltration bleibt `not_decidable`. |
| Doppelte Quell-ID / spätere Ingestion | Ein Ereignis, mehrere Abrufzeiten; geänderte Inhalte bleiben als Revision und Klärungsfrage erhalten. |
| Leerresultat / fehlende Retention | Fehlende Quelle/Abdeckung bleibt Unsicherheit, keine Entwarnung. |
| Prompt-Injection in Logtext | Text bleibt Beleginhalt; weder SQL noch Shell/KQL/Modellaktionen werden daraus ausgeführt. |
| Manipulierter Tenant, Rolle, Objekt | Authentifizierter Serverkontext und tenantgebundene SQL-Schlüssel; Ablehnung getestet. |
| Neustart und konkurrierende Worker | Persistente Job-/Prozess-Leases, Fencing, transaktionale Quoten und Deduplication. |
| Umsetzung ohne Nachweis | `pending`; unabhängiger Prüfer benötigt aktuellen vorhandenen Beleg. Nichtanwendbarkeit braucht menschliche Review und Grund. |
| API-429, Ausfall, Trunkierung | Begrenzte Retry-Entscheidung und persistierte Wartezeiten; Teilbelege/Lücken bleiben sichtbar. Echte Provider-Ausfälle wurden nicht live erzeugt. |
| Storage-Logs fehlen | Kein automatischer Exfiltrationsausschluss. |
| Budgetende | API-Aufrufe, konservative Laufzeit, Ergebnisbytes sowie monetäre Reserven begrenzen Folgeaufrufe; keine Rücksetzung durch neue Jobs. |
| Abgelaufene Risikoentscheidung | Status `expired`, lokale Eskalation, keine Verlängerung oder technische Abschaltung. Externe Zustellung benötigt eingerichteten, getesteten Kanal. |
| Widersprüchliche Quellen | Strukturierte Faktenwidersprüche und Quellrevisionen öffnen Klärungsfragen; beide Belege bleiben erhalten. Freier Text wird nicht als allgemein gelöstes semantisches Widerspruchsproblem ausgegeben. |
| Ungeprüfter Standort | Nur explizite Prüfstatus; kein `safe`. Positive begrenzte Bewertung benötigt Reviewer und Evidenz. |
| Dienstleister meldet fertig | Abnahme bleibt ausstehend; unabhängige menschliche Abnahme mit Belegreferenz. |
| Restrisiko akzeptiert | Technische Datenlücken und Fallstatus bleiben bestehen. |
| Notbetrieb/Wiederanlauf | Gültige Risikofreigabe plus aktuelle Bereinigungs-, Funktionstest- und Überwachungsnachweise sowie Betreiber/Rückfallplan erforderlich. |

## Weiterhin notwendige Betreiber-/Pilotabnahme

Live-Konfiguration, effektive Rechte, Retention und tatsächliche Quellenabdeckung; verschlüsselter Datenträger und Backups; Empfängerbereitschaft und Webhook-Idempotenz; echte Shadow-/Benchmarkdaten; Restore-Probe, Verfügbarkeits-/RTO-/RPO-Messung und Analystenzeit/Kostenvergleich. A2 muss in einer gesondert autorisierten, kontrollierten Umgebung abgenommen werden, bevor es für einen echten Tenant genutzt wird. Diese Nachweise werden nicht durch lokale Unit-Tests, synthetische Datensätze, den Pilot-Report oder Referenzlisten von Umgebungsvariablen ersetzt.

## P1-Fortsetzung

| Bereich | Implementierung und geprüfte Grenze |
|---|---|
| FR-15 | Explizit freigegebene interne Ticket-/CMDB-HTTP-Adapter. Stabile externe Fall-ID, persistente gefencete Zustellungsbelege, Empfangs-Idempotenzvertrag, frische CMDB-Snapshots und Schutz vor parallel geändertem Kontext. Kein realer Provider wurde aufgerufen. |
| FR-16 | Konfigurierte Storage-/Netzwerk-Importformate mit Mandant, Standort, Ereigniszeit, nativen IDs, Gegenbelegen und Provider-Abdeckung. Ergänzend existieren standardmäßig deaktivierte Read-only-Collector für Entra-Token-Kontext, Defender-Prozessdaten, Log-Analytics Storage/Netzwerk und begrenzte AD-CS/LDAP-Prüfungen. Kein beliebiges KQL; AD-CS-CA-Ausstellungsrichtlinien bleiben unvollständig abgedeckt. Live-Rechte und Quellenqualität nicht abgenommen. |
| FR-17 und weitere Playbooks | Token-Kontextkorrelation, begrenzte Prozessketten, Cloud-Transfer und ESC1-Voraussetzungen. Aktuelle passende Vorlagen/ACLs/CA-Einstellungen sind nötig; unbekannte Eigenschaften und Analysegrenzen bleiben Datenlücken. Keine Behauptung eines bestätigten Exploits oder Abflusses. |
| Betriebswiederherstellung | Konsistente Sicherung bei laufendem SQLite-Dienst, Hash-/Audit-/Integritätsprüfung und Restore in eine neue pausierte Datenbank. Budgets bleiben erhalten; Quellen-/Release-Nachweise werden ungültig. Fortsetzung braucht dokumentierten Abgleich. |

Abschließende Prüfung: **61 Rust-Tests bestanden**, beide Binärdateien gebaut; der bestehende native Build meldet weiterhin seine bisherigen Warnungen. JavaScript-Syntax und Anmeldung, Playbook-Ausführung mit fehlenden Belegen sowie deaktivierte Adapter wurden in der lokalen Browseroberfläche geprüft. CLI-Backup der laufenden synthetischen Datenbank, Verify und Restore waren erfolgreich (`audit_chain: verified`, `restored_paused`, Abgleich erforderlich). Es gab keine produktiven Quellen-, Ticket-, CMDB- oder Modellaufrufe.

Die dokumentierten internen Adapterverträge benötigen beim Betreiber eine passende Gegenstelle. Der implementierte A2-Executor ist auf Graph `revokeSignInSessions` für konfigurierte Ziele mit unabhängiger Challenge-Signatur begrenzt und standardmäßig deaktiviert; A3 bleibt optional und deaktiviert. Pilot-Readiness-Evidenz erfasst Messungen, schafft selbst aber keine Abnahme. Collector-, Response- und Pilot-Funktionen müssen lokal separat entwickelt getestet werden; Live-Rechte, echte Restore-/Verfügbarkeits-/Kostenmessungen und eine kontrollierte A2-Abnahme bleiben offen. Die [Betriebsanleitung](security-investigator.md), [Pilot-Anleitung](investigator-pilot.md), [Playbook-Verträge](investigator-playbooks.md), [Adapter-Verträge](investigator-integrations.md) und [Restore-Anleitung](investigator-backup-restore.md) unterscheiden ausführbare Funktionen von notwendigen Live-/Betriebsnachweisen.
## Repository and repeatable offline check (2026-10-06)

At audit time, local `main` and the fetched `origin/main` both point to `f7d5bb8`; no Investigator pilot files are present in `origin/main` or the other fetched remote-tracking branches. The repository has 18 modified tracked files and 49 untracked files. Of the untracked files, 23 belong to the Investigator scope: these two docs, three `integrations/investigator` files, and 18 `src/investigator` files. The remaining 26 untracked files and all modified tracked files are outside that count and must be reviewed separately before any publish.

Run the offline synthetic harness after building the Investigator CLI:

```powershell
.\integrations\investigator\pilot\run-offline-acceptance.ps1 -Executable .\target\debug\relayne_investigator.exe
```

The script creates a unique output directory and refuses to overwrite an existing one. It runs the built-in synthetic replay, snapshots its SQLite database, verifies the snapshot, restores to a new database, and writes `acceptance-receipt.json` with artifact SHA-256 hashes and measured local backup/restore elapsed times. A failure preserves partial artifacts for diagnosis. No provider or external service is contacted. These measurements describe only the local synthetic run; they are not production pilot measurements and must not be recorded as live `pilot.record` evidence.

To check config environment-reference *names* without reading their values:

```powershell
.\integrations\investigator\pilot\check-env-refs.ps1 -ConfigPath <operator-config.json>
```

No Git commit or push was made as part of this audit. Local branch presence does not mean a change is on GitHub; only committed and pushed files are available there.
