# Relayne Security Investigator

Der Investigator ergänzt Relayne um einen separat laufenden Rust-Dienst. Web-Oberfläche und MCP verwenden dieselbe authentifizierte Fall-API. Der Dienst bleibt aktiv, wenn die Oberfläche geschlossen wird. Grundlage ist das [PRD vom 20.09.2026](PRD_Autonomous_Security_Investigator_2026-09-20.md), insbesondere dessen verbindlicher Lieferzuschnitt in Abschnitt 17.

## Start

```powershell
cargo build --bin relayne_investigator
target\debug\relayne_investigator.exe init investigator.local.json
# Einen zufälligen Token nur für die aktuelle Umgebung erzeugen:
$env:RELAYNE_INVESTIGATOR_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
# Token für die Anmeldung lokal anzeigen, nicht in Tickets/Logs übernehmen:
$env:RELAYNE_INVESTIGATOR_TOKEN
target\debug\relayne_investigator.exe serve investigator.local.json investigator.local.sqlite
```

Die Oberfläche liegt unter `http://127.0.0.1:47841`. In Relayne ist sie über **Security Investigator → Open investigator** erreichbar. Der Server bindet ausschließlich an Loopback; der Host-Header muss der konfigurierten Adresse entsprechen. Die Anmeldung verwendet den Token. Der Browser hält ihn nur im Arbeitsspeicher. Die Standardkonfiguration ist **DEMO/A0**, ohne Quellzugriff oder externe Benachrichtigungen.

Für einen reproduzierbaren Test ohne Zugangsdaten und Netzwerk:

```powershell
target\debug\relayne_investigator.exe replay target\investigator-reference
```

Das Ausgabeverzeichnis muss neu sein. Ergebnis: SQLite-Fall, `report.json` und `report.md` mit 40 Fehlanmeldungen über zehn Konten, einem doppelt gelieferten erfolgreichen Login, einem blockierten Ressourcenaufruf und fehlendem Datei-Audit. Die 43 Lieferungen ergeben 42 eindeutige Ereignisse. Ein Login-Erfolg beweist weder Datenzugriff noch MFA-Umgehung oder Datenabfluss.

## Bedienung und Rollen

- `viewer`: Fälle, Belege, Audit und Berichte lesen.
- `analyst`: Untersuchungen, Belegimport, Kontext, Fragen und Maßnahmen bearbeiten.
- `reviewer`: Befunde prüfen, belegte Fragen beantworten und unabhängig verifizieren.
- `incident_lead`: Koordination, Übergabe, Abschluss und Eskalation.
- `risk_owner`: befristete geschäftliche Risikoentscheidungen und Wiederanlaufentscheidung.
- `admin`: Dienstkonfiguration, Budgets und Releases verwalten; diese Rolle ersetzt keine Risk-Owner-Delegation.

Die Konfiguration ordnet jede Identität einem eigenen `token_env` zu. Gemeinsame Tokens für unterschiedliche Identitäten werden abgelehnt. Rollen-/Tokenänderungen werden durch einen kontrollierten Dienstneustart wirksam. Die interne `system`-Rolle kann nicht als Benutzer konfiguriert werden. Eine Risikoakzeptanz ist keine technische Aktionsfreigabe. Eine Maßnahmenmeldung erhält zunächst `pending`; ein unabhängiger Prüfer benötigt einen im Fall vorhandenen technischen Beleg. Eine Übergabe muss der empfangende Owner selbst bestätigen.

Fall- und Objektänderungen werden versioniert. Die Oberfläche sendet `expected_version`, damit konkurrierende Änderungen sichtbar werden. Berichte enthalten die drei Kernansichten: Lagebild, Maßnahmen/Verifikation sowie Notbetrieb/Entscheidungsprotokoll. Frühere Situationen bleiben nachvollziehbar. Abgelaufene Belegauszüge werden auch aus gespeicherten Fallversionen entfernt; Herkunft und Hash bleiben mit dem Status `expired` erkennbar.

## Reale Quellen und A1

`contract` gibt den versionierten technischen Vertrag aus. Implementiert sind **Microsoft Graph v1.0 `security/alerts_v2` und `auditLogs/signIns`** über tenantgebundene Client-Credentials. Es werden nur feste GET-Abfragen, begrenzte Zeitfenster und geprüfte Pagination-URLs verwendet. OAuth- und Quellaufrufe werden vor Ausführung budgetiert. Arbiträre URLs, KQL, Shellbefehle und schreibende Security-Aktionen sind nicht verfügbar.

Vor Aktivierung muss der Betreiber im Zielmandanten die aktuellen Herstellerrechte, Lizenzen, Felder, Retention, Quoten und Datenregion prüfen. Der Vertrag nennt `SecurityAlert.Read.All` und `AuditLog.Read.All` als vorgesehene Application Permissions; deren tatsächliche Verfügbarkeit wurde in dieser Entwicklungsumgebung nicht geprüft.

Notwendige Konfiguration:

1. Echte Tenant-/Client-UUID, `sources.enabled`, `sources.secret_env` als Umgebungsreferenz.
2. Benannter Vertragsprüfer, UTC-Prüfzeit, bestätigte Least-Privilege-Rechte und Lizenz.
3. Tatsächlich geprüftes `coverage_start`/`coverage_end`, Retention und Region. Der Dienst erweitert dieses Zeitfenster nicht selbstständig. Eine leere Abfrage bestätigt keine Retention.
4. Verschlüsselter kundeneigener Datenträger, restriktive Dateiberechtigungen, bestätigte Aufbewahrung. SQLite selbst ist **nicht** als verschlüsselter Objektspeicher ausgegeben.
5. Benannte Fach-/Plattform-/Datenschutz-/Release-Verantwortliche, Vertretung und expliziter Standortscope.
6. Konfigurierter interner primärer und Ersatz-Webhook, erlaubte HTTPS-Hosts, bestätigte Empfänger und serverseitig unterstützte Idempotency-Keys. `notifications.probe` sendet ausdrücklich einen Test an beide eingerichteten Empfänger. Probe und Bereitschaft müssen gültig sein.
7. Geprüftes Release mit unabhängiger Review, Shadow-Nachweis und begrenztem Canary-Anteil.
8. Erfolgreiche, frische Quellproben und `operations.a1_enabled`. Unbeaufsichtigter Betrieb benötigt ausdrücklich bestätigte kontinuierliche Betreuung; andernfalls bleibt A1 gesperrt.

Interne Benachrichtigungen enthalten nur Fall-/Meldungskennung, Dringlichkeit und knappen Meldungstext. U0/U1 werden zeitnah zugestellt; unbestätigte U0 nach 15 Minuten, U1 nach 60 Minuten an den Ersatzweg eskaliert. U2/U3 erscheinen in einer täglichen Zusammenfassung ab 08:00 UTC. Ein einmaliges begründetes Snoozing ist auf maximal 24 Stunden begrenzt; neue materielle Meldungen erhalten eigene Kennungen. Zustellung ist keine menschliche Bestätigung. Fehler bleiben sichtbar und sperren die Bereitschaft für neue A1-Aufträge. Pro Tick gibt es höchstens zwei Zustellversuche, maximal drei Wiederholungen je Stufe; der konfigurierte Empfänger muss wiederholte Idempotency-Keys deduplizieren.

## Stop, Kosten und Wiederaufnahme

`service.stop` verhindert neue Ermittlungsaufrufe. Bereits laufende HTTP-Anfragen haben feste kurze Timeouts; sie werden nicht als sofort physisch abgebrochen dargestellt. Fristen- und Eskalationsverarbeitung läuft weiter. Queue-Leases, Quellcursor, Quoten, Fehler und konservativ reservierte Laufzeit überleben Neustarts. Wiederaufnahme setzt das Fallbudget nicht zurück. Kosten werden in ganzzahligen Mikroeinheiten geführt. Die konfigurierten Aufrufkosten sind konservative Betreiberansätze, keine nachgemessene Microsoft-Rechnung. Es gibt keine Modellaufrufe oder Modellkosten.

Der deterministische Referenzablauf prüft Alarm-/Loginbelege und Gegenhypothesen. Er führt keine unbegrenzten, modellgenerierten Pivots aus. Technische Retries sind begrenzt; Berechtigungs-, Schema- und Retentionsfehler bleiben Datenbedarf. Eine neue Lage führt zum menschlichen Review, niemals zum automatischen fachlichen Abschluss.

## API und MCP

```http
POST /api/command
Authorization: Bearer <token>
Content-Type: application/json

{"action":"cases.list","payload":{}}
```

MCP liegt unter `/mcp`: `initialize`, `tools/list` und `tools/call` mit `investigator_command`. `tools/list` enthält den vollständigen Aktionskatalog. Ein HTTP-fähiger MCP-Client verwendet denselben Bearer-Header. Tokens gehören weder in die URL noch in eingecheckte Plugin-Dateien. Siehe [MCP-Verbindung](../integrations/investigator/README.md). Das Plugin besitzt keine eigene Geschäftslogik und kann interne Worker-/Budgetbefehle nicht aufrufen.

## Release- und Betriebsverfahren

`releases.submit/review/shadow/activate/rollback` verwalten unveränderliche Pakete, Qualitätsnachweise, Rollen und Canary-Freigabe. Ein Paket muss zu den Komponenten der tatsächlich installierten Binärdatei passen. Ein Modell kann weder Code herunterladen noch seine Policy verändern. Benchmark- und Shadow-Ergebnisse müssen aus tatsächlichen Tests importiert und menschlich geprüft werden; ein Formular erzeugt keine solchen Nachweise. Rollback stoppt neue Aufträge und wählt eine vorher freigegebene Version. Ein Binär-/Datenbank-Rollback bleibt ein kontrollierter Deployment-Schritt; historische Fälle behalten ihre Komponentenbindungen.

Für Dauerbetrieb den CLI-Dienst unter einem dedizierten Windows-Konto über die vorhandene Service-/Task-Verwaltung des Betreibers starten. Secrets über dessen Secret-Verwaltung bereitstellen. Ein Service-Wrapper/Autostart wird durch diese Entwicklung nicht ungefragt auf dem Rechner installiert. Für entfernte Bedienung ist ein betreiberseitiger TLS-Reverse-Proxy erforderlich, der den erwarteten internen Host/Origin kontrolliert übergibt; der Dienst selbst bleibt an Loopback gebunden.

Die CLI bietet jetzt konsistente Sicherung, Integritätsprüfung und Wiederherstellung in eine neue, zunächst pausierte Datenbank. Siehe [Backup und Restore](investigator-backup-restore.md). Verschlüsselung, Sicherungsplan, Aufbewahrung und gemessene RTO/RPO bleiben Betreiberpflicht.

## Lieferumfang und Betriebsgrenzen

Der verbindliche MVP-Ablauf wird durch die unten beschriebenen P1-Funktionen ergänzt. A1 setzt weiterhin frische Quellen- und Zustellungsproben sowie passende Release-Freigaben voraus. Lokale Tests ersetzen weder Quellenfreigabe noch eine gemessene Betriebsabnahme. Siehe [Abnahmeprotokoll](security-investigator-acceptance.md).

## P1-Erweiterungen

Fünf [evidenzbasierte Playbooks](investigator-playbooks.md) stehen in Web und MCP bereit. [Ticket-/CMDB-Adapter und Provider-Importe](investigator-integrations.md) ergänzen den MVP; sie sind standardmäßig deaktiviert. Adapter verwenden feste freigegebene Ziele, persistente Zustellungsbelege und gemeinsame Fallbudgets. Quelle, Herkunft und Datenlücken bleiben im Fall nachvollziehbar.

Native, standardmäßig deaktivierte Read-only-Collector unterstützen Entra-Token-Kontext, Defender-Prozessdaten, Log-Analytics Storage-/Netzwerkdaten sowie einen begrenzten AD-CS/LDAP-Prüfpfad. Der AD-CS-Pfad deckt CA-Ausstellungsrichtlinien nicht vollständig ab; unbekannte Eigenschaften bleiben Datenlücken. Diese Implementierungen unterstützen nur die fest eingebauten Quellen und Schemas, keine beliebigen Provider oder Abfragen. Die Konfigurationsstruktur ist `collectors`.

Der ebenfalls standardmäßig deaktivierte FR-18-Executor unterstützt A2 für genau einen Vorgang: Microsoft Graph `revokeSignInSessions` für explizit konfigurierte Benutzerziele. Eine Aktion benötigt einen kurzlebigen, exakten Challenge, unabhängige Ed25519-Signaturen und zusätzliche Freigaben für als kritisch oder Tier 0 markierte Ziele. Das ist eine eng begrenzte ausführbare Funktion und keine allgemeine Incident-Response-Plattform. A3 bleibt optional und deaktiviert; es gibt keine beliebigen Änderungen, Isolation oder Löschaktionen.

Die [Pilot-Evidenz und der Readiness-Report](investigator-pilot.md) halten menschlich gemessene Quellenmachbarkeit, Restore-, Shadow-, Verfügbarkeits-, Zeit- und Kostenwerte mit Belegreferenzen fest. JSON- und Markdown-Exporte kennzeichnen fehlende oder veraltete Daten und trennen Messwerte von Zielen. Das Aufzeichnen von Beobachtungen aktiviert weder A1 noch A2 oder A3 und bescheinigt keine Produktionsreife. Das [No-secret-Referenzskript](../integrations/investigator/pilot/check-env-refs.ps1) prüft nur die Form und Inventarisierung benannter Umgebungsvariablenreferenzen; es liest keine Secret-Werte.

Externe Adapter erfordern eine passende Implementierung ihres dokumentierten internen HTTP-Vertrags und die Live-Abnahme durch den Betreiber. Quellenzugriff, Rechte, Retention, Restore, Verfügbarkeit, Shadow-Qualität, Analystenzeit, Kosten und Eskalationsbesetzung sind weiterhin reale Pilot-/Betriebsnachweise und wurden durch die lokale Implementierung nicht erbracht.
