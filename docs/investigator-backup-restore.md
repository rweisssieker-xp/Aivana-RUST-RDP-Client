# Investigator sichern und wiederherstellen

Die CLI erstellt einen konsistenten SQLite-Snapshot einschließlich der bereits bestätigten WAL-Transaktionen. Der Quelldienst darf dabei laufen. Das Zielverzeichnis muss neu sein; bestehende Dateien werden nicht überschrieben.

```powershell
target\debug\relayne_investigator.exe backup investigator.local.sqlite backup-20260920
target\debug\relayne_investigator.exe verify-backup backup-20260920
target\debug\relayne_investigator.exe restore backup-20260920 investigator.restored.sqlite
```

Die Sicherung enthält `investigator.sqlite` und `manifest.json`: Zeit, SHA-256-Dateihash, Fall-/Jobanzahl, Mandanten und geprüfte Audit-Verkettung. Geprüft werden SQLite-Integrität und die Verkettung einschließlich der gespeicherten Payload-Hashes. Dies ist eine lokale Integritätsprüfung, keine unabhängig signierte Beweissicherung. Sicherungen sind vertraulich wie die Quelldaten und gehören auf freigegebenen verschlüsselten Speicher. Konfiguration und Secret-Umgebungsvariablen werden nicht exportiert und müssen separat verwaltet werden.

Eine Wiederherstellung schreibt ausschließlich eine **neue Datenbank**. Sie bewahrt Budgets, Belege und vorhandene Zustellungsbelege. Verwaiste laufende Aufträge werden wieder in die Warteschlange gestellt. Dienstbetrieb und automatische Zustellung bleiben zunächst pausiert; frühere Connector-, Benachrichtigungs- und aktive Release-Nachweise werden ungültig. Die Wiederherstellung erscheint unter `service.status.recovery`.

Vorgehen bei tatsächlicher Wiederherstellung:

1. Quelldienst kontrolliert beenden, damit nicht alter und wiederhergestellter Stand gleichzeitig externe Vorgänge auslösen.
2. Snapshot prüfen und in eine neue Datenbank wiederherstellen. Bei einem Fehler das Ziel nicht starten; der unvollständige Stand bleibt zur Diagnose liegen.
3. Möglichen Datenverlust zwischen Snapshot und Ausfall dokumentieren. Zustellungen und Tickets aus diesem Zeitraum beim Empfänger abgleichen; dessen persistente Idempotenzbelege sind dabei erforderlich.
4. Den Dienst mit der passenden Konfiguration und der neuen Datenbank starten. Er bleibt pausiert.
5. Als `admin` oder `incident_lead` `service.recovery_ack` mit `reason`, `external_effects_reconciled:true` und `data_loss_reviewed:true` ausführen. Die Bestätigung wird auditiert und startet noch keine Untersuchung.
6. Quell-/Benachrichtigungsproben und Release-Freigabe erneuern; anschließend bewusst `service.resume` aufrufen.

Ein wiederhergestellter Snapshot kann spätere, verloren gegangene Vorgänge nicht rekonstruieren. Das System behauptet deshalb weder vollständige Historie noch gemessene RTO/RPO. Sicherungsplan, Aufbewahrung, Wiederherstellungsproben und Messung der Pilotziele bleiben Aufgabe des Betriebs. Abgelaufene Belegextrakte dürfen durch alte Backups nicht dauerhaft wieder in Nutzung kommen; die vorhandenen Retentionsprüfungen gelten auch nach Restore.
