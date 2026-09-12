# Mission Control – implementierter Ausbau

Stand: 11. September 2026. Native Rust/egui-Anwendung. Mission Control ist die neue Startansicht; Rechnerzentrale und Sitzungen bleiben über die Navigation erreichbar.

## Aufträge und überprüfbare Abläufe

Ein Auftrag enthält ein gewünschtes Ergebnis, ausgewählte Rechner und bearbeitbare Schritte mit Erfolgskriterien und Rückwegen. Der zuerst ausgewählte Rechner ist der Probelauf. Erst nach Befunderfassung und manueller Ergebnisbestätigung werden weitere Rechner freigegeben. Jeder Schritt wird einzeln gestartet.

Ausführbare Schritte: TCP-Prüfung plus vorhandene Sitzungsdaten, WinRM-Systeminventar, Dienste, Prozesse, Systemereignisse sowie explizit eingegebene SSH-Befehle auf SSH-Profilen. Manuelle Schritte erfassen den Kontext, führen aber selbst keine Änderung aus. Ein Prozess mit Exitcode 0 gilt noch nicht als erfülltes Erfolgskriterium.

Missionen werden vor Remote-Ausführung gespeichert. Nach einem Neustart werden zuvor laufende Schritte als unterbrochen geführt; es gibt keinen automatischen Wiederanlauf. Pausieren stoppt lokale Jobs, kann aber bereits gestartete Remote-Befehle nicht zurücknehmen. Rückwege sind dokumentierte Anweisungen, keine automatisch erstellten Maschinen-Snapshots.

Ziele sind an Profil-ID, Host, Port, Protokoll, Benutzer, Domäne und Gatewayroute gebunden. Geänderte Profile werden nicht stillschweigend verwendet. Sitzungsbefunde stammen nur aus Sitzungen mit passender ursprünglicher Endpunkt-Identität.

## Befunde, Vergleich und Übergabe

- Suche über erfasste lokale Befunde und Sitzungsereignisse, einschließlich tatsächlicher Werkzeugausgaben. Kein flächendeckendes OCR aller Rechner.
- Vergleich zweier zeitgestempelter Befunde nach strukturierten Feldern. JSON-Dienstlisten werden anhand ihrer Namen verglichen, damit eine geänderte Reihenfolge keine Änderung vortäuscht.
- Vollständig bestätigte Aufträge können als erprobte Abläufe für neue Zielrechner verwendet werden.
- JSON-Übergaben erhalten neue Auftrags- und Befund-IDs und werden pausiert importiert. Identische lokale Profile können ausdrücklich zugeordnet werden. Fehlende oder abweichende Endpunkte bleiben blockiert.
- Markdown-Berichte und JSON-Übergaben überschreiben keine bestehenden Dateien. Sie enthalten lesbare Rechnernamen/Befunde und sollten vor Weitergabe geprüft werden.
- Der lokale Auftragsspeicher `missions.dpapi` ist unter Windows mit DPAPI geschützt. Ein unlesbarer Speicher wird nicht durch einen leeren ersetzt.

## Vormachen und Lernen

Unter **Vormachen & Lernen** können bis zu 200 Bedienschritte einer ausgewählten Sitzung aufgenommen, bearbeitet und lokal verschlüsselt gespeichert werden. Navigation und vollständige Klickpaare einschließlich zusammengehöriger Doppelklicks sind wiederverwendbar. Texte und Tastenkombinationen werden als auszufüllende Platzhalter geführt; Eingabetexte und Passwörter werden nicht gespeichert. Ziehen und Zwischenablagedaten werden nicht aufgezeichnet.

Wiedergabe erfordert passende Bildgröße, ein ausgewähltes verbundenes Ziel, Prüfung des sichtbaren Elements und Freigabe jedes einzelnen Schritts. Danach muss die Wirkung manuell bestätigt werden. Es handelt sich um nachvollziehbare Bedienabläufe mit Koordinatenprüfung, nicht um semantisch positionsunabhängige GUI-Automation. Der Lernspeicher enthält aktuell einen gespeicherten Ablauf; die Missionsbibliothek kann mehrere bestätigte Aufträge enthalten.

## Remote-Werkzeuge und Dateien

- SSH-Befehle mit strenger Hostschlüsselprüfung und Schlüssel-/Agent-Authentifizierung; kein interaktives Terminal und keine Passwortübergabe über Prozessargumente.
- WinRM verwendet die aktuelle Windows-Identität und PowerShell-Remoting. System-, Dienste-, Prozess- und Ereignisabfragen sowie ausdrücklich bestätigte Dienstaktionen sind implementiert.
- SFTP-Verzeichnisabfrage, Upload/Download, rekursive Übertragung und ausdrücklich gewählte Wiederaufnahme. Wiederaufnahme setzt einen unveränderten Quellinhalt und passenden bereits übertragenen Präfix voraus; keine automatische Prüfsummenverifikation.
- Zwei Bereiche zeigen lokale Dateien (bis 500 Einträge) und die tatsächliche letzte Remote-Verzeichnisantwort mit passendem Ziel/Pfad/Zeitpunkt. Remote-Namen werden nicht unzuverlässig aus `ls`-Text als Dateisystemobjekte interpretiert.
- Serielle Warteschlange mit Abbruch, 120 Sekunden Zeitlimit und begrenzter Ausgabe. Keine erfundenen Prozent- oder Geschwindigkeitsanzeigen. Aufträge sind aktuell nicht über Neustarts hinweg persistent.

OpenSSH und Windows PowerShell müssen lokal vorhanden sein. Details: [Remote-Werkzeuge](remote-operations-implementation.md).

## Inventar und Vault

AD-Abfragen verwenden das installierte ActiveDirectory-Modul/RSAT. Entra-Abfragen verwenden Microsoft Graph PowerShell und ein ausdrücklich bereitgestelltes `AIVANA_GRAPH_ACCESS_TOKEN` mit `Device.Read.All`; das Token wird weder in Argumenten noch in der Ausgabe ausgegeben. Maximal 500 Geräte und 128 KiB Antwort pro Abruf. Entra-Anzeigenamen sind lediglich zu prüfende Zielkandidaten, keine bestätigten DNS-Adressen. Die API-Basis ist [Get-MgDevice](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/get-mgdevice?view=graph-powershell-1.0).

JSON/CSV-Inventare können geprüft, ausgewählt und ohne Wiederherstellung importierter Geheimnisse übernommen werden. Doppelte Endpunkte und abweichende Login-Zuordnungen überschreiben bestehende Profile nicht. Dynamische Gruppenregeln filtern nach Hostname und Tag.

Bitwarden wird über eine installierte, entsperrte CLI mit vorhandener `BW_SESSION` verwendet. Der Abruf ist an das unveränderte Zielprofil gebunden. Ein neuer geschützter Credential-Datensatz wird erst durch erfolgreiches Profilspeichern aktiv; der alte Login wird bei einem Fehler nicht überschrieben. Keine bidirektionale Vault-Synchronisierung, kein KeePass-Connector.

## Fenster und Aufzeichnungen

Sitzungen können eigene native Fenster erhalten, zwischen lokalen Monitoren verschoben und im Vollbild angezeigt werden. Nur die fokussierte Sitzung erhält Eingaben und Zwischenablagezugriff. Benannte Fensteranordnungen wenden sich ausschließlich auf bereits offene Sitzungen an; Wiederherstellen startet keine Anmeldung. Das ist noch keine automatische Verteilung einzelner Remote-Monitore auf einzelne lokale Monitore.

Explizite Aufzeichnungen speichern höchstens ein verändertes Schlüsselbild pro Sekunde, maximal 600 Bilder / 128 MiB je Aufzeichnung. Schwärzungsrechtecke werden vor der PNG-Kodierung angewendet. Index und Bilder sind lokal DPAPI-geschützt. Suche über Titel/Bildnotizen und angehängte Sitzungsereignisse, Bildauswahl über Zeitleistenschieber und bewusster unverschlüsselter PNG-Export sind vorhanden. Kein Video-, Audio- oder OCR-Archiv. Bei Prozessabbruch bleiben unvollständig abgeschlossene Archive entsprechend gekennzeichnet.

## Noch offen

- Vollständige Live-Abnahme mit gültigen RDP-Testzugangsdaten; letzter bekannter Smoke-Test scheiterte vor Bildempfang an `STATUS_LOGON_FAILURE`. Keine erneuten Anmeldeversuche im Rahmen dieses Ausbaus.
- Live-Interoperabilität von WinRM, SSH/SFTP, AD, Entra, Bitwarden, Audio, Gateway und getrennten Sitzungsfenstern mit der konkreten Benutzerumgebung.
- RD-Gateway NTLM/MFA und RemoteApp/RAIL: im eingebundenen Gateway-/Sitzungspfad nicht implementiert. Die vorhandene Gateway-Bibliothek vermerkt NTLM selbst als nicht implementierten Handshake-Pfad. Keine wirkungslosen Schalter ergänzt.
- Vollständiges gemeinsames Team-Backend mit Rollen, gleichzeitiger Bearbeitung und zentralem Audit; vorhanden sind dateibasierte Übergaben.
- Automatische Ursachenanalyse von Abhängigkeiten, freie natürlichsprachliche Auftragsplanung und selbstständige Reparatur mit nachgewiesenem Rollback; vorhanden sind explizite Abläufe, Befunde und Prüfungen.

## Verifikation

Lokale Unit-/Integrationstests prüfen Zustand, Probelauf, Import, Zielbindung, Prozessabbruch, Ausgabegrenzen, Schwärzung, Aufzeichnungsablage, Geheimnisschutz, Lernabläufe und natives Rendering in schmalen/breiten Fenstern. Diese Tests ersetzen keinen Test mit einem echten Remote-System.

Abschließend: `cargo test -- --test-threads=1` – **224 bestanden, 0 fehlgeschlagen, 4 Live-Tests ignoriert**. `cargo build` erfolgreich; drei bestehende Warnungen zu ungenutzten Kompatibilitäts-/Metrikfeldern. `git diff --check` ohne Whitespace-Fehler. Unabhängige statische Reviews einschließlich Korrekturrunden abgeschlossen; keine wichtigen Befunde in der abschließenden gezielten Prüfung offen.

Die native Mission-Control-Startansicht wurde per `--gui-capture` mit dem echten Renderer aufgenommen und visuell geprüft: [Startansicht](gui-concepts/mission-control-implemented.png). Alle neuen Ansichten wurden zusätzlich bei 640 und 1440 logischen Pixeln ohne automatische Verbindungen gerendert. Live-RDP-Interaktion und alle umgebungsabhängigen Connectoren bleiben unbestätigt.
