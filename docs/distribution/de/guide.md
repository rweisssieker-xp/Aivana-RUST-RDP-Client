# Relayne — Auslieferungs- und Betriebshandbuch

Entwicklungsentwurf · 2026-09-13 · de

## Stand und Umfang
Dies ist eine unsignierte Entwicklungsauslieferung, kein freigegebenes Verkaufsrelease. Für Remote-Recovery und Protokolle bestehen lokale Tests, aber keine abgeschlossene Kundenabnahme. Die neue Release-Ansicht und dieses Handbuch sind in en-US, de, fr und it verfügbar. Fachansichten und ältere technische Dokumente sind teilweise weiterhin deutsch; vollständige Produktübersetzung bleibt eine Release-Voraussetzung.

## Anbieter und Kontakt
Aivana GmbH
Paulusstr. 45a - Hinterhaus - LOFT45
33602 Bielefeld, Germany
info@aivana-gmbh.ai · +49 521 92278996
Amtsgericht Bielefeld · HRB 46421 · DE459356027
https://www.aivana-gmbh.ai
https://aivana-gmbh.ai/Imprint

Öffentliches Impressum am 13.09.2026 geprüft. Geschäftsführer: Udo Bergmann. Dies ist der allgemeine Geschäftskontakt, keine zugesagte Support-SLA und kein gesondert benannter Datenschutzbeauftragter. Die Datenschutzseite der Website bezeichnet sich derzeit als Mustertext. Produktspezifische Bedingungen und Datenschutzfreigabe stehen aus.

## Voraussetzungen und Installation
Windows x64. Relayne vor der Installation schließen. Administratorrechte sind nicht erforderlich. Das Paket installiert kein Hyper-V, aktiviert keinen Fernzugriff, konfiguriert keine Hosts und erzeugt keine Zugangsdaten. Externe Protokollvoraussetzungen benötigen eine separate Abnahme.
Das gesamte Paket in ein neues Verzeichnis entpacken. Prüfen: powershell -File .\Test-Package.ps1 -PackageRoot .
Nur für dieses unsignierte Dev-Paket: powershell -File .\Install-Relayne.ps1 -Language de -AllowUnsignedDev
Die Installation kopiert ausschließlich Manifestdateien in ein neues Versionsverzeichnis unter LOCALAPPDATA\Relayne\versions. Vorhandene Versionen werden nicht überschrieben. Den ausgegebenen Pfad zu relayne.exe manuell starten. Sprache in der Anwendung wählen; vorhandene Fachansichten können unübersetzt bleiben.

## Updates und Rückkehr zu einer älteren Version
Jedes Paket wird neben der bisherigen Version installiert. Ein automatischer Updater oder Downloaddienst ist nicht enthalten. Anwendung schließen und die ältere Programmdatei starten. Zuvor Anwendungsdaten sichern: Der Rückweg der Programmdatei setzt keine Datenbank- oder Konfigurationsänderungen zurück. Ohne Prüfung besteht keine Zusage zur Datenkompatibilität. Eine fehlgeschlagene Paketprüfung lässt bestehende Installationen unverändert.

## Deinstallation
powershell -File .\Uninstall-Relayne.ps1 -Version VERSION -Language de aus einem vertrauenswürdigen Paket ausführen. Nur das geprüfte Versionsverzeichnis wird entfernt. Benutzerprofile, Zugangsdaten, Protokolle und Anwendungsdaten bleiben erhalten. Deinstallation kündigt kein Abonnement. In diesem Entwicklungsstand besteht kein aktives Abonnement.

## Integrität und Sicherheitsgrenzen
Test-Package.ps1 prüft eine strikte Dateiliste und SHA-256-Prüfsummen. Das erkennt beschädigte Dateien; ein mitgeliefertes unsigniertes Manifest bestätigt nicht den Herausgeber. Öffentliche Codesignatur und ein vertrauenswürdiger Release-Kanal fehlen weiterhin. Install-Relayne.ps1 verweigert dieses Dev-Paket ohne ausdrückliches AllowUnsignedDev. Es werden weder Konto, geplanter Task, Dienst, Firewallregel noch Remote-Verbindung angelegt.

## Daten und Datenschutz — technischer Entwurf
Profile, Einstellungen, Nachweise und Protokolle werden lokal gespeichert. Bestehende Zugangsdaten- und geschützte Fallspeicher verwenden Windows DPAPI, soweit implementiert; nicht sämtliche Anwendungsdateien sind verschlüsselt. Windows-Kontoschutz und Dateizugriff bleiben relevant. Ein konfigurierter Remote-Host, Teamserver oder optionaler KI-Anbieter kann über den jeweiligen Anwendungsablauf Daten erhalten; Installer und Release-Ansicht versenden diese nicht. Störungstexte, Screenshots und Exporte vor Weitergabe prüfen; automatische Schwärzung bietet keine Garantie. Aufbewahrung, Rechtsgrundlagen, Auftragsverarbeitung, Drittlandtransfers und Löschverfahren benötigen eine produktspezifische Prüfung. Diese Release-Arbeit ergänzt weder Telemetrie noch automatischen Absturz-Upload.

## Support und Störungsmeldung
Version, Windows-Version, Reproduktionsschritte, erwartetes/tatsächliches Ergebnis und bereinigte Protokolle an den allgemeinen Kontakt melden. Passwörter, Tokens, Kundenscreenshots oder Hostdetails erst nach Vereinbarung eines sicheren Kanals übermitteln. Eine verbindliche Reaktionszeit besteht noch nicht. Sicherheitsmeldungen, Eskalationsverantwortung und unterstützte Umgebungen sind vor Verkauf festzulegen.

## Preis, Lizenz und Kündigung — kein Angebot
9,99 EUR je Nutzer und Monat sind eine Preisidee. Netto-/Bruttobehandlung, Rechnungsdetails, Zahlungsanbieter, Erstattung, Kündigung und Supportanspruch sind nicht abschließend festgelegt. Checkout und kommerzielle Aktivierung sind deaktiviert. Dieses Handbuch erteilt keine kommerzielle Lizenz und ist weder Vertrag noch Rechtsberatung. Hinweise zu Drittanbieterabhängigkeiten und Lizenzverträglichkeit müssen vor externer Auslieferung geprüft werden.

## Release-Nachweise
Das Paketmanifest enthält Version, Quellrevision, Status uncommitteter Änderungen, Entwicklungskanal und exakte Prüfsummen. Lokale Umgebungsdateien, Profile, Geheimnisse, Testlogs und Kundennachweise sind ausgeschlossen. Für ein künftiges Release geprüfte Build-Hashes und tatsächliche Testergebnisse festhalten; grüne Entwicklungstests allein belegen keine Verkaufsfähigkeit.
