# Rechnerzentrale und native RDP-Erweiterungen

Stand: 10. September 2026. Die Umsetzung bleibt eine native Rust/egui-Anwendung.

## Bedienung

- **Rechnerzentrale:** Rechner suchen, nach Gruppe/Favoriten filtern, Zeile auswählen. Die Auswahl allein öffnet keine Verbindung. Über den rechten Bereich verbinden oder eine bestehende Sitzung öffnen.
- **Vorschauen:** Die bisherigen Raster-/Listenansichten bleiben erreichbar. Eine große Vorschau wird ausdrücklich im Kachelmenü gewählt.
- **Sitzung:** Dunkle Arbeitsansicht mit Anpassen/100 %, Vollbild, Dateien, Nebeneinander, KI und Zeitleiste. Im Vergleich erhält nur die aktive Sitzung Eingaben; die zweite wird durch Aktivieren oder Klick auf ihre Vorschau aktiv.
- **Tastatur:** Strg+K öffnet Aktionen in der Rechnerzentrale; innerhalb einer Sitzung ist es Strg+Umschalt+K, damit Strg+K an Windows weitergereicht wird. Gedrückte Tasten/Maustasten werden bei Fokusverlust freigegeben.
- **Profile:** Anzeige, automatische Wiederverbindung, Zwischenablage, Audio, Mikrofon, Ordner und Gateway werden im Profil eingestellt und beim nächsten Verbindungsaufbau verwendet.
- **Import/Export:** Dateipfad zu .rdp, .csv oder .json eingeben. Für Export gewünschte Profile mit Kontrollkästchen wählen. .rdp enthält ein Profil; CSV/JSON können mehrere enthalten. Zugangsdaten werden nicht exportiert. Mehrfachauswahl erlaubt Gruppenänderung und Favoritenmarkierung.
- **Dateien:** Lokale Dateipfade zeilenweise bereitstellen, anschließend im Remote-Explorer einfügen. Für die Gegenrichtung Dateien remote kopieren und einen lokalen Zielordner angeben. Ergebnisse stehen im Ereignisverlauf.
- **Darstellung:** Vergrößerung der Bedienoberfläche unter Einstellungen; diese ist unabhängig von der Remote-Auflösung.

## Implementierung und Grenzen

| Funktion | Implementiert | Grenze / Voraussetzung |
|---|---|---|
| Eingaben | Key-down/up, Maustasten-down/up, Ziehen, Rad, Text, Zwischenablage-Tastenkombinationen | egui vereinigt einige linke/rechte Modifikatortasten; Betriebssystem-reservierte Tastenkombinationen bleiben lokal |
| Wiederverbindung | Fünf Versuche mit begrenztem Backoff, Abbruch, kein paralleler Ersatzworker | Nur vorübergehende Verbindungsfehler; Authentifizierungs-/Zertifikatsfehler werden nicht blind wiederholt |
| Text-Zwischenablage | CLIPRDR, synchronisierte exklusive Zuordnung zur fokussierten Sitzung | Im Profil ausdrücklich aktivieren; Serverrichtlinie muss es erlauben |
| Dateien | CLIPRDR Dateiliste und begrenzte Datenblöcke in beide Richtungen | Einzeldateien; Ordner als ZIP. Vorhandene Zieldateien werden nicht überschrieben |
| Anzeige | Display Control, ausstehende Größenänderung, Reaktivierung, mehrere Remote-Monitore | Server muss dynamische Anzeige anbieten. Die Anordnung beschreibt Remote-Monitore, keine automatisch verteilten lokalen App-Fenster |
| Wiedergabe | Native CPAL-Ausgabe, PCM16, Fehlerdiagnose | Gemeinsames PCM-Format und lokales Audiogerät erforderlich |
| Mikrofon | AUDIO_INPUT-DVC, PCM16, begrenzte Warteschlange, native Aufnahme | Mono/Stereo, unterstütztes ausgehandeltes Format. Aufnahme nur bei aktivierter Option und Kanalöffnung; Abbruch stoppt unabhängig von Netzwerk-Wartezeiten |
| Ordnerfreigaben | RDPDR: Erstellen, Lesen/Schreiben, Auflisten, Dateiinformation, Löschen, Kürzen und Datei-Umbenennen | Nur freigegebene Ordner; Lesezugriff erzwingbar. Freigabename 1–7 ASCII-Zeichen. Verzeichnisumbenennen und Überschreiben beim Umbenennen nicht unterstützt; Datei-Umbenennen benötigt Hardlinks |
| Gateway | Nativer TLS/WebSocket-Transport, getrennte geschützte Zugangsdaten | HTTP Basic, Zielport 3389. Kein NTLM/MFA/Zustimmungsdialog und keine IPv6-Gateway-Adresse; Zertifikat muss Systemvertrauen erfüllen |
| Zertifikate | Prüfung im Hintergrund, Ergebnis an unverändertes Profil gebunden | Eine Auswahländerung verwirft das Ergebnis; kein automatisches Vertrauen |

## Verifikation

GUI-, Eingabe-, Wiederverbindungs-, Import-, Gateway-Validierungs-, Dateisystem- und Kanaltests werden mit `cargo test -- --test-threads=1` ausgeführt. Tests mit echtem RDP-Server bleiben separat und werden nicht durch Unit-Tests ersetzt.

`--gui-capture <PNG-Dateipfad>` fordert einen Screenshot direkt aus dem nativen Renderer an und schließt die App danach. Es werden keine Verbindungen automatisch geöffnet. Ein schwarzer Windows-Desktop-Screenshot gilt nicht als bestandene visuelle Prüfung.

Die Grenzen oben sind Teil des Funktionsumfangs; erfolgreicher Build und Protokolltests belegen noch keine Interoperabilität mit einem konkreten Gateway, RDP-Server oder Audiogerät.

### Live-Test am 10. September 2026

Das hinterlegte Testziel war per Vorprüfung erreichbar. Der anschließende native Smoke-Test scheiterte an der CredSSP-Anmeldung mit `STATUS_LOGON_FAILURE (0xc000006d)` vor dem Bildempfang. Die Anmeldung wurde nicht wiederholt. Für die vollständige Live-Abnahme sind lokal gültige Zugangsdaten erforderlich. Die Fehlerklassifizierung wurde anschließend gegen genau diese Meldung abgesichert, damit automatische Wiederverbindung daraus keine weiteren Anmeldeversuche macht.

Abschließende lokale Prüfung: `cargo test -- --test-threads=1` — 183 bestanden, 0 fehlgeschlagen, 4 ignoriert. `cargo build` erfolgreich. Drei Warnungen betreffen ungenutzte Kompatibilitäts-/Metrikfelder; keine Compilerfehler.
