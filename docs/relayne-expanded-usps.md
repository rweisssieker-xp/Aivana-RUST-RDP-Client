# Relayne: erweiterter Funktionsumfang

Diese Übersicht ersetzt die früheren Umfangsgrenzen in `relayne-next-usps.md`. Die genaue Abnahme steht in `relayne-acceptance.md`.

| Bereich | Neue Umsetzung | Geltungsbereich |
|---|---|---|
| Reparaturpakete | Ed25519-Signaturen, lokale Herausgeberschlüssel, Vertrauensspeicher, Widerruf und begrenzter HTTPS-Download | Lokale Vertrauensverwaltung; Import bleibt ein prüfbarer Entwurf |
| Klonfreigabe | Automatischer Vergleich von OS/Build, Architektur, Dienstkonfiguration, Abhängigkeiten und Binärdatei vor Klontest; verpflichtender frischer Vergleichsbeleg | Windows-Dienste, WinRM und PowerShell Direct; keine universelle Gleichheit aller Anwendungsdaten |
| Fachliche Klonprüfung | Bis vier HTTP-Aufrufe mit GET/POST, Formularen, Sitzungscookies, Status/Text sowie JSON-Pointer-Prüfungen; getrennte HTTPS-Secret-Slots für Klon und Produktion | JSON-Assertions für String/Bool/null und Ganzzahlen bis ±9007199254740991; Prüfpfade und Erfolgskriterien werden ausdrücklich definiert |
| Wiederherstellung | Dateien bis 1 MiB, sechs Registrytypen, Dateiberechtigungen und sicher begrenzte Wiederherstellung inzwischen gelöschter Dateien | Keine vollständigen Dateisystem-/Registrybaum- oder VM-Snapshots |
| Demonstrierte Abläufe | Textlose Iconvorlagen, Verschiebungserkennung, Konfidenz- und Mehrdeutigkeitsprüfung; vollständige Prozedur als Workflow-Schritt | Unterstützte Klick-/Parameterschritte mit frischen OCR-Nachbedingungen; keine allgemeine visuelle Objekterkennung |
| Workflow-Zuordnung | Eindeutige lokale SSH-Identität; RDP-Prozedur bindet Profil-Snapshot an tatsächlich ausgewählte Sitzung | Unbestätigte HTTP-/WinRM-/manuelle RDP-Zuordnungen werden nicht als gesichert ausgegeben |
| Gemeinsame Arbeit | Komprimierte maskierte Bilder, Aktualisierung bis fünfmal pro Sekunde, einzeln freigegebene Navigationstasten | OCR, Netzwerk und UI begrenzen reale Bildrate; kein 30/60-fps-Videostream oder freie Tastaturweiterleitung |
| RemoteApp | Windows ActiveX-Control im Prozess, native GUI-Verwaltung, explizites Trennen | Windows-Komponente erforderlich; RemoteApp kann eigene Programmfenster öffnen, kein IronRDP-RAIL-Compositor |
| Gateway | Explizite Server-Zustimmung und einmaliger PAA-Anbieter-Cookie | Kein allgemeiner OTP-Code; Anbieter muss den PAA-Anmeldeablauf bereitstellen |
| Unternehmensidentität | Browseranmeldung mit Authorization Code und PKCE, RS256-OIDC-Prüfung mit Discovery/JWKS, feste Rollenbindungen und aktuelle Berechtigungsprüfung vor Team-Eingaben | Ein konfigurierter Anbieter und registrierte öffentliche Desktop-App; keine ungeprüften Proxy-Identitäten |

## Bedienung

- **Workflows:** Herausgeberverwaltung öffnen, Schlüssel erzeugen oder geprüften öffentlichen Schlüssel eintragen; Paket importieren/herunterladen, Inhalt prüfen und explizit starten.
- **Vormachen:** Eine Prozedur mit Nachbedingungen aufzeichnen, Iconvorschläge visuell prüfen, anschließend „Als Workflow vorbereiten“ wählen. Laufzeitwerte werden separat über benannte Slots eingetragen.
- **Klon → Produktion:** Vorbereitete Offline-Vorlage und Produktionsprofile zuordnen, Gastzugang nur für den Worker bereitstellen. Abgleich, Klontest und Produktionsfreigabe bleiben nachvollziehbare separate Schritte.
- **Team:** Bildfreigabe und Steuerungsrecht ausdrücklich erteilen. Klick oder Einzeltaste benötigt zwei unterschiedliche berechtigte Identitäten; der Besitzer prüft und führt den unveränderlichen Antrag einmal aus.
- **RemoteApp:** Gespeichertes Profil mit RemoteApp-Konfiguration im Windows-Control öffnen. Gateway-Zustimmung oder PAA-Abfrage erscheinen nur bei entsprechendem Verbindungsaufbau.

## Infrastrukturabhängige Abnahme

Authentifizierte externe RDP-, SSH-, WinRM- und Gateway-Verbindungen, echte Hyper-V-Klontests, ein konfigurierter Unternehmensanbieter und physische Mehrmonitor-Fälle benötigen entsprechende erreichbare Infrastruktur. Lokale Tests ersetzen diese Abnahmen nicht. Auf dem Entwicklungsrechner fehlt `Get-VM`; für Änderungen werden isolierte lokale Testdateien, Registrywerte und bewachte Dienst-/Hyper-V-Modelle verwendet.

Details: [Signaturen](relayne-signed-packages.md), [Abgleich](clone-production-equivalence.md), [Änderungsverlauf](relayne-change-history.md), [Icon-Prozeduren](relayne-icon-procedures.md), [OIDC](relayne-team-oidc.md), [Protokolle](relayne-protocols.md).
