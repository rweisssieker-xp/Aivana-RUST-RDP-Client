# Relayne: zusätzliche Änderungs- und Prüfwerkzeuge

**Historischer Entwicklungsstand:** Die unten genannten 16-KiB-, Signatur-, ACL- und Prozedurgrenzen wurden teilweise durch den [aktuellen erweiterten Funktionsumfang](relayne-expanded-usps.md) ersetzt. Für noch offene Punkte und neue Abnahmeergebnisse ist diese aktuelle Übersicht maßgeblich.

**Weiterentwicklung:** Für Windows-Dienstaufträge mit HTTP-Prüfung ist inzwischen der [gebundene Übergang vom Klontest zur Produktionsfreigabe](relayne-promotion.md) implementiert. Die nachfolgend dokumentierte frühere Grenze „keine Produktionsfreigabe aus diesem Lab-Nachweis“ ist für diesen ausdrücklich beschriebenen Pfad aufgehoben. Andere Protokolle und beliebige Aufträge sind weiterhin nicht automatisch mit dem Lab verbunden.

Stand: 11. September 2026. Diese Erweiterung ergänzt die [sechs zuvor integrierten Arbeitsabläufe](relayne-six-usps.md). Die Tabelle trennt den ausführbaren Umfang von weiterhin offenen Erweiterungen und Infrastrukturabnahmen.

| Vorschlag | Implementierter Ablauf | Grenzen |
|---|---|---|
| Änderungs-Zeitmaschine | Vorher-/Nachher-Inhalte bestehender Dateien und REG_SZ-Werte, verschlüsseltes Journal vor Mutation, Vergleich vor Änderung und Wiederherstellung, lokale PowerShell oder WinRM | 16 KiB pro Inhalt, 128 Einträge; keine Berechtigungen, gelöschten Objekte oder universelle Anwendungskonfiguration. Dienstwiederherstellung bleibt im vorhandenen Ausführungsmodul |
| Automatisches Testlabor | Hyper-V-VM aus Offline-VHDX mit Differenzdatenträger und privatem Switch; PowerShell-Direct-Dienständerung, optionale lokale HTTP-Prüfung, Wiederherstellung bei Fehler; kontrolliertes Aufräumen eigener Ressourcen | Vorbereitete Windows-Generation-2-Vorlage und Gastzugang erforderlich; kein universeller Produktionsklon, kein automatischer Transfer beliebiger Aufträge, keine Produktionsfreigabe aus diesem Lab-Nachweis |
| Protokollübergreifende Aufträge | Serieller Plan aus SSH, festen WinRM-Operationen, HTTP und RDP-Prüfpunkten; Voraussetzungen, Aktion, Ergebnisprüfung, separat geprüfte Wiederherstellung | RDP-Prüfpunkte senden keine automatischen Eingaben. Beliebige plattformübergreifende Transaktionen und automatische Kompensation sind nicht enthalten |
| Störungsrekonstruktion | Gemeinsame gefilterte Zeitleiste aus Telemetrie, Dienstabweichungen, Sitzungsaktionen, Änderungsjournal und Prüfergebnissen; zeitliche Hypothesen mit Quellen | Kein Kausalitätsbeweis; Uhrabweichungen und Erfassungsintervalle bleiben relevant. Frei deklarierte Workflow-Ziele werden nicht anhand unbestätigter Profil-IDs mit Telemetrie verknüpft |
| Fachliche Funktionsprüfung | Mehrstufige HTTP-Anmeldung und Folgeaufrufe mit temporären Geheimnissen, begrenzten Sitzungscookies, Status-, Text- und JSON-Prüfungen; optional exakter OCR-Textnachweis am aktuellen RDP-Bild | Anwendungsspezifische Prüfschritte müssen beschrieben werden; kein allgemeiner Browser-/SSO-Automat. OCR bestätigt sichtbaren Text, keine fachliche Transaktion |
| Reparaturpakete | Versioniertes JSON-Paket mit Herkunftsangabe, Voraussetzungen, Aktionen, Prüfungen und Wiederherstellung; Integritätsprüfung, Größen-/Schemavalidierung, inaktiver Import | Prüfsumme ist keine Herausgebersignatur. Feste Befehle und Formularwerte sind Paketinhalt und müssen vor Weitergabe geprüft werden |

## Nachweise und Unterbrechungen

OCR-Nachweise binden einen eindeutigen Prüfschritt-Token, die aktuelle unveränderte Profilsitzung, den Verbindungsbeginn und das konkrete Bild. Ein Bild muss nach Aktivierung des Prüfschritts empfangen worden sein; veraltete Bilder, Zielwechsel und mehrdeutige Wörter führen zu keinem Erfolg. Die Erkennung bleibt lokal. Manuelle Bestätigungen werden separat als Bedienerbelege ausgewiesen.

Störungszusammenhänge benötigen passende unveränderliche Endpunktkennungen. Ein später auf einen anderen Rechner umgestelltes Profil verbindet dessen neue Fehler nicht mit früheren Änderungen des alten Rechners. Alle Zusammenhänge bleiben Hypothesen.

Datei-/Registry- und Workflow-Journale werden vor Änderungen verschlüsselt gespeichert. Unterbrochene Abläufe werden nicht automatisch wiederholt. Dateiänderungen können bei einem Abbruch teilweise geschrieben sein; bei abweichendem Inhalt verweigert die Wiederherstellung ein blindes Überschreiben. Registry-Werte können nicht gegen fremde Schreiber exklusiv gesperrt werden. VM-Abbrüche zwischen Ressourcenerstellung und Journalfortschreibung können eine manuelle Zuordnung erfordern.

## Abnahme

Entwicklungsprüfungen verwenden isolierte lokale Dateien, Windows DPAPI, echte HTTP-Loopback-Server sowie tatsächlich ausgeführte PowerShell-Skripte mit bewachten Hyper-V-/Dienstmodellen. Auf diesem Entwicklungsrechner ist `Get-VM` nicht verfügbar. Eine echte Hyper-V-Generalprobe ist deshalb nicht abgenommen. Vorhandene externe Profile wurden nicht für Änderungsversuche verwendet.

Die zuvor offene authentifizierte RDP-/Gateway-/SSH-/WinRM-Abnahme, physische Monitorprüfung, produktive Teamserver-Bereitstellung, eingebettetes RAIL und zusätzliche Gateway-MFA-Verfahren werden durch diese Erweiterung nicht als erledigt erklärt.

Details: [Änderungsverlauf](relayne-change-history.md), [Testlabor](relayne-test-lab.md), [Workflows und Pakete](relayne-workflows.md), [Störungsrekonstruktion](relayne-incidents.md).

Abschließender Gesamttest: `cargo test --offline -- --test-threads=1` — **304 Anwendungstests und 8 Team-Tests bestanden, 0 fehlgeschlagen, 4 bestehende Live-Tests ignoriert**. Darunter echte lokale Dateiänderung mit Konfliktprüfung und Wiederherstellung, tatsächliche HTTP-Anmeldung mit Sitzungscookie und JSON-Nachbedingung, Abbruch nach einem fehlgeschlagenen Schritt, verschlüsselte Journale, Ablehnung alter Prüfschritt-Tokens und alter OCR-Bilder sowie ausgeführte Hyper-V-/Dienst-Testmodelle einschließlich HTTP-Fehler und Wiederherstellung.

`cargo build --offline --bins` erfolgreich; das Desktop-Programm wurde neu gebaut, das unveränderte Team-Programm war aktuell. Nicht blockierende Dead-Code-Warnungen bleiben. `git diff --check` ist sauber. Die vier neuen Ansichten wurden am nativen Renderer bei 2160 × 1536 Pixeln aufgenommen und visuell geprüft: [Änderungsverlauf](gui-concepts/relayne-changes-implemented.png), [Testlabor](gui-concepts/relayne-lab-implemented.png), [Workflows](gui-concepts/relayne-workflow-implemented.png), [Störungsrekonstruktion](gui-concepts/relayne-incident-implemented.png). Leere Zustände und die ausdrücklich dargestellte lokale Workflow-Vorlage enthalten keine erfundenen Ausführungsresultate. Die Ansichten werden außerdem bei 640 und 1440 logischen Pixeln ohne Remote-Verbindungsaufbau gerendert.
