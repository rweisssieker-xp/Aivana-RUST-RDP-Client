# Relayne: sechs integrierte Arbeitsabläufe

Stand: 11. September 2026. Alle sechs vorgeschlagenen Bereiche besitzen jetzt eine funktionierende Implementierung in der nativen Anwendung. Der unterstützte Umfang ist unten ausdrücklich begrenzt. Die Auswahl einer isolierten lokalen Testumgebung wurde vom Benutzer an Codex delegiert; es wurden keine Firmenrechner oder vorhandenen Dienstanmeldungen für Mutationstests ausgewählt.

| Bereich | Tatsächlich implementiert | Grenze |
|---|---|---|
| Einmal vormachen, auf weitere Rechner übertragen | Automatische OCR-Verankerung am beim Klick gezeigten Bild; benannte verschlüsselte Abläufe, Parameter, Zielwarteschlange, portable Text-/Kontextgeometrie, prüfbare sichtbare Nachbedingungen | Textlose Icons und allgemeine Control-Rollen werden nicht erkannt; jedes Ziel benötigt eine neue Freigabe |
| Auftrag bis zum geprüften Ergebnis | Unveränderlicher Dienstplan: Ausgangszustand und Abhängigkeiten → Freigabe → Änderung → separater HTTP/TCP-Funktionstest → unterstützte Wiederherstellung bei Fehler; Pilot und Rollout | Windows-Dienstzustand und konfigurierter Healthcheck; kein beliebiger Geschäftsprozess oder allgemeines Maschinen-Rollback |
| Änderung vorher erproben | Echte, getrennt zugeordnete Testziele führen denselben Plan aus; erfolgreicher Testnachweis bindet Plan und Zielzuordnungen für eine Stunde | Keine automatische VM-Klonerzeugung. Erfolgreiche Teständerungen bleiben auf dem Testsystem bestehen |
| Rechnerübergreifende Ursachenprüfung | Erfasste TCP-Verbindungen plus passende Ziel-Listener und Dienst-PIDs bilden den Zusammenhang; zielgerichtete Pfadprobe vom betroffenen Rechner, Ereignisverlauf und Belegreferenzen | Beobachtungen und gestützte Hypothesen, keine universelle Kausalitätsanalyse; historische Zuordnungen sind gekennzeichnet |
| Gemeinsam an einer Sitzung arbeiten | Explizit freigegebene, vor Übertragung maskierte Bilder; Raum-Mitglieder, Annotationen, kurzlebige exklusive Steuerung und unveränderliche Klickanträge mit zwei unterschiedlichen Identitäten; Ausführung nur beim freigebenden Host | HTTP-Polling, Klicksteuerung, kein gemeinsames Tippen/Clipboard; OCR-Schwärzung ist heuristisch. Server-Identitäten sind keine verifizierten natürlichen Personen |
| Passende Lösungen aus Erfahrung | Automatisch abgeleitete Dienstabläufe aus tatsächlichen Laufbelegen, getrennte Test-/Produktionsresultate, registrierbare Auftragslösungen, nachvollziehbare Rangfolge und Voraussetzungenabgleich | Dokumentierte Ergebnisse und deterministische Ähnlichkeit, keine erfundene Erfolgsprognose. Übernahme startet keine Aktion |

## Gesamtablauf für ein Ziel

Ein vollständiger semantischer Ablauf kann für fünf Minuten als Ganzes freigegeben werden, wenn sämtliche Schritte übertragbar sind, alle Parameter vorliegen und jeder Schritt sowie das Ende eine sichtbare Nachbedingung besitzt. Freigabe bindet Ablauf, Parameter, Ziel, Profil und Verbindungsinstanz. Vor jedem Schritt wird der aktuelle Zielanker aufgelöst. Während einer fehlenden Nachbedingung werden keine weiteren Eingaben gesendet; die Prüfung wartet begrenzt. Mehrdeutigkeit, Ziel-/Profilwechsel, manuelle Eingabe, Fokusverlust oder Ablaufänderung stoppen den Gesamtablauf. Die nächste Zielsitzung wird bewusst übernommen und neu freigegeben. Es werden keine Remote-Anmeldungen automatisch aufgebaut.

## Lokale Testumgebung und offene Abnahme

Die Funktionsprüfungen verwenden echte lokale HTTP-/TCP-Server, den echten Windows-OCR-Aufruf, Windows DPAPI, lokale PTYs sowie ausgeführte PowerShell-Skripte mit bewachten Dienst-/Telemetrie-Fakes. So werden auch Fehler, ungültige Voraussetzungen, veraltete Belege, Widerruf und Wiederherstellung geprüft, ohne reale Dienste zu verändern.

Abschließender Gesamtlauf: `cargo test --offline -- --test-threads=1` — **279 Anwendungstests und 8 Team-Tests bestanden, 0 fehlgeschlagen**. Vier bestehende authentifizierte Live-Tests bleiben ausgelassen. `cargo build --offline --bins` erfolgreich; beide Binärdateien wurden neu gebaut. Nicht blockierende Dead-Code-Warnungen verbleiben. Der zusätzliche Telemetrie-Test führte das tatsächlich generierte Erfassungsskript gegen bewachte PowerShell-Fakes aus und prüfte die typisierte Antwort.

Produktiver Teamserver-Betrieb, echte RDP-/Gateway-/RemoteApp-/WinRM-/SSH-Anmeldung und physische Monitorplatzierung sind weiterhin nicht extern abgenommen. Eingebettetes RAIL und zusätzliche Gateway-Einwilligungs-/MFA-Transporte sind weiterhin offen; RemoteApp nutzt den bereits vorhandenen separaten Windows-Client. Diese Arbeit liefert keine gegenteilige Vollständigkeitsbehauptung.

Details: [Vormachen](relayne-transferable.md), [Ausführung/Testlauf](relayne-execution.md), [Ursachen/Lösungen](relayne-insights.md), [Co-Working](relayne-collaboration.md).

Die Ansichten [Prüfen & Ausführen](gui-concepts/relayne-execution-implemented.png) und [Ursachen & Lösungen](gui-concepts/relayne-insights-implemented.png) wurden mit dem nativen Renderer bei 2160 × 1536 Pixeln aufgenommen und visuell geprüft. Navigation, Eingaben und leere Ergebniszustände sind lesbar; die Aufnahmen enthalten keine simulierten Messergebnisse. Verbundene Live-Sitzungen sind damit nicht abgenommen.
