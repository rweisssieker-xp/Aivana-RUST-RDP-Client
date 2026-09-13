# Erweiterte Recovery-Funktionen

Neu: [Änderungen und Fehler im Klon erproben](relayne-change-trials.md) ergänzt im Testlabor einen vollständigen Starttyp-/Dienstausfallversuch mit geprüftem Checkpoint-Rückweg. Die bisherigen geplanten Recovery-Generalproben bleiben separat und benötigen weiterhin ihren vorbereiteten Fehlerzustand.

Diese Erweiterung integriert sechs Funktionen in die bestehenden Relayne-Abläufe. Die Aktivierung externer Verbindungen und des Windows-Hintergrundauftrags erfolgt ausdrücklich in der Oberfläche.

| Funktion | Einstieg | Umsetzung |
|---|---|---|
| Dauerüberwachung | **Hintergrund** | Benutzerbezogene Windows-Aufgabe, lesende Vergleiche bei geschlossener App, ablaufende Freigaben, Meldungen und optionale lokale Windows-Hinweise. |
| Geplante Generalproben | **Hintergrund** | Exakter Plan und konkrete Klone mit DPAPI-geschütztem Gastzugang; echte Vergleiche und Klonbelege erneuern den Recovery-Vertrag. |
| Expert Procedure Compiler | **Vormachen & Lernen** | KI schlägt Parameter und Nachbedingungen für eine vorhandene Demonstration vor. Vorschau und ausdrückliche Übernahme vor bestehender Workflow-Ausführung. |
| Zusätzliche Reparatur | **Recovery Agent** | Dienstneustart für eine laufende, fachlich fehlerhafte Anwendung: fehlgeschlagene HTTP-Baseline, nachgewiesenes Stoppen, Starten und erfolgreiche Nachprüfung. |
| Kompatibilitätskatalog | **Tickets & Katalog → Kompatibilitätskatalog** | Signierte Pakete, tatsächlich geprobte Dienst-/HTTP-Semantik und echte Umgebungsfingerprints; Signaturwiderruf, Drift und Ablauf ändern den angezeigten Status. |
| Ticket-Anbindung | **Tickets & Katalog → Tickets & Ergebnisberichte** | Einzelnes Jira-Ticket lesen oder lokales JSON importieren, Inhalt prüfen, Recovery-Fall vorbereiten und Ergebnisbericht nach Vorschau ausdrücklich als Jira-Kommentar zustellen. |

## Hintergrundbetrieb und Generalproben

Die Windows-Aufgabe arbeitet alle fünf Minuten unter dem angemeldeten Benutzer, auch bei geschlossener Oberfläche. Sie ist kein Windows-Dienst für abgemeldete Benutzer und erhöht keine Rechte. Autorisierung gilt höchstens 168 Stunden; Ziel-/Planänderung, Ablauf oder Widerruf stoppen weitere Arbeit. **Alles deaktivieren & Aufgabe entfernen** löscht zunächst Freigaben und Gastzugänge. Details: [Hintergrundbetrieb](recovery-background.md).

Generalproben benötigen vorhandene gestartete, isolierte Klone im passenden Fehlerzustand. Relayne erzeugt keine Fehler und setzt keine VM automatisch auf einen Checkpoint zurück. Nach einer erfolgreichen Reparatur muss der Fehlerzustand für den nächsten Reparaturtest wieder vorbereitet werden. Andernfalls wird keine neue erfolgreiche Reparatur behauptet. Zusätzliche HTTP-Geheimwerte bleiben Aufgabe der manuellen Generalprobe. Es gibt keine geplanten Produktionsänderungen.

## Dienstneustart

Der neue Reparaturtyp ist auf einen ausdrücklich benannten Windows-Dienst begrenzt. Sowohl im Klon als auch vor dem Produktionsschritt müssen der laufende Ausgangszustand und ein fehlgeschlagener Anwendungstest belegt sein. Laufende abhängige Dienste oder nicht laufende Voraussetzungen sperren den Neustart. Ein nachgewiesener gestoppter Zwischenzustand gehört zum Beleg; bloß „vorher Running, nachher Running“ genügt nicht. Bei Fehlern wird die Rückkehr zum ursprünglichen Dienstzustand versucht. Das stellt keine verlorenen Sitzungen oder Anwendungsdaten wieder her. Vorher gespeicherte Startpläne behalten ihre bisherigen Hashes und ihr Verhalten.

## Kompatibilitätskatalog

Zunächst in **Workflows** einen lokalen Herausgeberschlüssel und explizites Herausgebervertrauen konfigurieren. Im Katalog einen frischen Recovery-Plan mit einer Zielzuordnung auswählen, daraus ein passendes Paket erzeugen und signieren oder ein bereits signiertes Paket einfügen. Die Aufnahme prüft die Signatur, exakte Dienstoperation, Hostbindung und identische öffentliche HTTP-GET-Kriterien gegen echte frische Generalprobenbelege. Zusätzliche Paketaktionen oder Restore-Schritte werden nicht als passend akzeptiert.

Ein Eintrag hält die zum Aufnahmezeitpunkt belegten Fingerprints fest. Der aktuelle Recovery-Vertrag liefert die Vergleichsbasis; entfernte Verträge, abgelaufene Vergleiche oder widerrufenes Vertrauen ergeben **Unbekannt**, Änderungen ergeben **Nicht kompatibel**. Das ist keine allgemeine Kompatibilitätsgarantie für andere Rechner oder Versionen. **Als neue Generalprobe vorbereiten** übernimmt den Plan in den bestehenden Prüfprozess, niemals direkt in die Produktion. Signierte Pakete können kopiert und über die vorhandenen Paketwege verteilt werden. Ein gehosteter Marktplatz oder herstellerübergreifendes Kompatibilitätsnetz wird nicht betrieben.

## Tickets und Zustellung

Jira benötigt einen HTTPS-Ursprung ohne Zusatzpfad, einen konkreten Ticket-Schlüssel sowie E-Mail und API-Token für REST API v3. Das Token bleibt nur im Arbeitsspeicher und wird nach einer Anfrage aus dem Eingabefeld entfernt. Nur ausdrücklich angeforderte Tickets werden gelesen. Externer Text bleibt ungeprüfter Inhalt und kann keine Befehle oder Reparaturen starten.

Der JSON-Import verwendet `origin`, `key`, `title`, `description` und `revision`; für lokale Tickets ist `origin` gleich `local`. Origin und Schlüssel bilden die lokale Identität. Identische Wiederholungen erzeugen kein weiteres Ticket, geänderte Inhalte entfernen die Fallzuordnung und benötigen neue Prüfung. Die aus Ticketidentität und Dienst abgeleitete Fall-ID verhindert doppelte Recovery-Fälle beim Wiederholen einer unterbrochenen Zuordnung.

Der Ergebnisbericht entsteht aus dem gespeicherten Recovery-Fall und tatsächlichen Ausführungsbelegen. Er kennzeichnet historische, offene und unbestätigte Ergebnisse. **Bericht kopieren** funktioniert ohne Jira. Für Jira wird erst die konkrete Vorschau bestätigt, dann der Bericht erneut auf Aktualität geprüft und ein Zustellversuch lokal gespeichert, bevor der HTTP-Aufruf beginnt. Weiterleitungen und automatische Wiederholungen sind deaktiviert.

Bei Timeout oder Abbruch bleibt die Zustellung **ungeklärt**. Die Zustell-ID steht im Jira-Kommentar und im lokalen Journal. Nach mindestens zwei Minuten kann ein Betreiber nach tatsächlicher Prüfung in Jira dokumentieren, ob der Kommentar angekommen ist. Erst die bestätigte Nichtzustellung erlaubt einen erneuten, ausdrücklich freigegebenen Versand; eine manuell bestätigte Zustellung bleibt von einer technisch bestätigten Zustellung unterscheidbar.

Ticketspeicher: höchstens 128 Tickets, 64 Zustellversuche pro Ticket und 2 MiB; Katalog: höchstens 64 Einträge und 8 MiB. Beide Speicher sind lokal DPAPI-geschützt und lehnen veraltete parallele Schreibversuche ab. Jira-Webhook-Verarbeitung, weitere Ticketanbieter und automatische externe Eskalationen sind nicht enthalten.

## Betrieb und Abnahme

Verifiziert am 12.09.2026: Die vollständige Offline-Testsuite bestand mit 416 Anwendungstests und 16 Team-Tests; fünf bestehende Tests blieben ignoriert. Nach der abschließenden Härtung des Katalogspeichers bestanden zusätzlich alle vier gezielt ausgeführten Katalogtests. `cargo check --offline --bins` und `cargo build --offline --bins` waren erfolgreich. Die nativen Ansichten wurden aufgenommen und visuell geprüft: [Hintergrund](gui-concepts/relayne-background.png) und [Tickets & Katalog](gui-concepts/relayne-ticket-catalog.png).

Siehe [Compiler](expert-procedure-compiler.md), [KI-Anwendungstests](relayne-ai-application-tests.md) und [Recovery-Pläne](relayne-living-recovery-plans.md). Entwicklungstests verwenden lokale Daten und bewachte Adapter. Für produktive Nutzung bleiben die echte Windows-Aufgabenplanung, erreichbare WinRM-/Hyper-V-Ziele, die Modellqualität und ein konfiguriertes Jira-Konto separat abzunehmen.
