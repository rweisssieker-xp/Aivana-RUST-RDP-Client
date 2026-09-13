# Änderungen und Fehler im Klon erproben

Unter **Isoliertes Testlabor** kann ein ausgewählter Relayne-Klon jetzt einen vollständigen Änderungsversuch durchlaufen. Die erste unterstützte Änderung ist der Starttyp eines Windows-Anwendungsdienstes: **Automatic ↔ Manual**. Das ist noch kein Update-, Paket- oder beliebiger Konfigurationsinstaller.

## Ablauf

1. Laufenden, gesunden Klon und HTTP-Baseline prüfen. Der aktuelle Starttyp muss unterstützt sein und sich vom gewünschten Starttyp unterscheiden.
2. Ausgangs-Starttyp geschützt speichern und einen eindeutig benannten Hyper-V-Standardprüfpunkt erstellen.
3. Starttyp ändern und Dienststatus sowie HTTP-Prüfung kontrollieren.
4. Dienst stoppen. Sowohl `Stopped` als auch das Scheitern derselben HTTP-Prüfung müssen beobachtet werden. Ein weiterhin gesunder HTTP-Endpunkt liefert keinen Fehlernachweis.
5. Dienst starten und `Running` sowie HTTP-Erfolg nachweisen.
6. Prüfpunkt zurückspielen. Ursprünglichen Starttyp, laufenden Dienst und gesunde HTTP-Prüfung kontrollieren. Erst dann den eigenen Prüfpunkt entfernen.

Der Klon kehrt dadurch nach einem abgeschlossenen Versuch wieder zum gesunden Ausgangszustand zurück und kann erneut getestet werden. Auch nach einem fehlgeschlagenen Änderungs- oder Reparaturschritt wird der Rückweg versucht. Der Starttyp wird im laufenden Gast geprüft; ein Betriebssystemneustart und das spätere automatische Startverhalten sind nicht Bestandteil dieses Nachweises.

## Voraussetzungen und Bedienung

- Vorhandener, laufender Relayne-Klon mit eigener privater Hyper-V-Netzwerkverbindung, einem nachvollziehbaren Kindlaufwerk und unveränderter VM-Identität.
- **Standardprüfpunkte mit Arbeitsspeicher**, keine vorhandenen Prüfpunkte. Neue Relayne-Klone erhalten diese Einstellung; ältere Klone im Hyper-V-Manager prüfen.
- Gastzugang über PowerShell Direct und die nötigen Hyper-V-/Dienstrechte. Keine automatische Rechteerhöhung.
- Anwendung mit genau einer öffentlichen HTTP(S)-GET-Prüfung auf Loopback. Keine Zugangsdaten, Folgeprüfungen oder Weiterleitungen. Antworten sind zeitlich und auf 64 KiB begrenzt.
- Stabiler laufender Dienst, Starttyp Automatic oder Manual ohne verzögerten Start. Laufende abhängige Dienste, inaktive Voraussetzungen und reservierte Infrastruktur-Dienstnamen sperren den Versuch.

Dienst, Zielstarttyp, HTTP-Prüfung und Gastzugang eintragen, **Versuch vorbereiten …** wählen und die eingefrorene Auswahl prüfen. **Diesen Klonversuch jetzt ausführen** beginnt den Lauf. Der Klon darf währenddessen nicht anderweitig verändert werden; der Rückweg verwirft Änderungen seit seinem Prüfpunkt. Es werden keine produktiven Maschinen angesprochen und keine geplanten Läufe installiert.

## Nachweise und Abbruch

Vor dem ersten Adapteraufruf wird ein unveränderlicher DPAPI-geschützter Auftrag gespeichert. Auftragshash, konkrete VM, Dienst, Zielstarttyp und HTTP-Kriterien sind gebunden. Ergebnis und separat bestätigter Rückweg werden getrennt gespeichert. Gastpasswörter bleiben transient und werden nach Übergabe aus dem Formular entfernt; sie stehen weder in Aufträgen noch in Prozessargumenten.

Nur belegte Baseline, Änderung, Ausfall, Reparatur, Rückkehr und Prüfpunktentfernung ergeben **Bestanden**. Ein Fehlschlag mit erfolgreichem Rückweg bleibt ein fehlgeschlagener Versuch. Ein später separat bestätigter Rückweg macht einen abgebrochenen Versuch ebenfalls nicht erfolgreich. Die Belege ersetzen keine Recovery-/Produktionsfreigabe und sagen nichts über den aktuellen Zustand anderer Maschinen aus.

Offene oder beschädigte Belege sperren weitere Versuche in diesem Klon. Bei Abbruch die gespeicherten Belege laden und **Rückweg … vorbereiten** wählen; dafür den Gastzugang erneut eingeben. Der Adapter akzeptiert ausschließlich den eindeutig zugeordneten Prüfpunkt und die geschützte Baseline. Fehlt der Prüfpunkt oder lässt sich die Rückkehr nicht verifizieren, bleibt die Sperre bestehen und die VM muss manuell untersucht werden. Pro Klon sind maximal 100 gespeicherte Versuche vorgesehen; es gibt keine automatische Beleglöschung.

## Grenzen der ersten Version

Keine Betriebssystemupdates, Paketinstallation, beliebigen Skripte, automatischen Produktionsänderungen oder KI-generierten Fehleraktionen. Keine Fehlerexperimente außerhalb des Klons. Reale Hyper-V-Prüfpunktoperationen und Gastintegration benötigen eine Abnahme in der vorgesehenen Testumgebung. Lokale automatisierte Tests verwenden Ersatzimplementierungen für Hyper-V und Windows-Dienstoperationen; HTTP-Verifikation läuft dabei auch gegen einen echten lokalen HTTP-Server.

## Lokale Prüfung am 12.09.2026

Die neun neuen Regressionstests bestanden. Sie prüfen Auftragsbindung, beschädigten Speicher, offene Aufträge, Phasennachweise, getrennte Wiederherstellung, fremde VM-/Netzwerk-/Laufwerkszuordnungen und die Oberfläche bei 640/1440 Pixel Breite. Der HTTP-Test prüft zusätzlich, dass ein fehlerhafter Anwendungszustand nach dem Zurückspielen die Prüfpunktentfernung verhindert.

`cargo build --offline --bins` war erfolgreich. Die native [Testlabor-Ansicht](gui-concepts/relayne-change-trials.png) wurde aufgenommen und visuell geprüft. Formatierung und `git diff --check` bestanden.

Bei der Gesamtprüfung wurde zusätzlich ein OCR-Lebensdauerfehler gefunden: Windows-Aktivierungsobjekte blieben global gecacht, nachdem der letzte kurzlebige OCR-Worker die Laufzeit freigegeben hatte. Nach einer längeren Pause konnte die nächste OCR-Anfrage mit `STATUS_ACCESS_VIOLATION` abstürzen. Ein gezielter Regressionstest mit 35 Sekunden Pause reproduzierte das Problem. Die OCR hält jetzt eine MTA-Nutzungsreferenz für die Prozesslebensdauer; die Initialisierung einzelner Worker bleibt ausgeglichen. Der ursprüngliche OCR-Test und der neue Pausentest bestehen mit der Korrektur. Details: [Untersuchung und Prüfplan](superpowers/plans/2026-09-12-ocr-runtime-lifetime.md).

Abschließende Prüfung nach der OCR-Korrektur: **427 Anwendungstests und 16 Team-Tests bestanden** im vollständigen Lauf ohne Filter oder zusätzliche Ausnahmen. Fünf bereits bestehende Tests blieben ignoriert. Beide Programme wurden erfolgreich neu gebaut; Formatierung und Diff-Prüfung bestanden.

## Voraussetzungen der Live-Abnahme

Die lesende lokale Prüfung fand weder das Hyper-V-Modul in Windows PowerShell noch den VMMS-Dienst oder ein Relayne-Testlabor. Die optionale Windows-Feature-Abfrage benötigt erhöhte Rechte. Für eine echte Generalprobe muss deshalb zuerst ein geeigneter Testhost mit einem eingerichteten Relayne-Klon bereitstehen. Es wurden keine Windows-Features installiert und keine realen VM-, Prüfpunkt- oder Dienständerungen ausgelöst.
