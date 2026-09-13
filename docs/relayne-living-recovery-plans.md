# Lebende Wiederherstellungspläne

Relayne kann erfolgreich geprobte Windows-Dienstpläne dauerhaft verfolgen. Zwei getrennte Fristen zeigen, wann ein neuer Produktionsvergleich beziehungsweise eine neue Klon-Generalprobe benötigt wird. Erkannte Änderungen entwerten bisherige Nachweise.

## Benutzung

1. Im Recovery Agent oder im Generalprobenbereich einen Dienstplan mit exakter Produktions-/Klonzuordnung erfolgreich proben.
2. **Wiederherstellungsplan pflegen …** oder den Navigationseintrag **Recovery-Pläne** öffnen. Den aktuellen geprüften Entwurf mit einem Namen importieren. Importiert werden echte Belege und die vor der Generalprobe erfassten Produktionsfingerprints.
3. Die Intervalle festlegen: Produktionsvergleich 5–1440 Minuten (Standard 60), Generalprobe 1–720 Stunden (Standard 24).
4. Einen Vergleich ausdrücklich über **Jetzt einmal über WinRM lesend prüfen** starten oder automatische Vergleiche für die aktuelle Sitzung einschalten. Automatische Vergleiche laufen nur bei geöffneter Anwendung; nach einem Neustart ist erneut Zustimmung erforderlich.
5. Bei Änderungen oder fälliger Generalprobe **Neue Generalprobe vorbereiten …** wählen, erneut prüfen und den erfolgreichen Entwurf importieren. Bei identischem Plan wird der vorhandene Eintrag erneuert. Geänderte Ziele oder Pläne benötigen einen eigenen Eintrag.

Eine neue Generalprobe ersetzt den bisherigen Testentwurf. Gastzugänge und Ausführungsfreigaben müssen neu eingegeben werden. Das Öffnen oder Importieren eines Plans startet keine Dienständerung.

In der Generalprobe können [KI-generierte Anwendungstests](relayne-ai-application-tests.md) aus einer ausdrücklich freigegebenen Beschreibung vorgeschlagen und nach Prüfung übernommen werden. Geänderte Erfolgskriterien benötigen erneut passende Generalprobenbelege.

## Was die Zustände bedeuten

| Zustand | Bedeutung |
|---|---|
| Bereit laut letztem Vergleich | Die gespeicherten Fristen und Vergleichsdaten sind aktuell. |
| Produktionsvergleich fällig | Die Frist für einen neuen lesenden Vergleich ist erreicht. |
| Neue Generalprobe fällig | Ein erneuter erfolgreicher Klontest ist erforderlich. |
| Änderung erkannt | Die Nachweise bleiben gesperrt, bis eine neue Generalprobe importiert wurde. |
| Zustand unklar | Ein Vergleich oder der lokale Speicher konnte nicht zuverlässig ausgewertet werden. |
| Pausiert | Der Plan nimmt nicht an automatischen Vergleichen teil. Ablauf und Nachweissperren gelten weiterhin. |

Ein lesender Vergleich verlängert niemals die Generalprobenfrist. Auch das Zurückdrehen einer erkannten Änderung macht alte Nachweise nicht wieder gültig. Neue Nachweise müssen aus einer eigenständigen erfolgreichen Generalprobe mit einer Produktionsbeobachtung nach der letzten Entwertung stammen. Bereits ersetzte Nachweisreferenzen bleiben widerrufen.

**Bereitschaft ist keine Produktionsfreigabe.** Die vorhandene Grenze von einer Stunde für Produktionsnachweise sowie alle bisherigen Prüfungen und ausdrücklichen Ausführungsfreigaben gelten weiterhin. Laufende Vergleiche und geänderte lokale Zielprofile sperren die Verwendung betroffener Pläne vor dem Produktionsschritt.

## Prüfumfang und Betrieb

Der Vergleich liest über WinRM mit der aktuellen Windows-Identität OS-Version und Build, Architektur, Hash und Version der Dienstdatei, Konfigurationshash, Startmodus und Abhängigkeiten. Er verändert weder Dienste noch VMs. Pro Ziel gelten ein Zeitlimit von 90 Sekunden und begrenzte Ausgabemengen; Abbruch oder unvollständige Ergebnisse erzeugen keinen positiven Nachweis.

Anwendungsdaten und Änderungen außerhalb dieser Felder sind nicht abgedeckt. Remote-Änderungen werden beim nächsten tatsächlichen Vergleich erkannt; die Anzeige ist keine kontinuierliche Überwachung oder Garantie einer erfolgreichen Wiederherstellung.

Der lokale DPAPI-geschützte Speicher enthält bis zu 128 Pläne, maximal 4 MiB und bis zu 1024 widerrufene Referenzen je Plan. Speicherfehler blockieren Freigaben. Die Oberfläche bietet keine Löschung alter Sperren an. Automatische Vergleiche speichern keine Sitzungserlaubnis und benötigen keine gespeicherten Gastpasswörter.

Neue Entwertungen, fehlgeschlagene Vergleiche und Widerrufe werden vor dem Hauptspeicher in einem zusätzlichen verschlüsselten Journal gesichert. Bei konkurrierenden Instanzen werden diese Einschränkungen zusammengeführt; veraltete Einstellungen können neuere Sperren nicht überschreiben. **Gespeicherte Pläne neu laden** bewahrt noch nicht übernommene Einschränkungen. Scheitert bereits die Journalspeicherung, versucht Relayne eine dauerhafte `.blocked`-Sperrdatei anzulegen. Diese wird nicht automatisch aufgehoben: Die verlorenen Nachweise müssen vor einer administrativen Reparatur rekonstruiert werden. Bei vollständig nicht beschreibbarem Datenträger kann auch eine dauerhafte Fehlermarkierung nicht garantiert werden.

Die automatisierten Tests verwenden lokale, abgesicherte Prozess- und Systemfixtures. Eine Prüfung gegen reale WinRM-/Hyper-V-Infrastruktur ist separat erforderlich.

## Verifikation am 12.09.2026

Der vollständige Offline-Testlauf bestand mit **374 Anwendungstests und 16 Team-Tests**, ohne Fehler; fünf bestehende manuelle Tests blieben ausgelassen. Nach der abschließenden Speicherhärtung bestanden zusätzlich alle **17 gezielten Vertragstests**. Diese umfassen beide Reihenfolgen konkurrierender Speicherzugriffe, dauerhafte Sperren bei Schreibfehlern, atomare Lesezugriffe und konfliktbehaftete Erneuerungen. Die UI-Tests prüfen Sitzungserlaubnis, einzelne laufende Vergleiche sowie die Planbindung unabhängig von neuen Nachweisreferenzen. Der bestehende Renderertest umfasst die neue Ansicht bei 640 und 1440 logischen Pixeln.

Beide Programme wurden offline gebaut; bestehende Dead-Code-Warnungen bleiben. Die [native Ansicht](gui-concepts/relayne-living-recovery-plans.png) wurde mit dem integrierten Aufnahmemodus erzeugt und visuell geprüft. Die zusätzliche Codeprüfung führte zur Härtung von Speicherkonflikten, konsistenten Lesezugriffen und laufenden Vergleichssperren. Es wurden keine realen WinRM-/Hyper-V-Ziele angesprochen.
