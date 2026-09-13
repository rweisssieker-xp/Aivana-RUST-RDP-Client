# Nachweisbare Reparaturergebnisse

Unter Ursachen & Lösungen ein Produktionsprofil auswählen und Nachweisbare Ergebnisse im Abschnitt der lernenden Empfehlungen öffnen. Der Bericht nutzt abgeschlossene Ergebnisse des Ausführungsjournals der letzten 90 Tage für diesen Endpunkt. Es erfolgt kein Netzwerk- oder KI-Aufruf.

## Was gemessen wird
Produktion und Testumgebung zeigen jeweils belegte Reparaturen, Fehler, Rücksetzungen und ungeklärte Ergebnisse. Es gelten die strikten Regeln der lernenden Empfehlungen: exakte Plan-/Zielbindung, Ausschluss doppelter Belege, fehlgeschlagene Baseline, erfolgreicher HTTP-Test sowie tatsächlicher Zustandswechsel oder belegter Neustart. Ausgeschlossene Ergebnisse werden separat gezählt.

Der Median umfasst das Intervall vom ersten gespeicherten Ausgangsbefund des Ziels bis zum erfolgreichen Funktionstest. Der spätere Abschluss eines Auftrags mit mehreren Zielen verlängert das Intervall nicht. Nur belegte Erfolge liefern Zeitstichproben; Stichproben- und Reparaturanzahl werden gemeinsam angezeigt. Fehlende Stichproben bleiben fehlend und werden nicht zu Null. Jede Stichprobe enthält Lauf-/Zielkennungen und UTC-Zeitpunkte.

## Grenzen der Interpretation
Dies ist weder vollständige Störungsdauer noch MTTR, Arbeitszeit, Verfügbarkeit, vermiedener Verlust oder Zeitersparnis. Die Zeitmessung nur erfolgreicher Fälle ist selektiv; Fehler bleiben separat sichtbar und zählen nicht als schnelle Reparaturen. Ein manueller Vergleich und finanzielle Kosten werden nicht erfasst; Arbeitsersparnis und ROI sind ausdrücklich nicht gemessen. Umgebungsgleichheit und kausale Wirksamkeit werden nicht unterstellt.

## Export und Datenschutz
Ergebnisbericht als JSON kopieren erzeugt einen lokalen Zwischenablagebericht mit ausgewählter Profilkennung, Zeitraum, getrennten Anzahlen und Zeitbelegen. Zugangsdaten und Hostadressen werden nicht exportiert; der Bericht erteilt keine Ausführungsfreigabe. Kennungen können trotzdem sensibel sein: vor Weitergabe prüfen. Quelldaten bleiben unverändert. Neue Oberfläche und Dokumentation unterstützen en-US, de, fr und it.

## Prüfung — 2026-09-13

Vier gezielte Ergebnis-/Oberflächentests und 21 Ausführungs-Regressionstests bestanden (drei überschneiden sich). Die neue Ansicht wurde in vier Sprachen bei 640 und 1440 Pixeln gerendert. Offline-Build und Formatprüfung erfolgreich. Kein erneuter Gesamttest und keine Live-Verbindungen; bestehende Build-Warnungen bleiben erhalten.

## Frühwarnradar aus Reparaturverläufen

Das aufklappbare Radar wertet belegte Produktionsreparaturen je identischem Verfahrensschlüssel aus (Dienst, Aktion und Funktionstest). Testläufe, doppelte Laufkennungen, zukünftige/veraltete Zeitpunkte und inkonsistente Intervalle bleiben ausgeschlossen. Es erzeugt keine Benachrichtigungen, Netzwerkaufrufe oder automatischen Aktionen; die Auswertung erfolgt beim Öffnen/Darstellen der Ansicht.

Wiederholte Reparaturen: mindestens drei unterschiedliche Läufe an mindestens zwei UTC-Tagen innerhalb der letzten sieben Tage. Dies zeigt wiederkehrende Reparaturaktivität, belegt aber keine gemeinsame Störungsursache.

Längere Prüfintervalle: Die letzten drei Erfolge werden mit den drei vorherigen innerhalb von 30 Tagen verglichen. Jede Gruppe muss mindestens zwei UTC-Tage abdecken; die jüngsten drei müssen innerhalb von sieben Tagen liegen. Ihr Median muss mindestens doppelt so hoch und mindestens 5.000 Millisekunden größer sein. Eine Null-Baseline löst diese Regel nicht aus.

Jede Warnung enthält die auslösenden Laufkennungen und bei Verlangsamung beide Mediane. Der JSON-Export verwendet jetzt das Schema relayne-outcome-impact-v2 mit Verfahrensidentitäten und Warnungen. Dies sind rückblickende Heuristiken, keine statistisch validierten Prognosen. Keine erreichte Schwelle belegt weder Systemgesundheit noch ausreichende Daten. Die Grenzen einer Zeitmessung nur erfolgreicher Fälle bleiben bestehen.

Radar-Prüfung (2026-09-13): 24 Ausführungs-Tests einschließlich drei neuer Radar-Tests sowie der viersprachige Oberflächentest bestanden. Offline-Build und Formatprüfung erfolgreich. Kein erneuter Gesamttest und keine Live-Verbindung.
## Lokale Prüfung von Warnungen

Radarwarnungen lassen sich mit Pflichtnotiz quittieren und manuell wieder öffnen. Die Warnung bleibt sichtbar. Die Quittierung gilt für das genaue Profil, Verfahren und die auslösenden Belege. Geänderte Belege oder ein Alter von 30 Tagen öffnen die Prüfung wieder; eine Aktualisierung allein nicht. Dies erteilt keine Reparaturfreigabe und verändert weder Ergebnisbelege noch Rangfolge.

Die Speicherung erfolgt lokal mit Windows-DPAPI in `relayne-warning-reviews.dpapi`. Notizen sind auf 256 Zeichen (1.024 Bytes) begrenzt; eine Geheimnisbereinigung erfolgt nach bestem Bemühen. Keine Zugangsdaten eintragen. Maximal 256 Quittierungen; abgelaufene Einträge können entfernt werden. Bei Schreibkonflikten oder Lesefehlern neu laden. Fehlgeschlagene Schreibvorgänge erhalten den bisherigen Stand. Quittierungen sind nicht im Ergebnis-JSON enthalten.
