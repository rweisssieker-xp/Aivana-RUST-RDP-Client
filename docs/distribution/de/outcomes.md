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
