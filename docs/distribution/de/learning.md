# Lernende Reparaturempfehlungen

Der neue Abschnitt unter Ursachen & Lösungen priorisiert vorhandene Dienst-Recovery-Ergebnisse für das ausgewählte Produktionsziel. Er trainiert kein Modell und ruft keinen KI-Anbieter auf. Die Rangfolge wird deterministisch aus dem aktuellen Ausführungsjournal berechnet; es entsteht kein zusätzlicher Speicher gelernter Belege.

## Belegregeln
Es zählen nur abgeschlossene Ergebnisse der letzten 90 Tage. Zukünftige, veraltete oder doppelte Lauf-/Zielidentitäten, ungültige Planbindungen und andere Endpunkte werden ausgeschlossen. Ergebnisse der Testumgebung bleiben getrennt und erhöhen die Produktionsrangfolge nicht. Start, Neustart und unterschiedliche Funktionstests besitzen getrennte Identitäten.

Eine belegte Reparatur benötigt die vorhandene Prüfung der Vorher-/Aktions-/Nachher-Belege, eine fehlgeschlagene Baseline, einen erfolgreichen HTTP-Funktionstest und einen tatsächlichen Zustandswechsel oder nachgewiesenen Neustart. Ein bereits gesunder Dienst oder eine reine TCP-Prüfung zählt nicht als Reparaturerfolg. Fehler, Rücksetzungen und ungeklärte Ergebnisse bleiben sichtbar.

## Rangfolge und Rücknahme
Pro Produktionskategorie zählen höchstens fünf Ergebnisse: +5 je belegter Reparatur, −8 je Fehler/Rücksetzung zusammen, −4 je ungeklärtem Ergebnis. Dies sind einsehbare Gewichtungen, keine Wahrscheinlichkeiten. Eine Empfehlung benötigt mindestens eine belegte Produktionsreparatur; ihr jüngster Erfolg muss neuer sein als jeder ungünstige oder ungeklärte Produktionsausgang. Bei gleichem Zeitpunkt bleibt sie gesperrt. Die Sortierung ist deterministisch.

## Bedienung und Grenzen
Profil auswählen, Anzahlen und Belegverweise prüfen und bei gestützter Empfehlung einen neuen Prüfplan vorbereiten. Bestehender Schutz laufender Aufträge sowie erneute Prüfung und Freigabe bleiben bestehen. Aus der Rangfolge startet keine Ausführung. Der ausdrücklich kopierte Bericht enthält Dienstnamen und Belegkennungen; vor Weitergabe prüfen.

Derselbe Endpunkt belegt keine unveränderte Software, Konfiguration oder Berechtigung. Es gibt weder kundenübergreifendes Lernen noch einen Kausalitäts- oder Produktivitätsnachweis. Ausgeschlossene Ergebnisse werden gezählt, aber nicht als positive Belege verwendet. Die bisherigen Lösungsansichten bleiben separat verfügbar. Neue Texte liegen in en-US, de, fr und it vor.
# Beleglücken
Historische Beleglücken werden ausdrücklich angezeigt: fehlende HTTP-Prüfung, nicht belegte fehlgeschlagene Baseline, fehlender Zustandswechsel oder unvollständige/widersprüchliche Vorher-/Aktions-/Nachher-Belege. Sie erklären die historische Unsicherheit, nicht den aktuellen Hostzustand.

## Prüfung — 2026-09-13

Fünf gezielte Lern-/Übersetzungstests und 18 Ausführungs-Regressionstests bestanden (vier Tests überschneiden sich). Offline-Build und Formatprüfung erfolgreich. Kein erneuter Gesamttest, keine Live-Hosts und keine externen Modellaufrufe. Bestehende Build-Warnungen bleiben erhalten.
