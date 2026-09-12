# Relayne Recovery Agent

Der native Arbeitsbereich **Recovery Agent** verbindet einen gespeicherten Störungsfall mit der vorhandenen Klon-Generalprobe, Produktionsfreigabe und Ergebnisprüfung. Der erste Ablauf unterstützt den Start eines gestoppten Windows-Dienstes mit ausdrücklich festgelegtem HTTP-Funktionstest.

## Bedienung

1. **Recovery Agent → Störung** öffnen und die Störung beschreiben. Den exakten Dienstnamen selbst eintragen oder ausdrücklich **KI-Reparaturvorschlag erstellen** wählen. Der OpenAI-Aufruf nutzt `OPENAI_API_KEY` und das bereits konfigurierte Modell. Er sendet ausschließlich den sichtbaren Störungstext und benötigt die entsprechende Checkbox. Ohne eindeutigen Dienstnamen soll die KI nach fehlendem Kontext verlangen; sie erfindet keine Zielrechner oder Erfolgsmeldungen.
2. Dienst und Begründung prüfen, dann **Geprüften Fall speichern und neuen Testentwurf vorbereiten**. Dies speichert einen lokalen Fall, ersetzt den bisherigen Testentwurf und entfernt dessen Belegverweise, Freigaben und flüchtige Zugangswerte. Es startet keine Verbindung. Eine laufende Generalprobe oder offene Testfreigabe verhindert das Ersetzen.
3. In **Generalprobe** Produktionsprofil, laufendes Testlabor und HTTP-Erfolgskriterien ausdrücklich zuordnen. Der Recovery-Dienst und Zielzustand `Running` sind fest. Die vorhandenen Abgleich-, Klon-, Freigabe- und Belegprüfungen bleiben wirksam. Zum Erstellen des Klons führt **Testlabor öffnen** in den bestehenden Arbeitsbereich; danach über **Recovery Agent** zurückkehren.
4. Nach erfolgreicher Generalprobe **Produktionslauf vorbereiten** wählen. Der konkrete Lauf erhält die Fall-ID und wird im Schritt **Freigabe & Ausführung** angezeigt. Die Produktionsvorprüfung liest das Ziel; eine Änderung benötigt weiterhin die separate Freigabe für dieses Ziel und den aktuellen Ausgangszustand. Beim Wechsel zu einem anderen Fall wird ein laufender Auftrag nicht umgebunden.
5. Unter **Ergebnis** den aus dem Journal berechneten Status und die zugeordneten Läufe lesen. **Bereinigten Ergebnisbericht kopieren** kopiert einen Textbericht mit Fall-ID, Planbindung, Zielzuständen und Abschlusszeiten. Frühere Fälle sind in der Auswahlliste verfügbar. Ein neuer Versuch wird als neuer Lauf mit derselben Fall-ID gespeichert; der letzte zugeordnete Produktionsversuch bestimmt den Fallstatus.

## Wann gilt ein Fall als behoben?

Nur ein abgeschlossener, zum Fall gehörender Produktionslauf mit gültigem Planhash und passenden Produktionszielen kann zählen. Er benötigt einen tatsächlichen Dienststart, strukturierte Ausgangs- und Änderungsbefunde, zuvor fehlgeschlagene und anschließend erfolgreiche HTTP-Prüfung sowie zeitlich geordnete Nachweise. Testläufe, bereits laufende Dienste, fehlende Belege, Rückkehr, Abbruch oder unklare Zustände gelten nicht als bestätigte Reparatur. Ein später fehlgeschlagener Versuch wird nicht durch einen früheren Erfolg verdeckt.

Der Nachweis ist historisch. Er ist keine kontinuierliche Zustandsüberwachung. Die Anwendung zeigt keine erfundene Zeitersparnis, Erfolgsquote oder KI-Konfidenz an.

## Speicherung und Betrieb

`relayne-recovery.dpapi` speichert höchstens 128 Fälle und maximal 1 MiB verschlüsselte Daten im bisherigen Anwendungsdatenverzeichnis. Texte werden zusätzlich heuristisch bereinigt. Bei unlesbarer Datei bleibt der Bestand unangetastet und neue Fälle sind gesperrt. Der bestehende Testentwurf und das Ausführungsjournal tragen optionale Fall-IDs; ältere Dateien ohne diese Felder bleiben lesbar. Zugangsdaten bleiben außerhalb des Falls.

Der Schalter **Neue Recovery-Fälle und KI-Vorschläge aktivieren** deaktiviert neue Recovery-Aktionen. `RELAYNE_RECOVERY_AGENT=0` startet mit deaktiviertem Schalter; standardmäßig ist er aktiv. Bereits laufende Arbeit wird nicht mitten in einer Änderung unterbrochen. Bestehende Läufe bleiben für Ergebnisprüfung und kontrollierten Abbruch zugänglich. Die bestehende Oberfläche **Prüfen & Ausführen** bleibt ebenfalls erreichbar.

Dies ist die erste lokale Produktintegration. Eine gehostete Mandantenplattform, Abrechnung, wiederkehrende Recovery-Verträge, ein Paketmarktplatz und automatische kundenseitige Ausführung sind nicht enthalten. Echte Hyper-V-/WinRM-Ausführung benötigt weiterhin die Infrastrukturabnahme aus [Klon → Produktion](relayne-promotion.md). Ein kostenpflichtiger Live-Modellaufruf und der zwanzig Fälle umfassende Vergleich zur Zeitersparnis sind keine Voraussetzung für die lokalen Softwaretests und werden nicht als durchgeführt dargestellt.

## Verifikation am 12.09.2026

`cargo test --offline -- --test-threads=1`: **354 Anwendungstests und 16 Team-Tests bestanden, 0 fehlgeschlagen**. Fünf bestehende manuelle Tests für externe RDP-Ziele, Zugangsspeicherung und die lokale ActiveX-Komponente bleiben ausgelassen. Acht neue Domain-Tests prüfen unter anderem ungültige Modellantworten, verschlüsselte Speicherung, falsche Ziel-/Planbindung, fehlende Änderungsbelege, bereits gesunde Anwendungen, abgebrochene Folgeversuche und einen beschädigten Laufindex. Vier neue Integrationstests prüfen Entwurfsübernahme und sichere Laufauswahl. Der bestehende Renderertest umfasst Recovery bei 640 und 1440 logischen Pixeln.

Beide Binärdateien wurden mit `cargo build --offline --bins` erstellt. Bestehende Dead-Code-Warnungen verbleiben. Die [native Recovery-Ansicht](gui-concepts/relayne-recovery-implemented.png) wurde mit dem eingebauten Aufnahmemodus erstellt und visuell geprüft. Die separate Codeprüfung fand nach Verschärfung der Erfolgsnachweise keine offenen Befunde im neuen Recovery-Ablauf.
