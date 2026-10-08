# Relayne als generischer IT-Helper

Architekturvorschlag vom 8. Oktober 2026. Die Bestandsprüfung ist abgeschlossen; Produktcode für diesen Ausbau wurde noch nicht geändert.

## Ziel

Ein Mitarbeiter beschreibt zum Beispiel „Unsere Bestellplattform ist langsam“. Relayne fragt fehlende Informationen ab, ordnet die betroffenen Systeme zu, sammelt Befunde, erklärt mögliche Ursachen, schlägt geprüfte Schritte vor und kontrolliert anschließend, ob das ursprüngliche Problem gelöst ist.

Der Bedienablauf bleibt zusammenhängend: **Problem beschreiben → Systeme zuordnen → Untersuchen → Änderung prüfen und freigeben → Ergebnis kontrollieren → Erfahrung sichern.**

## Ausbau in sechs Waves

1. **Gemeinsame Grundlage:** Problemaufnahme und Rückfragen, betroffene Rechner/Anwendungen/Datenbanken, klare Erfolgskriterien, Befundquellen und eine Übersicht verfügbarer Diagnosefunktionen. Vorhandene Profile und Nachweise werden weiterverwendet.
2. **SQL-Performance:** Echte PostgreSQL- und SQL-Server-Anbindungen für Status, Sperren, Wartezeiten, Tabellen/Indizes und Statistiken. Abfragepläne verständlich auswerten und Empfehlungen mit ihren Befunden verknüpfen.
3. **Weitere Systeme:** Windows- und Linux-Ressourcen, Netzwerkpfade sowie begrenzte Diagnosen für Docker-Container, Kubernetes-Workloads, Azure-VMs und AWS-EC2-Instanzen. Jede Anbindung zeigt ihre Voraussetzungen und tatsächlich unterstützten Prüfungen.
4. **Kontrollierte Änderungen:** Versionierte Reparaturvorschläge und Freigaben für die genaue Aktion und das genaue Ziel. Neben bestehenden Dienstaktionen werden zunächst Indexanlage und Statistikpflege für beide Datenbanktypen unterstützt. Risiken und Grenzen der Wiederherstellung stehen vor der Freigabe fest.
5. **Ergebnis und Wissen:** Die betroffene Anwendung und alle festgelegten Abhängigkeiten erneut prüfen. Wiederholte, vergleichbare Performance-Messungen unterscheiden Verbesserungen von Messrauschen. Erfolgreiche Fälle werden als geprüfte Erfahrungen gespeichert und bei Änderungen erneut validiert.
6. **Bedienung und Abnahme:** Alle Schritte in einer gemeinsamen Helper-Ansicht verbinden, dynamische Abläufe prüfen, Dokumentation und Windows-Prüfungen ergänzen und die gesamte Änderung unabhängig kontrollieren.

Jede Wave liefert bereits einen nutzbaren Bedienweg für ihre Funktionen. Fehlende Berechtigungen, Werkzeuge oder Messwerte erscheinen ausdrücklich als fehlend oder unbekannt. Erfahrungen und Vorschläge ersetzen keine Freigabe einer neuen Änderung.

## Konkreter Abnahmefall

Die SQL-Sandbox mit synthetischen Bestellungen wird durch Relayne untersucht. Der Fall umfasst einen fehlenden Kundenindex, veraltete Statistiken, eine Sortierung mit Plattenauslagerung und eine blockierende Transaktion. Relayne muss echte Befunde sammeln, Vorschläge zeigen, unterstützte Änderungen freigeben und ausführen sowie unabhängige Ergebnisse speichern. Zusätzlich prüfen API und beide Portale die fachliche Funktion.

Performance wird mit Aufwärmläufen und wiederholten Messungen verglichen. Ein unklarer Unterschied bleibt unklar. Fälle können auch als „extern gelöst“, „diagnostiziert ohne Änderung“ oder „weiterer Eingriff erforderlich“ enden, jeweils mit nachvollziehbarem Grund.

Für andere Plattformen werden ausführbare Anbindungen mit lokalen Testgegenstellen geprüft. Tatsächliche Tests an SQL Server, Linux, Containern und Cloud-Ressourcen werden getrennt ausgewiesen, abhängig von verfügbaren Umgebungen und Zugängen.

## Arbeitsweise

Bis zu zwölf Subagents für unabhängige Aufgaben. Gemeinsame Schnittstellen und Integrationsänderungen werden geordnet umgesetzt. Einfache Arbeiten erhalten Luna; anspruchsvolle Datenbank-, Sicherheits- und Integrationsaufgaben Sol. Jede Wave erhält passende Tests und eine unabhängige Prüfung.

Die Änderungen bleiben im separaten Entwicklungszweig. Die vorherigen sechs Produktverbesserungen und die vorhandenen Demo-Dateien bleiben erhalten.

Die verbindlichen Verträge, Grenzen und Abnahmeszenarien stehen in [der vollständigen Architektur](superpowers/specs/2026-10-08-generic-helper-design.md).
