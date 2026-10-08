# Relayne als generischer IT-Helper

Architektur vom 8. Oktober 2026 bestätigt. Die Bestandsprüfung und der detaillierte Umsetzungsplan sind vorbereitet; Produktcode für diesen Ausbau wurde noch nicht geändert.

## Ziel

Ein Mitarbeiter beschreibt zum Beispiel „Unsere Bestellplattform ist langsam“. Relayne fragt fehlende Informationen ab, ordnet die betroffenen Systeme zu, sammelt Befunde, erklärt mögliche Ursachen, schlägt geprüfte Schritte vor und kontrolliert anschließend, ob das ursprüngliche Problem gelöst ist.

Der Bedienablauf bleibt zusammenhängend: **Problem beschreiben → Systeme zuordnen → Untersuchen → Änderung prüfen und freigeben → Ergebnis kontrollieren → Erfahrung sichern.**

## Vollständiger Ausbau in 18 Waves

| Wave | Ergebnis |
|---|---|
| 1 | Problemaufnahme, gezielte Rückfragen und gespeicherte Fälle |
| 2 | Betroffene Systeme, Anwendungen und Datenbanken zuordnen |
| 3 | Nachvollziehbare Befunde, Quellen, Aktualität und Berichte |
| 4 | Ursachenhypothesen, nächste Prüfungen und bewusst angeforderte KI-Beratung |
| 5 | Ausführbare Anbindungen, geschützte Zugänge, Abbruch und Zeitlimits |
| 6 | Native PostgreSQL-Diagnosen |
| 7 | Native SQL-Server-Diagnosen |
| 8 | Abfragepläne, Optimierungshinweise und getrennte Sandbox-Messläufe |
| 9 | Windows-, Linux-, Ressourcen- und Netzwerkdiagnosen |
| 10 | Docker- und Kubernetes-Diagnosen |
| 11 | Azure-VM- und AWS-EC2-Diagnosen |
| 12 | Versionierter Reparaturkatalog und genaue Änderungsvorschau |
| 13 | Rollen, Freigaben, Ausführungsjournal und Wiederaufnahme nach Unterbrechung |
| 14 | Echte begrenzte SQL-Änderungen und isolierte Generalprobe |
| 15 | Übernahme auf das eigentliche Ziel, Wiederherstellung und Klärung ungewisser Ergebnisse |
| 16 | Fachliche Funktionsprüfung und vergleichbare Performance-Messungen |
| 17 | Geprüfte Erfahrungen, erneute Validierung und Abschlussberichte |
| 18 | Gemeinsame Bedienoberfläche, echte Datenbank/API/Portal-Demo und Gesamtabnahme |

Jede Wave liefert bereits einen nutzbaren Bedienweg für ihre Funktionen. Fehlende Berechtigungen, Werkzeuge oder Messwerte erscheinen ausdrücklich als fehlend oder unbekannt. Erfahrungen und Vorschläge ersetzen keine Freigabe einer neuen Änderung.

## Konkreter Abnahmefall

Die SQL-Sandbox mit synthetischen Bestellungen wird durch Relayne untersucht. Der Fall umfasst einen fehlenden Kundenindex, veraltete Statistiken, eine Sortierung mit Plattenauslagerung und eine blockierende Transaktion. Relayne muss echte Befunde sammeln, Vorschläge zeigen, unterstützte Änderungen freigeben und ausführen sowie unabhängige Ergebnisse speichern. Zusätzlich prüfen API und beide Portale die fachliche Funktion.

Performance wird mit Aufwärmläufen und wiederholten Messungen verglichen. Ein unklarer Unterschied bleibt unklar. Fälle können auch als „extern gelöst“, „diagnostiziert ohne Änderung“ oder „weiterer Eingriff erforderlich“ enden, jeweils mit nachvollziehbarem Grund.

Für andere Plattformen werden ausführbare Anbindungen mit lokalen Testgegenstellen geprüft. Tatsächliche Tests an SQL Server, Linux, Containern und Cloud-Ressourcen werden getrennt ausgewiesen, abhängig von verfügbaren Umgebungen und Zugängen.

## Arbeitsweise

Bis zu zwölf Subagents für unabhängige Aufgaben. Gemeinsame Schnittstellen und Integrationsänderungen werden geordnet umgesetzt. Einfache Arbeiten erhalten Luna; anspruchsvolle Datenbank-, Sicherheits- und Integrationsaufgaben Sol. Jede Wave erhält passende Tests und eine unabhängige Prüfung.

Die Änderungen bleiben im separaten Entwicklungszweig. Die vorherigen sechs Produktverbesserungen und die vorhandenen Demo-Dateien bleiben erhalten.

Die verbindlichen Verträge, Grenzen und Abnahmeszenarien stehen in [der vollständigen Architektur](superpowers/specs/2026-10-08-generic-helper-design.md). Der [detaillierte Umsetzungsplan](superpowers/plans/2026-10-08-generic-helper.md) enthält Dateien, Schnittstellen, Abhängigkeiten und Tests für jede Wave und wartet auf deine Bestätigung vor dem Code-Start.
