# Relayne: erweiterte Änderungs- und Prüfabläufe

Der Benutzer hat die Umsetzung der sechs vorgeschlagenen Erweiterungen autorisiert: Änderungs-Zeitmaschine, automatisches Testlabor, protokollübergreifende Aufträge, Störungsrekonstruktion, fachliche Funktionsprüfungen und übertragbare Reparaturpakete. Vorhandene Änderungen und Profile bleiben erhalten. Entwicklungsprüfungen verwenden lokale Testdateien, Loopback-Dienste und bewachte PowerShell-Testmodelle.

- [x] Dateien/Registry vor und nach Änderungen vergleichen, journalisieren und konfliktbewusst wiederherstellen.
- [x] Isolierte Hyper-V-Labs aus Offline-Vorlagen erstellen, tatsächlich prüfen und ausschließlich eigene Ressourcen aufräumen (Adapter mit ausgeführten Testmodellen geprüft; Live-Hyper-V offen).
- [x] Protokollübergreifende Aufträge mit Voraussetzungen, Nachbedingungen und definierten Wiederherstellungsschritten.
- [x] Gemeinsame Störungszeitleiste mit Quellen und ausdrücklich unbestätigten Ursachenhypothesen.
- [x] Mehrstufige fachliche HTTP-Prüfungen mit tatsächlichen Ergebnisbelegen.
- [x] Versionierte Reparaturpakete importieren/exportieren und vor Ausführung prüfen.
- [x] Native GUI integrieren, aussagekräftige Tests, Build und Renderer-Aufnahmen prüfen.

Hyper-V-Verwaltungsbefehle sind auf dem Entwicklungsrechner nicht verfügbar. Echte VM-Ausführung und die bisher offene authentifizierte Infrastrukturabnahme dürfen nicht als bestanden gemeldet werden. Unterstützte Adapter und Grenzen werden im Abschluss dokumentiert.
