# Klon-Generalprobe zur Produktionsausführung

Der Benutzer hat die weitere Umsetzung des vorgeschlagenen durchgängigen Ablaufs autorisiert. Unterstützter erster Pfad: Windows-Dienstzustand mit HTTP-Nachbedingung; keine universelle VM-/Anwendungstransaktion.

- [x] Unveränderliche Zuordnung der Produktionsprofile zu konkreten Lab-/VM-Identitäten.
- [x] Dauerhafter Testauftrag vor Lab-Mutation und gespeicherter Nachweis nach echter Zustandsänderung und HTTP-Prüfung.
- [x] Separater Produktionsstart mit erneuter Prüfung aller Belege; bestehende Vorprüfung, Pilot, einzelne Ziel-Freigaben und Wiederherstellung verwenden.
- [x] Nachweisalter, Plan-/Zielabweichungen, Unterbrechungen, ungültige Journale und konkurrierende Lab-Aktionen berücksichtigen.
- [x] Native Oberfläche mit konkreter Ausführungsübersicht, sequenzieller Generalprobe, Abbruch nach laufender Probe und Belegübersicht.
- [x] Gesamttests, Build und native Renderer-Aufnahme abschließen.

Die Vorlage wird nicht automatisch aus Produktion synchronisiert. Übereinstimmung von Version und Konfiguration muss vor der Generalprobe geprüft werden. Der Klontest verwendet Loopback-HTTP, die Produktionsprüfung den Zielhost. Authentifizierte Live-Abnahme und echte Hyper-V-Ausführung bleiben mangels geeigneter Testinfrastruktur offen.
