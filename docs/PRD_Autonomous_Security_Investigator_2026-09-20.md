# PRD – Autonomous Security Investigator
## Produktentwurf für Software mit Plugin-Anbindung

Version: 0.3 · Datum: 20.09.2026 · Status: Vorschlag zur fachlichen und technischen Freigabe
Arbeitstitel: Aivana Autonomous Security Investigator
Dokumentzweck: Anforderungen und Abnahmekriterien; keine Implementierungs- oder Betriebsfreigabe.
Informationsbasis: Die im bisherigen Austausch identifizierten Verbesserungsfelder. Keine vollständige technische Prüfung des bestehenden Plugins. Dieses Dokument enthält keine internen Incident-Daten oder Zugangsdaten.

## 1. Zusammenfassung und Produktentscheidung

Entwickelt werden soll ein dauerhaft laufendes Untersuchungssystem für Security Operations: Es nimmt freigegebene Alarme entgegen, sammelt gezielt Evidenz, prüft Gegenhypothesen, identifiziert fehlende Daten, priorisiert Fälle und bereitet überprüfbare Entscheidungen vor. Menschen konzentrieren sich auf unklare, kritische und geschäftlich relevante Entscheidungen.

Empfohlen wird ein eigenständiger Software-Kern mit Web-Oberfläche und dünner MCP-/Plugin-Anbindung. Autonomie bedeutet im MVP selbstständige, begrenzte Untersuchung, nicht uneingeschränkte Administration. Der Betrieb darf weder von einem geöffneten Chat noch vom Fortbestand einer einzelnen Modellsitzung abhängen.

| Option | Vorteile | Grenzen | Empfehlung |
|---|---|---|---|
| Reines interaktives Plugin | Kleiner Einstieg; vorhandene Chat-Oberfläche | Dauerbetrieb, Wiederaufnahme, Rechte und Audit benötigen zusätzliche Infrastruktur | Nur als Bedienoberfläche |
| Eigenständiger Kern plus Plugin | Dauerbetrieb, zentrale Regeln, unabhängige Oberfläche, kontrollierbare Datenhaltung | Höherer initialer Entwicklungs- und Betriebsaufwand | Bevorzugte Produktform |
| Mandantenfähiges SaaS | Zentraler Betrieb und Verteilung | Zusätzliche Isolation-, Vertrags-, Datenschutz- und Betriebsanforderungen | Spätere Option |

Deployment-Annahme für den MVP: kundeneigene Cloud-Umgebung, ein Mandant, konfigurierte Standorte. Ein späteres SaaS darf keine stillschweigende Änderung der Datenverarbeitung sein.

## 2. Problem und Nutzen

Die wiederholte manuelle Zusammenstellung von Alarmen, Logins, Endpunktdaten und Analystenkommentaren bindet Zeit. Doppelte Ereignisse können die Angriffslage überzeichnen. Fehlende Telemetrie kann fälschlich als Entwarnung interpretiert werden. Übergaben und Maßnahmen bleiben ohne technische Nachprüfung offen.

Die Produktlücke ist deshalb nicht nur bessere KQL-Erzeugung. Benötigt werden zuverlässige Konnektoren, inkrementelle Verarbeitung, Geschäftskontext, überprüfbare Evidenz und ein geschlossener Arbeitsablauf bis zur bestätigten Übergabe.

Ziele:
- Analystenzeit bei gleichbleibender oder verbesserter Untersuchungsqualität reduzieren.
- Wiederholbare, nachvollziehbare Untersuchungen über freigegebene Standorte ermöglichen.
- Fakten, Schlussfolgerungen, Gegenbelege und Unbekanntes strikt trennen.
- Fehlende Daten, fehlende Rechte und technische Ausfälle sichtbar machen.
- Maßnahmen und Übergaben bis zum nachgewiesenen Ergebnis verfolgen.

Nichtziele des MVP:
- Ersatz vollständiger Datenträger-/Speicherforensik oder Malware-Reverse-Engineering.
- Rechtsverbindliche Bewertung oder Garantie eines kompromissfreien Zustands.
- Autonome Kontosperren, Isolation, Token-/Zertifikatswiderrufe oder Löschungen.
- Automatisches Schließen von Security-Incidents im Quellsystem.
- Unbegrenzte Abfragen oder selbstständige Ausweitung von Rechten und Mandantenscope.

## 3. Nutzer und Kernabläufe

SOC-Analyst: erhält belegte Fallzusammenfassungen, prüft strittige Schlussfolgerungen und genehmigt Übergaben.
CISO: verantwortet Sicherheitsprioritäten, Eskalation, Anforderungen an Dienstleister und die Qualität des Lagebildes; akzeptiert Geschäftsrisiken nur im Rahmen ausdrücklich delegierter Befugnisse.
Geschäftlicher Risk Owner: entscheidet innerhalb seiner Befugnisse über dokumentierte Restrisiken und die befristete Fortführung betroffener Geschäftsprozesse.
Incident Lead: steuert Priorität, Untersuchungsscope und Eskalation.
Identity-/Endpoint-/Netzwerkverantwortliche: liefern Kontext und bearbeiten zugewiesene Maßnahmen.
Security Engineering: verwaltet Konnektoren, geprüfte Playbooks und Qualitätsprüfungen.
Produktverantwortliche: bewerten Zeitgewinn, Qualität und Gesamtkosten.
Datenschutz und Plattformbetrieb: bestimmen zulässige Datenverarbeitung, Aufbewahrung und Zugriffsrollen.

Primärer Ablauf:
1. Konfigurierter Alarm oder Zeitplan startet einen Fall.
2. Der Dienst prüft Mandant, Berechtigungen, Telemetrieabdeckung und Budget.
3. Er erkennt bereits bearbeitete Ereignisse und lädt nur neue oder geänderte Informationen.
4. Ein versioniertes Playbook erzeugt Hypothesen und zulässige Untersuchungsaufträge.
5. Validierte Abfragen sammeln begrenzte Evidenz und Gegenbelege.
6. Der Dienst korreliert Ereignisse, dokumentiert Unsicherheit und prüft Abbruchkriterien.
7. Ein Ergebnis enthält Fakten, Alternativen, Datenlücken und nächste Maßnahmen.
8. Ein Mensch bestätigt die fachliche Entscheidung; vereinbarte Folgemaßnahmen werden nachverfolgt.

Beispiel: Bei einem verdächtigen Login werden erfolgreicher Zugriff, fehlgeschlagene Authentifizierung und blockierter Anwendungszugriff getrennt bewertet. Eine technisch erfolgreiche Anmeldung allein belegt weder Datenabfluss noch einen MFA-Bypass.

## 4. Autonomiemodell und Sicherheitsgrenzen

| Stufe | Verhalten | Produktphase |
|---|---|---|
| A0 – Assistiert | Analyst startet einzelne Untersuchungen | Onboarding und Vergleichsbetrieb |
| A1 – Autonome Untersuchung | Automatischer Start, freigegebene Read-only-Abfragen, Bewertung, Bericht und interne Eskalation | MVP |
| A2 – Freigegebene Ausführung | Separater Executor führt eine konkret genehmigte Maßnahme aus und prüft ihr Ergebnis | Nach MVP |
| A3 – Eng begrenzte Reaktion | Nur vorab freigegebene reversible Aktionen mit Ziel-, Zeit-, Mengen- und Risikolimit | Optional nach Sicherheitsnachweis |

Im MVP sind automatische lokale Fallaktualisierungen und Benachrichtigungen an ausdrücklich konfigurierte interne Empfänger erlaubt. Externe Ticketschreibvorgänge sind standardmäßig deaktiviert und benötigen eine eingerichtete Integrationsfreigabe.

Jeder Tool-Aufruf wird außerhalb des Sprachmodells gegen eine deterministische Policy geprüft. Unbekannte Aktionen werden abgelehnt. Ein Modell darf weder sich selbst freigeben noch seine Policy ändern.

Für spätere Reaktionen gilt: Freigaben sind an Identität, Mandant, Ziel, genaue Aktion, Parameter und Ablaufzeit gebunden. Änderungen erfordern erneute Freigabe. Kritische Identitäten und Tier-0-Systeme benötigen ein zusätzliches Vier-Augen-Verfahren. Ein globaler Stoppschalter verhindert neue Aufträge; laufende Anfragen werden soweit technisch möglich abgebrochen und vollständig protokolliert.

## 5. Funktionale Anforderungen

P0 = verpflichtend für MVP; P1 = anschließender Ausbau; P2 = spätere Option. Der verbindliche Lieferzuschnitt einschließlich der manuellen Governance-Basis steht in Abschnitt 17. Sicherheitskontrollen werden nicht zugunsten eines kleineren MVP entfernt.

| ID | Prio | Anforderung | Abnahmekriterium |
|---|---|---|---|
| FR-01 | P0 | Konnektor- und Berechtigungsprüfung für Defender sowie Entra-/Sentinel-Daten | Pro Quelle sind Authentifizierung, tatsächlich lesbare Daten, Zeitraum, Schema und letzter erfolgreicher Abruf sichtbar; fehlende Rechte erzeugen keinen grünen Status |
| FR-02 | P0 | Hintergrunddienst mit persistenter Warteschlange | Nach Prozessneustart wird jeder offene Auftrag wiederaufgenommen oder als fehlgeschlagen ausgewiesen; kein stiller Verlust |
| FR-03 | P0 | Idempotente, inkrementelle Verarbeitung | Wiederholung derselben Quell-ID erzeugt kein zusätzliches Ereignis; geänderte Inhalte werden versioniert |
| FR-04 | P0 | Ereignis- und Ingestion-Zeit getrennt behandeln | Verzögert angelieferte Testereignisse erscheinen am Ereigniszeitpunkt und werden nicht als neuer Angriff gezählt |
| FR-05 | P0 | Kontrolliertes Query-Gateway | Mandant, Zeitbereich, Tabellen, Ergebnismenge, Timeout und Budget werden vor Ausführung geprüft; verbotene Abfragen erreichen keine API |
| FR-06 | P0 | Hypothesenbasierte Playbooks | Jedes Playbook enthält Startbedingungen, Beleg- und Gegenbelegsuche, Datenvoraussetzungen, Abbruch und Eskalation |
| FR-07 | P0 | Evidenzregister mit Herkunft | Jede wesentliche Aussage referenziert Quelle, Quell-ID soweit vorhanden, UTC-Zeit, Query-Version und Abrufstatus |
| FR-08 | P0 | Telemetrieabdeckung und Unsicherheit | Jeder Bericht trennt Nulltreffer von nicht verfügbaren, abgeschnittenen oder nicht ausreichend lange aufbewahrten Daten |
| FR-09 | P0 | Geschäftskontext | Assetkritikalität, Rolle, Standort, Owner und genehmigte Änderungen werden mit Herkunft und Aktualität berücksichtigt; fehlender Kontext bleibt sichtbar |
| FR-10 | P0 | Analystenentscheidung und Übergabe | Review, Einwände, Owner, Fälligkeit und Übergabestatus werden versioniert; ein Bericht allein gilt nicht als bestätigte Übergabe |
| FR-11 | P0 | Maßnahmenverifikation | Manuell gemeldete Umsetzung und technisch bestätigte Umsetzung bleiben getrennte Status; fehlender Nachweis bleibt offen |
| FR-12 | P0 | Ressourcensteuerung | Pro Fall und Mandant begrenzte Laufzeit, API-Aufrufe, Ergebnisvolumen und Modellkosten; Budgetende führt zu Teilbericht und Eskalation |
| FR-13 | P0 | Oberfläche und Plugin | Beide verwenden dieselbe Fall-API und Berechtigungsprüfung; der Dienst arbeitet nach Schließen der Oberfläche weiter |
| FR-14 | P0 | Berichte und Export | Menschenlesbare Zusammenfassung und strukturierter JSON-Export enthalten Belege, Einschränkungen, Owner und nächste Schritte |
| FR-15 | P1 | Ticket-/CMDB-Anbindung | Ein konfigurierter Adapter synchronisiert per stabiler externer ID; Wiederholung erzeugt keine doppelten Tickets |
| FR-16 | P1 | Netzwerk-/S3-/Storage-Evidenz | Providerabhängige Logquellen werden separat validiert; fehlende Objektzugriffslogs verhindern eine pauschale Abflussentwarnung |
| FR-17 | P1 | AD-CS-/ESC1-Prüfpfad | Bewertung setzt aktuelle Zertifikatvorlagen, Berechtigungen und relevante CA-Konfiguration voraus; ohne diese nur Datenanforderung |
| FR-18 | P2 | Freigegebener Response-Executor | Nur gültig signierte, zielgebundene Freigaben werden ausgeführt; Ergebnis und Wiederanlauf sind idempotent |
| FR-19 | P0 | Verbindliches, versioniertes Lagebild | Jede freigegebene Fassung enthält Scope, Standzeit, betroffene Assets/Identitäten, Fakten, Hypothesen, offene Fragen, Belege und menschlichen Freigeber; widersprüchliche Quellen bleiben sichtbar |
| FR-20 | P0 | Untersuchungsfragen und Abflussbewertung | Jede wesentliche Frage hat Owner, Frist, benötigte Quellen und Status; ein Ausschluss ist nur für expliziten Scope und Zeitraum mit begründeter Evidenzbewertung zulässig |
| FR-21 | P0 | Notbetriebs- und Wiederanlauffreigaben | Ohne benannten Risk Owner, Restrisiko, Kontrollen, Ablaufdatum und menschliche Entscheidung kann keine Freigabe als gültig erscheinen; Ablauf erzeugt Eskalation, keine automatische Verlängerung |
| FR-22 | P0 | Verbindliche Zuständigkeiten und Wirksamkeitsprüfung | Jede Maßnahme hat einen operativen Owner, einen verantwortlichen Entscheider, Frist, Nachweis und Prüfer; Selbstmeldung allein erzeugt keine bestätigte Wirksamkeit |
| FR-23 | P1 | Dienstleister-Aufträge und Abnahme | Jeder Auftrag enthält Scope, Untersuchungsfragen, Liefergegenstände, Evidenzanforderungen, Aufwand mit Herkunft und Abnahmestatus; Abschluss nur nach menschlicher Abnahme |
| FR-24 | P1 | Standortübergreifende Prüfmatrix | Für jede relevante Feststellung sind betroffene oder vergleichbare freigegebene Standorte mit Prüfstatus und Datenabdeckung sichtbar; ungeprüfte Standorte gelten nicht als unauffällig |
| FR-25 | P0 | Entscheidungsprotokoll und Eskalation | Jede Risikoentscheidung referenziert eine Lagebildversion, Alternativen, Begründung, befugten Entscheider und Wiedervorlage; überfällige Punkte werden nach konfigurierter Regel eskaliert |
| FR-26 | P0 | Governance-Berichte und Qualitätsgates | Lagebild, Maßnahmenliste und Notbetriebs-Entscheidungsprotokoll sind reproduzierbar exportierbar; fehlende Nachweise verhindern pauschale positive Statusanzeigen |

MVP-Playbook: verdächtige Anmeldung/Password Spray mit Gegenbelegsuche und optionalem, fest begrenztem Endpunkt-Pivot. Eigenständige Playbooks für Tokenmissbrauch und Endpunkt-Prozessketten folgen in P1. Cloud-Massendownload/Exfiltration wird danach ausgebaut, sobald die benötigten Audit- und Netzwerkquellen nachweislich verfügbar sind.

## 6. Referenzarchitektur

Datenquellen → Konnektoren → normalisiertes Evidenzregister → Untersuchungsdienst → Review und Übergabe.
Scheduler, Queue, Policy-Gateway und Audit begleiten alle Schritte. Web-Oberfläche und Plugin sprechen ausschließlich mit der Fall-API.

Komponenten:
- Konnektor-Service: OAuth, Secret-Referenzen, Pagination, Schemaerkennung, Quoten und Fehlerklassifikation.
- Scheduler/Queue: Trigger, Prioritäten, Leasing, Wiederaufnahme und begrenzte Parallelität.
- Case Service: Fallzustand, Zuständigkeiten und Versionskontrolle.
- Investigation Engine: versionierte Playbooks, Hypothesen, Gegenbelege und Stop-Regeln.
- Query-/Policy-Gateway: erzwingt Scope und Budgets unabhängig vom Modell.
- Evidence Store: minimierte Belege, Herkunft, Hashes und Aufbewahrung.
- Review Service: begründete Analystenentscheidung und Übergaben.
- Governance-Modul im Case Service: Lagebildversionen, Untersuchungsfragen, Risikofreigaben, Dienstleisterabnahmen und Standort-Prüfmatrix; nutzt dieselben Policies und Auditmechanismen, kein separater autonomer Entscheider.
- Audit/Metrics: manipulationsgeschützte Protokollierung, Kosten und Qualitätsmessung.
- Web-/MCP-Adapter: Bedienung ohne eigene abweichende Geschäftslogik.
- Response Service: spätere, gesondert berechtigte Komponente; nicht Bestandteil des MVP.

Technologieentscheidung erst nach Machbarkeitsprüfung. Als Ausgangspunkt: zustandslose API/Worker, relationale Datenbank, dauerhafte Queue und verschlüsselter Objektspeicher. Ein spezialisierter Graphspeicher ist kein MVP-Muss.

## 7. Datenmodell und Zustand

Kernobjekte: Tenant, ConnectorHealth, AssetContext, Case, Hypothesis, QueryRun, Evidence, CoverageGap, Finding, Review, Action, Approval, AuditEvent und BudgetLedger.
Governance-Erweiterungen: SituationReportVersion, InvestigationQuestion, RiskAcceptance, RecoveryGate, SupplierWorkOrder, DeliverableAcceptance, SiteAssessment und DecisionRecord. Alle besitzen stabile IDs, Mandantenscope, Version, zuständige Rollen, Zeitstempel und referenzierte Evidenz. Eine Risikoakzeptanz ist keine technische Aktionsfreigabe und ersetzt niemals ein Approval des Response-Executors.

Evidence speichert mindestens Quellsystem, Mandant, native ID oder nachvollziehbaren Ersatzschlüssel, Ereigniszeit, Abrufzeit, Inhaltshash, minimal erforderliche Felder, Query-Version und Aufbewahrungsfrist. Quellverweise allein reichen nach Ablauf der Quellretention nicht zur Reproduktion; erforderliche Belegauszüge werden deshalb ausdrücklich policygesteuert gesichert.

Case-Zustände: Neu → Vorprüfung → Untersuchung → Review erforderlich → Übergabe bestätigt → fachlich abgeschlossen.
Zusätzliche Zustände: Wartet auf Daten, Budget erreicht, Technischer Fehler, Pausiert.
Die Maschine darf den Untersuchungslauf beenden, aber nicht selbst den Security-Fall fachlich schließen. Späte relevante Evidenz erzeugt einen nachvollziehbaren Wiederaufnahmevorschlag.

Action-Zustände: Vorgeschlagen → Genehmigt → In Bearbeitung → Umsetzung gemeldet → Technisch verifiziert oder Nachweis offen.
Nicht anwendbare Schritte müssen begründet sein; kein automatisches Überspringen von Freigaben.

## 8. Fehlerfälle und Betrieb

- Abgelaufenes Token oder fehlende Berechtigung: Quelle als gestört kennzeichnen, keine endlosen Retries.
- API-Quoten: serverseitige Wartehinweise beachten, exponentielle Verzögerung und Jitter, gemeinsame Mandantenlimits.
- Teilresultat/Trunkierung: nach erlaubter Strategie paginieren oder Zeitfenster teilen; verbleibende Lücke ausweisen.
- Schemaänderung: betroffenen Playbook-Schritt stoppen; keine stillschweigende Interpretation falscher Felder.
- Modellfehler: validierte strukturierte Ausgabe verlangen; ungültige Ausgabe nicht ausführen.
- Nicht erreichbare Quelle: verfügbare Evidenz auswerten, Schlussfolgerung einschränken und Datenbedarf eskalieren.
- Neustart oder doppelte Zustellung: stabile Auftragsschlüssel und transaktionale Statusänderungen.
- Widersprüchliche Evidenz: ausdrücklich zum Review, keine Mehrheitsentscheidung ohne Erklärung.

Vorgeschlagene Pilotlimits: höchstens 20 Abfragen und 30 Minuten aktive Bearbeitung je Fall sowie zwei parallele Fälle je Mandant. Kostenobergrenze wird vor Pilotstart vom Betreiber festgelegt; ohne konfigurierte Grenze kein autonomer Modus. Wartezeiten auf externe Daten werden separat gemessen.

## 9. Sicherheit, Datenschutz und Governance

- Least Privilege; Leserechte im MVP, separate Dienstidentitäten für spätere Schreibaktionen.
- Mandantenscope aus vertrauenswürdiger Sitzung und Konfiguration, niemals aus ungeprüftem Modelltext.
- Secrets im Secret Store; keine Token oder Kennwörter in Prompts, Reports oder Diagnoseausgaben.
- Logs, E-Mails, Dokumente und Tool-Ergebnisse sind nicht vertrauenswürdige Daten und dürfen keine Tool-Berechtigungen verändern.
- Nur freigegebene Modellanbieter und Regionen; Übermittlung und Trainingsverwendung vertraglich/technisch vorab prüfen.
- Minimierung und Pseudonymisierung vor Modellaufrufen, soweit die Untersuchung dadurch nicht verfälscht wird.
- Rollen: Leser, Analyst, Incident Lead, Integrationsadministrator, Auditor; sensible Rechteänderungen separat protokollieren.
- Audit enthält Policy-, Playbook- und Modellversion, Tool-Aufrufe, Ergebnisstatus und Freigaben; keine geheimen Modellgedanken.
- Verschlüsselung, Wiederherstellungsprüfung, Zugriffsaudit und dokumentierte Löschprozesse.
- Aufbewahrungsvorschlag: minimierte Fallevidenz 90 Tage, Audit 365 Tage; erst nach fachlicher/datenschutzrechtlicher Freigabe aktivieren. Legal Hold überschreibt automatische Löschung nachvollziehbar.
- Kein automatischer Export an private Postfächer oder unbekannte externe Dienste.
- Keine pauschale Aussage „forensisch gerichtsfest“: eine entsprechende Beweissicherung erfordert gesonderte Verfahren und Prüfung.

## 10. Qualitätsziele und Abnahme

Ziele sind Pilotvorgaben, keine Zusicherung bereits gemessener Leistung.

| Kennzahl | Vorgeschlagenes Ziel / Messung |
|---|---|
| Menschliche Bearbeitungszeit | Median mindestens 30 % niedriger gegenüber vergleichbaren manuellen Fällen, inklusive Review und Nacharbeit |
| Belegbarkeit | 100 % entscheidungsrelevanter Feststellungen mit Herkunft oder explizit als unbestätigt markiert |
| Kritische Befunde | Keine zusätzliche übersehene kritische Feststellung im freigegebenen Benchmark gegenüber der Analystenreferenz |
| Unberechtigte Aktionen | Null in Negativtests; jeder Versuch wird blockiert und protokolliert |
| Deduplizierung | 100 % erwartete Zusammenführung im kuratierten Doppelereignis-Testset |
| Wiederaufnahme | Kein verlorener Auftrag und keine doppelte externe Wirkung in Ausfalltests |
| Datenlücken | Alle absichtlich eingebauten Quell-, Retention- und Berechtigungslücken werden ausgewiesen |
| Bedienbarkeit | Analyst kann jeden entscheidungsrelevanten Beleg aus dem Fall öffnen oder dessen Nichtverfügbarkeit erkennen |

Pflichttests (MVP: 1–13 und 15–16; Test 14 ist Abnahmebedingung für FR-23 in P1):
1. Erfolgreicher Login versus blockierter Ressourcenaufruf: keine unbelegte Schlussfolgerung auf Datenzugriff.
2. Derselbe Login mit späterer Ingestion: ein Ereignis, korrekte Zeitleiste.
3. Leere Abfrage bei fehlender Retention: keine Entwarnung.
4. Prompt-Injection in Logtext: keine Ausführung der enthaltenen Anweisung.
5. Mandantenwechsel und manipulierte Objekt-ID: Zugriff abgelehnt.
6. Neustart während Abfrage/Übergabe: deterministische Wiederaufnahme.
7. Maßnahmenstatus „erledigt“ ohne technischen Nachweis: Verifikation bleibt offen.
8. API-Ausfall/429/Trunkierung: Teilbericht mit sichtbaren Grenzen.
9. Fehlende Storage-Logs: Datenabfluss bleibt ungeklärt statt ausgeschlossen.
10. Budgetüberschreitung: keine weiteren autonomen Aufrufe nach ausgeschöpftem Budget.
11. Abgelaufene Notbetriebsfreigabe: als abgelaufen anzeigen, Owner und Eskalationsempfänger informieren; weder automatisch verlängern noch produktive Verbindungen abschalten.
12. Widerspruch zwischen Dienstleisterbericht und Logbefund: beide Quellen erhalten, Klärungsfrage eröffnen und Entwarnung bis zum menschlichen Review verhindern.
13. Standort ohne geprüfte Telemetrie: Status „nicht geprüft“ oder „unzureichende Daten“, niemals pauschal grün.
14. Dienstleister markiert einen Auftrag als abgeschlossen: ohne dokumentierte menschliche Abnahme bleibt der Liefergegenstand „zur Abnahme“.
15. Risk Owner akzeptiert ein Restrisiko: die offene technische Datenlücke bleibt sichtbar; der Fall wird dadurch nicht als technisch bereinigt markiert.
16. Änderung des Scopes oder neuer kritischer Gegenbeleg: bestehende Entscheidung wird zur Neubewertung markiert und der befugte Entscheider benachrichtigt.

## 11. Pilot und Wirtschaftlichkeit

Phase 1: 20 anonymisierte oder synthetische Fälle zum Erkennen von Workflowproblemen; keine statistisch belastbare Einspargarantie.
Phase 2: 50–100 repräsentative, nach Schweregrad und Falltyp geschichtete Fälle mit verblindeter fachlicher Referenzbewertung. Stichprobengröße anhand der gemessenen Streuung nachjustieren.
Phase 3: Live-Shadow-Betrieb: System arbeitet autonom lesend, Menschen behalten Entscheidung und operative Verantwortung.
Phase 4: Begrenzter produktiver Rollout nach dokumentierter Abnahme.

Verglichen werden identische Falldaten und gleiche Betrachtungszeiträume. Erfasst werden menschliche Arbeitszeit, Wartezeit, Nacharbeit, Fehlalarme, übersehene Befunde, API-/Modellkosten und Betriebsaufwand. Ergebnis nach Falltyp ausweisen, nicht nur als Gesamtdurchschnitt.

Nettonutzen = vermiedene menschliche Arbeitszeit × Vollkostensatz − laufende Plattform-, Modell-, API-, Betriebs- und Review-Mehrkosten.
Einmaliger Aufbau und Integration sind separat in der Amortisation zu berücksichtigen. Eine eingesparte Stunde reduziert nicht automatisch einen externen Pauschalvertrag. Die 30-%-Zielmarke ist eine zu prüfende Hypothese.

## 12. Lieferphasen und Verantwortlichkeiten

| Phase | Ergebnis / Freigabegate | Verantwortliche Rolle |
|---|---|---|
| Discovery | Quellzugriff, Datenumfang, Hosting, Datenschutz, Pilotbudget bestätigt | Product Owner + Security Lead |
| Fundament | Authentifizierung, Policy-Gateway, Queue, Audit, Datenmodell getestet | Engineering Lead + Plattformbetrieb |
| MVP | Ein Referenz-Playbook, Evidenzregister, Review, schlanke Oberfläche/Plugin und Governance-Basis gemäß Abschnitt 17 | Engineering + SOC |
| Qualität | Replay-, Sicherheits-, Ausfall- und Benchmarktests bestanden | QA + Security Lead |
| Pilot | Gemessener Nutzen, dokumentierte Einschränkungen und Betriebsfreigabe | SOC Lead + Product Owner |
| Ausbau | Ticket-/CMDB-Adapter, weitere Datenquellen und Playbooks, Dienstleister-Workflow und Standortmatrix | Integration Owner |
| Reaktion | Eigenes Sicherheitskonzept und gesonderte Freigabe für A2/A3 | Security Governance |

Keine belastbare Termin- oder Budgetzusage ohne bestätigte Teamkapazität und Schnittstellenzugänge. Die Phasen sind Liefergates, kein bereits freigegebener Projektplan.

## 13. Risiken und offene Produktentscheidungen

| Risiko | Gegenmaßnahme |
|---|---|
| Fehlende oder zu spät verfügbare Telemetrie | Abdeckungsprüfung und explizite Datenlücken |
| Selbstsichere, unbelegte Modellbewertung | Evidenzpflicht, Gegenhypothesen, Analystenreview |
| Automatisierung vervielfacht Fehler | Budgets, feste Scopes, Canary-/Shadow-Betrieb und Stoppschalter |
| Überhöhte Berechtigungen | Getrennte Identitäten, Policy-Gateway und Berechtigungstests |
| Hohe Gesamtkosten | Inkrementelle Verarbeitung, Cache mit Frischeangabe, kleine Abfragen, Kostenledger |
| Dauerhaft offene Übergaben | Owner, Frist, Eskalation und technische Ergebnisprüfung |
| Veralteter Geschäftskontext | Herkunft, Aktualität und Bestätigung durch zuständige Rolle |

Vor Entwicklungsfreigabe zu entscheiden:
- Product Owner und fachliche Abnahmeinstanz benennen.
- Hostingregion, Modellanbieter und zulässige Datenklassen bestätigen.
- Konkrete Quellen, API-Rechte und Lizenz-/Retention-Voraussetzungen im Zielmandanten prüfen.
- Pilotkostenobergrenze und Betriebszuständigkeit festlegen.
- Ticket-/CMDB-Zielsystem für die spätere Integration auswählen.
- Aufbewahrung und zulässige interne Benachrichtigungsempfänger freigeben.
- Befugnisse für Risikoakzeptanz, Freigaben, unabhängige Prüfung und Eskalationsfristen schriftlich festlegen; ohne diese Konfiguration bleiben entsprechende Entscheidungsfunktionen gesperrt.

## 14. Definition of Done für den MVP

Alle P0-Anforderungen im Lieferzuschnitt von Abschnitt 17 sind nachweislich getestet; die MVP-Pflichtprüfungen aus Abschnitt 10 und die Abnahmen aus Abschnitten 18–23 bestehen. Der autonome Dienst funktioniert ohne aktive Chat-Sitzung. Datenlücken und unbelegte Aussagen sind sichtbar. Es gibt keine produktiven Response-Rechte. Audit, Backup-Wiederherstellung, Stoppschalter und Betriebsübergabe sind überprüft. Pilotresultate, bekannte Grenzen und Freigaben liegen schriftlich vor.
Die drei Governance-Kernartefakte aus Abschnitt 15 müssen als einfache versionierte Fallansichten und Exporte vorliegen; Berechtigungs-, Ablauf- und Eskalationsregeln sind verpflichtend. Erweiterte Management-Dashboards, Dienstleister-Workflows und die interaktive Standortmatrix sind P1. Aufwand und Lieferplanung sind anhand dieses verkleinerten MVP neu zu bewerten; die vollständige Produktvision bleibt erhalten.

Nächster Schritt: PRD fachlich prüfen und freigeben; danach einen separaten technischen Umsetzungsplan samt Aufwandsschätzung erstellen. Dieses Dokument beauftragt weder Softwareentwicklung noch produktive Eingriffe.

## 15. CISO-Steuerung und verbindliche Entscheidungsqualität

### 15.1 Zweck und Leitprinzip

Das Produkt unterstützt den CISO dabei, Untersuchungen zu steuern und Erkenntnisse in nachweislich wirksame Maßnahmen zu überführen. Es ersetzt weder dessen Verantwortung noch die Entscheidung eines befugten geschäftlichen Risk Owners. Die Anforderungen beschreiben einen Soll-Prozess und sind keine persönliche Leistungsbewertung eines konkreten CISO oder Dienstleisters.

„Läuft wieder“, „umgesetzt“, „technisch verifiziert“ und „Restrisiko akzeptiert“ sind getrennte Aussagen. Das System darf daraus kein pauschales „sicher“ ableiten. Jede positive Bewertung muss den geprüften Scope, Zeitraum, Datenstand und bekannte Einschränkungen nennen.

### 15.2 Drei verbindliche Führungsartefakte

1. Gemeinsames Lagebild: betroffene Systeme und Identitäten, Standorte, Ereigniszeitraum, geschäftliche Auswirkungen, bestätigte Fakten, Hypothesen, Gegenbelege, Datenlücken und offene Untersuchungsfragen. Jede wesentliche Aussage verweist auf Evidenz. Entwurf und menschlich freigegebene Fassung sind sichtbar getrennt; neue kritische Evidenz kennzeichnet die bisherige Freigabe als überprüfungsbedürftig.
2. Priorisierte Maßnahmenliste: Risiko und Begründung der Priorität, operativer Owner, verantwortlicher Entscheider, Frist, Abhängigkeiten, Umsetzungsmeldung, Prüfmethode, Prüfer, Prüfergebnis und Restunsicherheit. „Erledigt“ ohne erforderlichen Nachweis zählt nicht als wirksam abgeschlossen.
3. Entscheidungsprotokoll zum Notbetrieb: betroffener Geschäftsprozess und technische Verbindungen, Handlungsalternativen, verbleibende Risiken, kompensierende Kontrollen, Überwachung, befugter Risk Owner, Entscheidung, Gültigkeit, Wiedervorlage und Kriterien für den Regelbetrieb.

Alle drei Artefakte müssen dieselben versionierten Falldaten verwenden. Unterschiedliche Berichtsstände dürfen nicht unbemerkt zu widersprüchlichen Managementaussagen führen. Kritische Veränderungen werden ereignisbezogen gemeldet; die regelmäßige Wiedervorlage wird durch eine vor Aktivierung festgelegte Incident-Cadence gesteuert.

### 15.3 Datenabfluss und verbleibende Unsicherheit

Der Dienst führt für jede Abflussfrage einen eigenen Prüfauftrag: welche Daten, aus welchem System, über welchen Kanal, in welchem Zeitraum und zu welchem Ziel? Er trennt Vorbereitung, Kopier-/Uploadversuch, nachgewiesene Übertragung und nachgewiesenen Inhalt. Ein Prozessstart oder eine Netzwerkverbindung belegt allein keinen erfolgreichen Upload.

Zulässige Ergebniszustände: „nachgewiesen“, „begründeter Verdacht“, „kein Nachweis bei dokumentierter Abdeckung“, „für abgegrenzten Scope begründet ausgeschlossen“ und „nicht entscheidbar wegen Datenlücken“. Der stärkere Ausschluss benötigt ein menschliches Review der Abdeckung und der Gegenhypothesen. Fehlende Storage-, Proxy- oder Netzwerklogs bleiben ausdrücklich sichtbar; Zeitfenster oder theoretische Bandbreite allein beweisen keine tatsächliche Datenmenge.

Im MVP werden auch manuell bereitgestellte, mit Herkunft versehene Belege und Datenanforderungen verwaltet. Das ersetzt nicht die erst für P1 vorgesehenen automatischen Storage-/Netzwerkadapter.

### 15.4 Risikobasierter Notbetrieb und Wiederanlauf

Für zeitweise Tunnel, Fernzugriffe und wieder aktivierte Anwendungen erfasst das System mindestens Zweck, Quelle/Ziel, erlaubte Identitäten, Berechtigungen, Öffnungszeiten, Überwachung, verantwortlichen Betreiber, Ablaufdatum und Rückfallplan. Die genaue technische Ausgestaltung wird durch zuständige Fachverantwortliche geprüft, nicht vom Modell als sicher erklärt.

Der Übergang in den Regelbetrieb erfordert dokumentierte Kriterien: erforderliche Bereinigung und Härtung, Wiederherstellungs-/Funktionstest, relevante Kontrollnachweise, Telemetrie und Überwachung sowie menschliche Freigabe. Nicht abschließend klärbare Punkte benötigen eine ausdrückliche, befristete Risikoentscheidung durch eine befugte Rolle. Ein abgelaufenes oder verändertes Risiko erzeugt erneuten Entscheidungsbedarf; im MVP keine automatische operative Abschaltung.

### 15.5 Dienstleistersteuerung und nachvollziehbarer Aufwand

Lieferstufe P1: Im MVP werden externe Belege und offene Fragen mit Quellenangabe im Fall erfasst; ein eigener Auftrags-, Abrechnungs- und Abnahme-Workflow wird noch nicht gebaut.

Dienstleister erhalten abgegrenzte Untersuchungsfragen statt ausschließlich allgemeiner Arbeitsaufträge. Pro Liefergegenstand werden Scope, Quellen, Analyseverfahren, Belege, Schlussfolgerungen, Grenzen, offene Punkte und nächste Entscheidung erfasst. Abnahmezustände: beauftragt, in Bearbeitung, geliefert, Nachbesserung erforderlich, abgenommen.

Das System unterstützt den Vergleich externer Berichte mit eigenen Erkenntnissen. Ein Widerspruch erzeugt eine Klärungsfrage, keine automatische Schuldzuweisung. Fehlende Kommentare in einem einzelnen Datenexport belegen nicht, dass keine Analyse erfolgt ist.

Aufwand wird als „geschätzt“, „gemeldet“, „belegt“ oder „abgerechnet“ gekennzeichnet. Incident-Anzahl ist kein automatischer Ersatz für Arbeitsstunden. Vertragsmodelle, Leistungsumfang und verfügbare Zeitnachweise müssen bei einer Wirtschaftlichkeitsbewertung berücksichtigt werden; das System behauptet keine Rechnungsersparnis allein aus Automatisierung.

### 15.6 Zuständigkeiten und Eskalation

| Aufgabe | Operative Durchführung | Verantwortliche Entscheidung |
|---|---|---|
| Lagebild und Untersuchungsfragen | Incident Lead mit SOC und Forensik | Benannte fachliche Freigabeinstanz; CISO verantwortet den Prozess |
| Identity-, Netzwerk-, Endpoint- und Anwendungsmaßnahmen | Jeweiliger Fach-Owner | Zuständiger Service-/Kontrollverantwortlicher |
| Wirksamkeitsnachweis kritischer Maßnahmen | Qualifizierter Prüfer, getrennt vom Ausführenden | Benannte Abnahmeinstanz |
| Priorisierung und Eskalation | Incident Lead | CISO oder benannte Vertretung |
| Befristete Akzeptanz geschäftlicher Restrisiken | Fach-Owner bereitet Entscheidung vor | Befugter geschäftlicher Risk Owner; CISO berät bzw. entscheidet nur mit Delegation |
| Dienstleisterabnahme | Fachlicher Auftraggeber | Benannter Abnahmeverantwortlicher |

Ein Gesamtkoordinator ersetzt nicht die Fachzuständigkeiten. Jede Maßnahme erhält genau einen operativen Owner; zusätzliche Beteiligte und Stellvertretungen sind möglich. Eskalationswege und Fristen werden je Priorität verbindlich konfiguriert. Kritische Maßnahmen ohne Owner oder ohne gültige Entscheidung bleiben als Steuerungslücke sichtbar.

### 15.7 Standortübergreifende Prüfung

Die interaktive Prüfmatrix und automatische Vergleichsvorschläge sind P1. Im MVP werden freigegebener Standortscope und nicht geprüfte Standorte im Bericht ausdrücklich genannt.

Relevante Erkenntnisse erzeugen Vorschläge für Prüfungen vergleichbarer, bereits freigegebener Standorte: gemeinsame Identitäten, Vertrauensstellungen, Administrationspfade, Fernzugänge und gleiche Systemtypen. Die Matrix zeigt je Standort: nicht geprüft, in Prüfung, Befund, kein Nachweis innerhalb des geprüften Scopes oder unzureichende Daten. Nicht passende Prüfungen benötigen eine Begründung.

Zusätzliche Standorte oder Mandanten außerhalb des freigegebenen Scopes werden ausschließlich vorgeschlagen, nicht autonom untersucht. Die Oberfläche darf aus einem unauffälligen Standort keine globale Entwarnung ableiten.

### 15.8 CISO-Kennzahlen und Abnahme

Zusätzlich zu technischen Kennzahlen werden ausgewiesen: Alter des freigegebenen Lagebildes, Anzahl kritischer offener Fragen, überfällige Maßnahmen, Anteil technisch verifizierter Maßnahmen, abgelaufene Risikofreigaben, Standortabdeckung und ausstehende Dienstleisterabnahmen. Jede Quote zeigt Zähler, Nenner und Datenstand; fehlende Prüfungen werden nicht aus dem Nenner entfernt, um bessere Ergebnisse zu erzeugen.

MVP-Abnahme anhand des synthetischen Referenzfalls aus Abschnitt 18: Das System erstellt alle drei Führungsartefakte in einfacher Form, hält offene Datenfragen trotz akzeptiertem Notbetrieb sichtbar, erfasst fehlende Belege, eskaliert eine abgelaufene Freigabe und verhindert einen unbefugten fachlichen Abschluss. Der Test darf keine produktive Maßnahme auslösen. Standortübergreifende Matrix- und Dienstleisterkennzahlen werden erst mit ihren P1-Funktionen abgenommen; vorher erscheinen sie als nicht verfügbar. Die Kennzahlen unterstützen menschliche Entscheidungen und sind kein automatisches Leistungsranking einzelner Personen.

## 16. Änderungshistorie

| Version | Änderung |
|---|---|
| 0.1 | Erstentwurf: autonomer Untersuchungskern mit Plugin, 18 Anforderungen, Sicherheitsgrenzen und Pilot |
| 0.2 | CISO-Steuerung integriert: acht zusätzliche Anforderungen FR-19 bis FR-26, Rollen und Governance-Datenmodell, sechs zusätzliche Pflichtprüfungen, erweiterte MVP-Abnahme und vollständiger Führungsprozess in Abschnitt 15 |
| 0.3 | MVP auf ein Playbook verkleinert; Governance-Basis erhalten, erweiterte Workflows nach P1 verschoben. Referenzfall, Machbarkeits-Gate, Schnittstellenverträge, Priorisierung, Benachrichtigungen, Stop-/Wiederaufnahmeregeln, Release-Sicherheit sowie Betriebs- und Kostenrahmen ergänzt |

## 17. Verbindlicher MVP-Zuschnitt

Der MVP liefert einen zuverlässig durchlaufenden Untersuchungsprozess statt einer vollständigen SOC-/GRC-Plattform.

| Bestandteil | MVP | P1 oder später |
|---|---|---|
| Untersuchung | Ein Login-/Password-Spray-Playbook; begrenzter Endpunkt-Pivot nur bei verfügbarer Quelle | Eigenständige Token-, Prozessketten-, Exfiltrations- und AD-CS-Playbooks |
| Quellen | Defender-Alarmdaten plus ein verbindlich ausgewählter Entra-Logpfad; Endpunktdaten bei erfolgreichem Gate | Zusätzliche redundante Pfade, Storage, Netzwerk, weitere Provider |
| Kontext | Validierter manueller Import mit Herkunft und Aktualität | Automatische CMDB-Synchronisation |
| Bedienung | Fallliste, Evidenz, offene Fragen, Review, Maßnahmen und schlanker Plugin-Adapter | Erweiterte Management-Dashboards und frei konfigurierbare Berichte |
| Governance | Drei versionierte Kernartefakte, menschliche Entscheidungen, befristete Risikofreigabe, technische Nachweise | Dienstleister-Auftragsworkflow, interaktive Standortmatrix und deren Kennzahlen |
| Übergabe | Interner Fall mit Owner, Frist und erlaubter Benachrichtigung | Externe Ticketsynchronisation |
| Autonomie | A1, begrenzt auf freigegebene Read-only-Aufträge | A2/A3 nach gesonderter Sicherheitsfreigabe |

FR-01 verlangt für jede tatsächlich gewählte Quelle einen nachgewiesenen Zugriff; nicht alle alternativen Datenpfade müssen implementiert werden. FR-09 wird zunächst durch einen validierten Import erfüllt. FR-11/22 erlauben überprüfte manuell eingebrachte technische Belege; ein bloßes „erledigt“ bleibt unzureichend. FR-19/21/25/26 werden durch gemeinsame Fallformulare und Exporte erfüllt, nicht durch zusätzliche Plattformen.

Scope-Änderungen benötigen eine dokumentierte Entscheidung von Product Owner und Security Lead einschließlich Aufwand, Risiko und Auswirkung auf die Abnahme.

## 18. Vollständiger synthetischer Referenzfall

Testdaten: Mandant DEMO, Standort Nord, Benutzer user-17, Endpunkt demo-client-17; keine realen Identitäten oder Incident-Daten. Alle Zeiten UTC an einem synthetischen Testtag.

| Schritt | Eingabe / Aktion | Erwartetes Ergebnis |
|---|---|---|
| 1 – Alarm | 09:00 Uhr: 40 fehlgeschlagene Anmeldungen über zehn Testkonten, ein anschließendes erfolgreiches Login von user-17 | Ein Fall mit abgegrenztem Zeitfenster, Scope, Budget und offenem Verdacht; kein automatisches Kompromittierungsurteil |
| 2 – Vorprüfung | Leserechte und Login-Abdeckung für 08:00–10:00 Uhr bestätigt; Datei-Audit fehlt | Login-Untersuchung möglich; Datenzugriffs-/Abflussfrage ausdrücklich nicht vollständig beantwortbar |
| 3 – Deduplizierung | Erfolgreiches Login wird zweimal mit identischer Quell-ID, aber unterschiedlicher Ingestion-Zeit geliefert | Ein Login-Ereignis, beide Abrufinformationen nachvollziehbar |
| 4 – Hypothesen | Angriff, legitime Nutzeraktivität, automatisierter Fehlversuch | Jede Hypothese erhält erwartete Belege und Gegenbelege |
| 5 – Abfragen | Login-Ergebnis, Ressourcenzugriffe und freigegebener Kontext; optional begrenzter Endpoint-Pivot | Query-Version, Quellen und Ergebnisse dokumentiert; fehlender Endpoint-Zugriff erzeugt eine Lücke |
| 6 – Gegenbeleg | Ressourcenzugriff nach dem Login wird blockiert; Nutzerbestätigung ist noch ausstehend | Login-Erfolg und Ressourcenblockade getrennt darstellen; keine Aussage „MFA umgangen“ oder „Daten abgeflossen“ |
| 7 – Ergebnis | Keine weiteren diskriminierenden Abfragen in den vorhandenen Quellen | Untersuchungslauf endet im Review; offene Fragen zu Nutzerbestätigung und Datei-Audit bleiben erhalten |
| 8 – Maßnahmen | Owner erhält Auftrag zur Identitätsprüfung; Umsetzung eines Sitzungswiderrufs wird nur gemeldet | Maßnahme bleibt bis zu geeignetem technischem Beleg „Nachweis offen“; Software widerruft selbst nichts |
| 9 – Entscheidung | Risk Owner genehmigt im Test den eingeschränkten Betrieb bis 12:00 Uhr | Befristete Entscheidung mit Kontrollen, Scope und Restunsicherheit; keine technische Entwarnung |
| 10 – Ablauf | Testuhr erreicht 12:00 Uhr ohne Verlängerung | Einmalige Ablaufeskalation gemäß Policy, keine automatische Verlängerung oder Abschaltung |
| 11 – Neue Evidenz | 12:10 Uhr: zuvor fehlender relevanter Auditbeleg trifft ein | Bei offenem Fall begrenzter Delta-Lauf; bei fachlich geschlossenem Fall Wiederaufnahmevorschlag an Menschen |

Erwartete Artefakte: Lagebild mit belegten Fakten und Grenzen; Maßnahmenliste mit Owner und Nachweisstatus; Entscheidungsprotokoll mit Ablauf; vollständiges Query-/Audit-Protokoll. Abnahme nur, wenn alle elf Schritte reproduzierbar sind und keine unerlaubte Schreibaktion auftritt.

## 19. Machbarkeits-Gate und Schnittstellenverträge

Vor einer verbindlichen Entwicklungsaufwands- oder Terminzusage wird ein begrenzter Read-only-Machbarkeitstest gesondert freigegeben. Dieses PRD behauptet keine bereits verifizierte API-Verfügbarkeit.

Für jeden gewählten Konnektor ist ein versionierter Vertrag erforderlich:

- Exakter API-Endpunkt, API-Version, Authentifizierungsmodus und dokumentierte Least-Privilege-Rechte einschließlich nötiger Rollen und Zustimmung.
- Benötigte Tabellen/Felder, Datentypen, stabile IDs, UTC-Semantik und Zuordnung zu den Playbook-Fragen.
- Lizenzvoraussetzungen, tatsächlich verfügbare Retention, Quelllatenz und nachgewiesenes Abfragezeitfenster.
- Pagination, Ergebnislimits, Quoten, Timeouts, Fehlercodes und zulässige Wiederholungen.
- Minimierte Speicherung, Löschfrist, Datenregion, zulässige Modellübermittlung und verantwortlicher Betreiber.
- Erfolgs-, Leerresultat-, Berechtigungsfehler-, Quoten-, Trunkierungs- und Schemaänderungstest.

| Datenbedarf | Zu prüfender Integrationspfad | Abhängigkeit |
|---|---|---|
| Alarme und Fallkontext | Gewählte unterstützte Defender-/Microsoft-Security-API | Pflicht für Alarmstart; sonst kein autonomer Alarmbetrieb |
| Anmelde- und Zugriffsereignisse | Entweder freigegebener Entra-API-Pfad oder tatsächlich befüllte Logquelle im Sentinel-/Log-Analytics-Umfeld | Pflicht für das Referenz-Playbook; Semantik und Abdeckung je Ereignistyp prüfen |
| Endpunkt-Pivot | Unterstützter Hunting-Pfad mit erforderlichen Prozess-/Netzwerkfeldern | Optional; ohne Nachweis bleibt Pivot deaktiviert |
| Asset-/Owner-Kontext | Validierter Import | Pflichtfelder und Frischegrenze prüfen; fehlende Werte sichtbar |
| Storage-/Netzwerk-Audit | Providerabhängig, P1 | Keine Exfiltrationsentwarnung aus nicht vorhandener Quelle |

Go-Kriterien: erforderliche Quellen lesbar, Referenzdaten korrekt normalisiert, Rechte minimal, Wiederholungen beherrscht, Quoten ausreichend und Testkosten gemessen. Ergebnis je Quelle: bestanden, mit dokumentierter Einschränkung bestanden oder nicht bestanden. Fehlt die verpflichtende Login-Quelle, bleibt A1 deaktiviert; Produktumfang muss neu entschieden werden. Konkrete API-Namen und Berechtigungen werden erst nach Prüfung aktueller Herstellerdokumentation und Zielumgebung im Vertrag fixiert.

## 20. Erklärbare Priorisierung und kontrollierte Benachrichtigungen

Untersuchungspriorität und Belegstärke sind getrennte Felder. Wenig Evidenz darf einen potenziell kritischen Fall nicht automatisch herabstufen.

Vorgeschlagene deterministische Reihenfolge:

1. Dringlichkeit U0: Hinweise auf aktive Ausbreitung, destruktive Aktivität oder Missbrauch einer hochprivilegierten Identität mit möglicher kritischer Auswirkung. Sofortiger menschlicher Review, auch bei noch unvollständiger Evidenz.
2. U1: plausibler unberechtigter Zugriff auf kritisches Asset oder anhaltende Angriffsaktivität.
3. U2: begrenzter Verdacht ohne belegte akute Auswirkung.
4. U3: Informations- und Kontextaufträge ohne akute Angriffshinweise.

Innerhalb einer Klasse: Geschäftsauswirkung, Assetkritikalität, Privilegierung und Alter des unbearbeiteten Falls. Quell-Schweregrad und Belegstärke werden angezeigt, ersetzen aber keine Erklärung. Fehlende Kritikalität ist „unbekannt“, nicht „niedrig“; ein potenziell kritischer Fall wird zur Einordnung vorgelegt. Jede Einstufung speichert Regelversion, Eingabefaktoren und Begründung. Menschliche Übersteuerung ist möglich und auditpflichtig.

Pilotvorschlag für Benachrichtigungen: U0 sofort an den benannten Bereitschaftsempfänger; nach 15 Minuten ohne Bestätigung an dessen Vertretung. U1 sofort an den Owner, Eskalation nach 60 Minuten innerhalb vereinbarter Abdeckung. U2/U3 in einer täglichen Zusammenfassung. Diese Fristen müssen vor A1-Aktivierung vom Betreiber bestätigt oder ersetzt werden; ohne erreichbaren U0-Eskalationsweg kein unbeaufsichtigter A1-Betrieb.

Nachrichtenschlüssel: Fall-ID, relevante Befundversion und Eskalationsstufe. Unveränderte Ergebnisse erzeugen keine neue Meldung. Neue materielle Evidenz, höhere Dringlichkeit, neue betroffene Identität oder abgelaufene Freigabe rechtfertigen eine neue Meldung. Empfangsbestätigung ist kein fachlicher Abschluss. Einmaliges Snoozing benötigt Owner, Grund und Ende; neue U0-Evidenz hebt das Snoozing auf. Zustellfehler werden sichtbar und über einen vorkonfigurierten Ersatzkanal eskaliert, niemals als erfolgreiche Übergabe gewertet.

Abnahme: priorisierte Testfälle werden erklärbar eingeordnet; 100 Duplikate lösen eine Erstmeldung statt 100 Nachrichten aus; neue kritische Evidenz wird trotz Bündelung gemeldet.

## 21. Fortsetzung, Stoppen und Wiederaufnahme

Eine Folgeabfrage ist nur zulässig, wenn sie eine benannte offene Hypothese unterscheiden oder eine konkrete Datenlücke schließen kann, innerhalb des Scopes liegt und Budget verfügbar ist. Vor Ausführung speichert der Dienst Frage, erwarteten Erkenntnisgewinn und Bezug zu bisherigen Ergebnissen. Identische Abfragen gegen unveränderte Daten werden nicht wiederholt.

| Situation | Verhalten |
|---|---|
| Neue diskriminierende Frage und verfügbare Quelle | Begrenzten nächsten Schritt ausführen |
| Keine neue relevante Evidenz nach zwei aufeinanderfolgenden Pivot-Schritten | Lauf beenden und Ergebnis zum Review bereitstellen |
| Alle zulässigen Prüfungen ausgeschöpft | Ergebnis einschließlich Restunsicherheit liefern; keinen Fall automatisch schließen |
| Pflichtquelle fehlt oder ist außerhalb der Retention | Datenanforderung mit Owner; Zustand „Wartet auf Daten“; keine sinnlosen Wiederholungen |
| API-Störung | Begrenzte technische Retries gemäß Konnektorvertrag; danach technischer Fehler und Eskalation |
| Laufzeit-, Kosten- oder Abfragebudget erreicht | Keine neuen Aufrufe; Teilbericht und Reviewbedarf |
| Neuer Scope oder zusätzliche Berechtigung nötig | Stoppen und menschliche Freigabe anfordern |
| Neue relevante Evidenz bei offenem Fall | Automatischer Delta-Lauf nur innerhalb des bestehenden Scopes und des kumulativen Fallbudgets |
| Neue relevante Evidenz nach fachlichem Abschluss | Menschlichen Wiederaufnahmevorschlag erzeugen; kein stiller Abschlusswiderruf |

Wiederaufnahme setzt nachvollziehbaren Trigger voraus: neue Quell-ID, materiell geänderter Beleg, wieder verfügbare benötigte Quelle oder menschlicher Auftrag. Sie setzt das Fallbudget nicht zurück. Zusätzliche Budgets erfordern eine befugte, auditierte Entscheidung. Ein Queue-Neustart zählt nicht als neue Untersuchung.

Abnahme: Endlosschleifen, künstliche Budgetresets und wiederholte Nulltreffer-Pivots werden im Replay verhindert; neue relevante Evidenz geht dennoch nicht verloren.

## 22. Sichere Änderungen an Modell, Prompt und Playbook

Jeder Lauf bindet unveränderliche Versionen von Modellkonfiguration, Prompt, Playbook, Query-Vorlagen, Policy und Normalisierung. Änderungen benötigen ein Release-Paket mit Begründung, Testresultaten, Freigabe und Rückkehrversion.

Release-Gates:

1. Struktur-/Policytests sowie alle für den Lieferumfang geltenden Pflichtprüfungen bestehen.
2. Referenzfall und repräsentativer Benchmark werden erneut ausgeführt; keine neue kritische Auslassung, kein Verlust von Herkunftsnachweisen und keine unerlaubte Aktion.
3. Kosten und Analysten-Nacharbeit werden mit der freigegebenen Version verglichen; Verschlechterungen außerhalb vorab vereinbarter Toleranzen blockieren die Freigabe.
4. Zunächst Shadow-Lauf; anschließend begrenzte Einführung für einen freigegebenen Teil der Fälle.
5. Sofortiger Rollback bei Sicherheitsverletzung oder kritischem Qualitätsverlust.

Rollback ändert keine historischen Belege. Betroffene Läufe werden markiert und bei Bedarf mit freigegebener Version zur Neubewertung vorgelegt. Datenmigrationen benötigen eine kompatible Wiederherstellungsstrategie; bloßes Zurücksetzen der Modellversion reicht nicht aus. Das System darf produktive Prompts oder Policies nicht selbstlernend ohne Freigabe verändern.

Abnahme: absichtlich fehlerhafte neue Playbook-Version wird vor Produktivfreigabe blockiert; Wiederherstellung der vorherigen Version ist getestet.

## 23. Betriebs- und Kostenrahmen

Vor Pilotstart müssen namentlich benannte Rollen für Plattformbetrieb, SOC-Fachbetrieb, Konnektoren, Datenschutz und Release-Freigaben sowie Vertretungen dokumentiert sein. Das Produkt ist keine Zusage eines besetzten 24/7-SOC.

Vorgeschlagene, vom Betreiber zu bestätigende Pilotziele:

- Servicebetrieb kontinuierlich; betreuter Pilot montags bis freitags 08:00–18:00 Uhr Europe/Berlin. Unbeaufsichtigter A1-Betrieb außerhalb dieser Zeit nur bei bestätigtem Bereitschaftsweg; sonst neue autonome Läufe pausieren und diesen Zustand sichtbar anzeigen.
- Interne Verfügbarkeit des Dienstes 99,5 % pro Kalendermonat; Quellverfügbarkeit separat ausweisen, nicht im Produktstatus verstecken.
- Wiederanlaufziel RTO höchstens vier Stunden; RPO höchstens 15 Minuten für gesicherte Falldaten. Nicht wiederherstellbare Audit-/Evidenzlücken werden ausdrücklich markiert; keine Behauptung lückenloser Historie.
- Nach Neustart keine verlorenen persistent bestätigten Queue-Aufträge; Recovery- und Backup-Test vor Pilotfreigabe.
- Technische Healthchecks und Alarmierung für Authentifizierung, Datenlatenz, Queue-Alter, Fehlerrate, Speichernutzung und Budgetverbrauch.

Kosten werden pro Lauf, Fall, Playbook und Monat ausgewiesen: Modell, API soweit bepreist, Infrastruktur, Speicherung, Betrieb und menschlicher Review. Variabler Aufwand und anteilig zugeordnete Fixkosten bleiben getrennt. Wiederholungen und Fehlversuche zählen mit.

Pflichtkonfiguration vor A1: Kostenlimit je Fall und Monat, Warnschwelle bei 80 %, Stopp neuer Aufträge bei 100 %. Vor kostenpflichtigen Aufrufen wird der konservativ geschätzte Betrag reserviert; parallele Worker dürfen gemeinsam kein Limit überschreiten. Ist eine belastbare Begrenzung technisch nicht möglich, wird der betreffende Pfad nicht autonom aktiviert. Menschlich freigegebene Budgeterhöhungen sind separat protokolliert.

Wirtschaftlichkeitsbericht: Median und 95. Perzentil der Kosten und Bearbeitungszeiten je Falltyp; vollständige und unvollständige Untersuchungen separat. Günstige Teilberichte dürfen die Wirtschaftlichkeit nicht künstlich verbessern. Go/No-Go für den Rollout entscheidet der Product Owner gemeinsam mit Security Lead und Betrieb anhand gemessener Qualität, Gesamtkosten und betreibbarer Eskalationslast.
