# Aivana RDP – geprüfter Venture Case

Stand: 11.09.2026. Entscheidung: **VALIDIEREN**. Noch keine Freigabe für Skalierung oder ein größeres Produktbudget.

## Ergebnis und Positionierung

Automatisch aus dem Repository und dem Gespräch abgeleitetes Ziel: die kommerzielle Chance einer nativen RDP-Arbeitsumgebung für DACH-IT-Administratoren und kleine MSPs bewerten. Diese Zielgruppe ist eine Hypothese, keine Kundenerkenntnis.

Positionierungshypothese: **Von der unterbrochenen RDP-Sitzung zur nachvollziehbaren Wiederherstellung und fertigen Übergabe – in einem Arbeitsplatz.** Der Einstieg ist ein konkreter Incident-Workflow. Verbindungsverwaltung, Rust und ein KI-Chat begründen alleine keinen belastbaren Kaufvorteil.

Empfohlener erster Anwendungsfall: Verbindungsfehler aufnehmen, DNS/TCP/Zertifikat/Zugang prüfen, Befunde zusammenfassen, eine sichere nächste Aktion vorschlagen, nach Freigabe ausführen, Ergebnis verifizieren und einen bereinigten Ticketentwurf exportieren. Keine behauptete universelle autonome Fehlerbehebung.

## Evidenz und Grenzen

- Repository-Evidenz: README.md beschreibt native Rust/egui-Sitzungen, Profile, Diagnostik, Evidenzexport, Freigaben und Runbooks. Dies belegt dokumentierten Funktionsumfang, nicht allgemeine Einsatzreife.
- Ein vorhandener lokaler Workflow-Bericht dokumentiert frühere Tests und einen erfolgreichen Live-RDP-Pfad. In diesem Venture-Lauf wurden keine neuen Anwendungstests ausgeführt. Daraus folgt keine breite Server-/Gateway-Kompatibilität.
- Externe Evidenz: vier importierte Herstellerquellen, siehe venture-sources.json. Sie belegen Angebote, nicht Aivanas Nachfrage oder Überlegenheit.
- Keine Kundeninterviews, Nutzungsdaten, Käufe, gemessenen Zeitgewinne oder validierten Kosten vorhanden.
- Namen Orbit und Orvexa sind nicht freigegeben. Das Naming wird getrennt fortgeführt.

ForgeMind wurde tatsächlich zweimal ausgeführt. Der erste Lauf klassifizierte das Produkt aufgrund des Worts „order“ fälschlich als Commerce-Plattform. forgemind.config.json korrigiert die Kategorie auf enterprise-operations. Die automatisch generierten Finanzwerte bleiben Kategorienvorgaben; die CLI kann konfigurierte Kategorien und daraus abgeleitete Defaults als „observed“ kennzeichnen. Diese Kennzeichnung ist **kein Nachweis beobachteter Geschäftszahlen**. Die generischen Rohberichte venture-case.md und financial-model.md sind keine Entscheidungsgrundlage. Maßgeblich sind dieser Review und das separat gerechnete Modell venture-economics.json. Die CLI-Empfehlung bleibt research-first.

## Kundenproblem und Käufer

Hypothese: Supportteams mit 3–10 aktiven Administratoren verlieren regelmäßig Zeit durch Wechsel zwischen Remote-Sitzung, Diagnosewerkzeugen und Ticketdokumentation. Nutzer und Champion sind erfahrene Administratoren; wirtschaftlicher Käufer ist die MSP-Geschäftsführung oder IT-Leitung. Sicherheits-/Datenschutzverantwortliche können die Nutzung externer KI begrenzen.

Zunächst Windows-/RDP-lastige Teams mit wiederkehrenden Supportfällen auswählen. Teams, die zuerst einen umfassenden gemeinsamen Tresor, SSH/VNC-Parität oder eine vollständige PAM-Lösung verlangen, passen voraussichtlich schlechter zum ersten Pilot. Das muss im Gespräch bestätigt werden.

## Wettbewerb

| Alternative | Belegtes Angebot | Konsequenz für Aivana |
| --- | --- | --- |
| Devolutions RDM | Zentrale Remote-Verbindungen, Credential-/PAM-Integration und KI-Unterstützung in Devolutions Server | „Mit KI“ ist kein nachgewiesener USP; einen konkreten Incident gegen den bestehenden Ablauf messen. |
| Royal TS | RDP, VNC, SSH, Zugangsdaten und Aufgabenautomatisierung | Protokollbreite und Routineautomation sind bereits vorhanden. |
| mRemoteNG | Open-Source-Verbindungsmanager unter Windows mit mehreren Protokollen | Hoher Preisdruck auf reine Sitzungsverwaltung. |
| Bestehender RDP-Client plus Diagnosewerkzeuge und Ticket | Zu prüfende Kundenalternative; hier keine gemessene Baseline | Den gesamten Ablauf einschließlich Dokumentationszeit vergleichen. |

Quellen, abgerufen 11.09.2026: [Devolutions](https://devolutions.net/remote-desktop-manager/), [Royal TS](https://www.royalapps.com/ts/win/features), [Royal-Lizenzänderungen](https://blog.royalapps.com/blog/licensing-and-versioning), [mRemoteNG](https://mremoteng.org/).

Die Royal-Featureseite zeigt 49 EUR, während eine separate Mitteilung Änderungen für v26.x beschreibt. Deshalb wird hier kein verbindlicher aktueller Vergleichspreis behauptet. Devolutions wurde nicht mit einem verifizierten aktuellen Angebot bepreist. Keine Schlussfolgerung, dass Mitbewerber den vorgeschlagenen Workflow nicht unterstützen.

## Marktchance als qualitative Hypothese

| Faktor | Vorläufige Bewertung | Zu erhebender Beleg |
| --- | --- | --- |
| Problemschwere | Potenziell hoch bei Störungen | Konkrete letzte Fälle und tatsächliche Kosten |
| Häufigkeit | Unbekannt | Vier Wochen Fälle pro Administrator |
| Erreichbarkeit | Unbekannt; DACH-MSPs als Startsegment | Benannte qualifizierte Firmen und Gesprächsquote |
| Differenzierung | Plausibel im vollständigen Incident-Ablauf | Vergleichstest mit bisherigem Werkzeug |
| Machbarkeit | Technische Basis dokumentiert, Einsatzbreite offen | Pilot-Kompatibilität und sichere Aktionsausführung |
| Nachfrageevidenz | Bisher nicht vorhanden | Wiederholte Nutzung und bezahlte Fortsetzung |

Kein Prozentwert für Markterfolg, kein behaupteter TAM/SAM. Ein gewichteter Zahlenwert würde hier Genauigkeit vortäuschen.

## Preis- und Werttest

Vom Nutzer gewählter Startpreis: **9,99 EUR pro Nutzer und Monat**. Für diese B2B-Kalkulation vorläufig als netto behandelt; die Steuerdarstellung wurde nicht vom Nutzer festgelegt. Kundeneigener KI-Schlüssel und separate Providerkosten bleiben Modellannahmen. Der Preis ist eine Produktentscheidung, keine validierte Zahlungsbereitschaft. Teamfunktionen nur anbieten, soweit tatsächlich verfügbar.

Bei angenommenen 60 EUR internem Stundenwert entsprechen 9,99 EUR rund zehn Minuten Zeitersparnis pro Monat; dies ist reine Wertrechnung. Für einen deutlichen Wechselanreiz im Pilot mindestens zwei nachgewiesene Stunden pro Administrator und Monat anstreben. Nur vermiedene, nicht anschließend durch Prüfung oder Korrektur wieder entstandene Arbeit zählen.

## Wirtschaftlichkeit: explizite Beispielszenarien

Startpreis, ausschließlicher Webverkauf und 0 EUR laufende Fixkosten stammen vom Nutzer. Alle übrigen Eingaben sind Analystenannahmen, keine Marktbeobachtungen. Einheit Kunde = zahlende Organisation, nicht Sitz. EUR netto angenommen. Preis ist je Sitz. Erreichbare Firmen sind nur ein angenommener Akquise-Pool, keine Marktgröße oder existierende Kontaktliste. Akquise, einmalige Entwicklung und variable Kosten bleiben unbestätigte Stressannahmen; laufende Fixkosten wurden auf Nutzervorgabe auf null gesetzt.

| Eingabe/Ergebnis | Konservativ | Basis | Positiv |
| --- | ---: | ---: | ---: |
| Erreichbare Firmen, hypothetisch | 30 | 100 | 250 |
| Neue Organisationen pro Monat | 1 | 3 | 8 |
| Sitze je Organisation | 3 | 5 | 10 |
| EUR pro Sitz/Monat | 9,99 | 9,99 | 9,99 |
| Monatlicher Logo-Churn | 4 % | 2 % | 1 % |
| Rohertragsmarge | 70 % | 80 % | 85 % |
| Akquisekosten je Organisation | 500 | 600 | 600 |
| Zusätzlicher Entwicklungsaufwand | 15.000 | 25.000 | 25.000 |
| Laufende Fixkosten/Monat | 0 | 0 | 0 |
| Umsatz im ersten Jahr | 2.027 | 10.873 | 60.108 |
| Rohertrag im ersten Jahr | 1.419 | 8.698 | 51.092 |
| Akquisekosten im ersten Jahr | 6.000 | 21.600 | 57.600 |
| Ergebnis nach obigen Kosten, 12 Monate | **−19.581** | **−37.902** | **−31.508** |
| Zahlende Firmen am Ende, Erwartungswert | 9,7 | 32,3 | 90,9 |
| Fixkostendeckung, ohne Akquise/Entwicklung | Keine Fixkosten | Keine Fixkosten | Keine Fixkosten |
| Deckung laufender Akquise, ohne Entwicklung | 24 Firmen | 46 Firmen | 57 Firmen |
| CAC-Amortisation, vereinfacht | 23,8 Monate | 15,0 Monate | 7,1 Monate |

Berechnung: Kunden_m = Kunden_(m−1) × (1−Churn) + Neukunden_m. Umsatz = Summe der monatlichen Kunden × Sitze × Preis. Neue Kunden zahlen vereinfachend ab Monatsbeginn. Ergebnis = Umsatz × Marge − Akquisekosten − 12 × Fixkosten − zusätzlicher Entwicklungsaufwand. Historische Entwicklungskosten sind nicht enthalten. Keine Steuern, Finanzierung, Forderungsausfälle oder jährliche Vorauszahlung. Variable Support-/Abwicklungskosten sind in der Marge angenommen, feste Arbeit in den Fixkosten; tatsächliche Gründergehälter und Vollkosten müssen ergänzt werden. KI-Kosten trägt in diesem Modell der Kunde separat. CAC muss auch Vertriebszeit enthalten. Der angenommene Akquise-Pool begrenzt den Absatz nicht automatisch und rechtfertigt die Neukundenrate nicht.

Der als „Positiv“ bezeichnete Fall kombiniert größere Teams und schnellere Akquise beim selben Preis. Die verbleibenden negativen Ergebnisse entstehen aus den unbestätigten Annahmen zu einmaliger Entwicklung und Kundengewinnung. Sie sind keine belegten Kosten des Webvertriebs und keine Verlustprognose.

Sensitivität des Basisfalls: Preis ±20 % verändert das Jahresergebnis um ungefähr ±1.740 EUR; CAC +50 % verschlechtert es um 10.800 EUR; zusätzliche Fixkosten von 1.000 EUR monatlich um 12.000 EUR. Verdoppelte Neukundenzahl verschlechtert das Ergebnis im ersten Jahr um rund 12.902 EUR, weil Akquisekosten sofort anfallen. Für 9,99 EUR ist deshalb ein günstiger Vertrieb mit eigenständigem Kauf und geringer Betreuung zu testen. Bei fünf Sitzen und 80 % Marge beträgt der monatliche Deckungsbeitrag pro Organisation 39,96 EUR; für sechs Monate einfache CAC-Amortisation dürften Akquisekosten höchstens 239,76 EUR betragen (ohne Churn). Bei 600 EUR CAC beträgt die Amortisation rund 15 Monate. Bei 0 EUR laufenden Fixkosten entfällt eine Mindestnutzerzahl zur Fixkostendeckung. Jeder zahlende Nutzer liefert bei positiver Marge einen Beitrag; Akquise und einmalige Entwicklung sind davon separat zu decken.

Reproduzierbar mit `node docs/forgemind/venture-economics.mjs`; Monatswerte und Sensitivitäten stehen in venture-economics.json.

## Vertrieb ausschließlich über das Web

Nutzervorgabe: 9,99 EUR pro Nutzer und Monat, Verkauf ausschließlich über die Website, keine laufenden Fixkosten. Vorgesehener Ablauf: Produktseite → Download/Test → Online-Kauf → automatische Lizenzaktivierung und Kontoverwaltung. Dieser Ablauf ist ein Konzept, keine bereits implementierte Verkaufsstrecke.

Einzelne Nutzer können eigenständig kaufen. Die bisherigen drei bis zehn Sitze pro Organisation sind Szenarioannahmen und müssen am tatsächlichen Online-Kauf geprüft werden. Kundenforschung ist optional und keine Verkaufsvoraussetzung. Die bisherigen CAC-Werte von 500–600 EUR pro Organisation sind keine belegten Webmarketingkosten; sie bleiben lediglich ein Stresstest. Nicht automatisch unterstellen, dass Webverkauf bezahlte Werbung erfordert oder kostenlos neue Kunden gewinnt.

Bei angenommenen 80 % Marge bleiben 7,992 EUR Deckungsbeitrag pro Nutzer und Monat. Für drei Monate einfache Amortisation wären höchstens 23,976 EUR Akquisekosten pro Nutzer tragbar, für sechs Monate 47,952 EUR, jeweils ohne Churn. Gemessen werden Besucher → Download → erste erfolgreiche Sitzung → Kauf, Zahlungen, Kündigungen und variabler Supportaufwand.

Reine monatliche Umsatzrechnung bei angenommenem Nettopreis: 100 Nutzer = 999 EUR; 500 = 4.995 EUR; 1.000 = 9.990 EUR. Das ist weder Gewinn noch eine Absatzprognose. Providerkosten separat zu behandeln bleibt vorläufige Modellannahme.
## Vierwöchiger Validierungsplan

1. Woche 1: Acht qualifizierte Gespräche vorbereiten, je vier MSPs und interne IT-Teams. Den letzten echten Incident rekonstruieren: Häufigkeit, Werkzeuge, Diagnosezeit, Dokumentation, Zuständigkeit, KI-Freigaben. Noch keine Nachrichten versendet.
2. Woche 2: Drei freiwillige Pilotorganisationen auswählen. Je Organisation mindestens fünf vergleichbare Testfälle mit dem bisherigen Verfahren und mit Aivana bearbeiten; Reihenfolge variieren. Gesamtdauer, Korrekturen, Ergebnisqualität und manuelle Eingriffe erfassen.
3. Woche 3: Wiederholte Nutzung prüfen. Tatsächliche Fälle, Supportminuten und Providerkosten dokumentieren. Nur genehmigte Testumgebungen verwenden; sensible Bildschirminhalte vor externer Verarbeitung klären.
4. Woche 4: Den eigenständigen Online-Kauf zu 9,99 EUR je Nutzer und Monat testen, sobald eine autorisierte Verkaufsstrecke bereitsteht. Ein Wunsch oder positives Interview zählt nicht als Kauf. Vorläufiges Signalziel: mindestens zwei von drei Piloten akzeptieren eine konkrete bezahlte Fortsetzung.

Vorläufige Erfolgsgrenzen: mindestens 30 % geringere mediane Gesamtdauer bei gleichwertiger Ergebnisqualität, nachvollziehbare Freigaben, keine unfreigegebene Aktion und regelmäßige Nutzung über zwei Wochen. Kleine Stichprobe liefert nur Richtung, keinen allgemeinen Produktivitätsnachweis.

Harte Stopps: keine materielle wiederkehrende Problembestätigung; keine messbare Verbesserung; unfreigegebene oder falsch adressierte Remote-Aktion; nicht beherrschbarer Datenabfluss; keinerlei bezahlte Fortsetzung; Supportkosten verbrauchen den möglichen Deckungsbeitrag. Bei technischen Sicherheitsfehlern Pilot pausieren; bei fehlendem Bedarf Segment/Workflow neu wählen. Keine automatische Investition allein aufgrund positiver Szenariotabellen.

## Nächste konkrete Aktion

Eine Liste von acht potenziellen Gesprächspartnern erstellen und die fünf häufigsten Incident-Typen aus vorhandenen autorisierten Supportdaten auswählen. Diese Informationen fehlen; sie werden nicht erfunden. Bis dahin ist das Ergebnis ein vorbereiteter Venture Case. Es wurden keine Kunden kontaktiert, keine Ausgaben ausgelöst und keine Anwendungscodeänderungen für diese Untersuchung vorgenommen.

