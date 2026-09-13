# Ursachen durch Vergleichstests eingrenzen

Unter **Planen & Lernen → Ursachen durch Vergleichstests eingrenzen** gibt es einen neuen Diagnoseablauf. Er ersetzt das bloße Nebeneinander von Fehlermeldungen durch explizite Hypothesen, erwartete Prüfergebnisse, Widersprüche und eine konkrete nächste Prüfung.

## Erstes unterstütztes Modell

Für eine nicht erreichbare Windows-Anwendung werden vier Alternativen verglichen:

| Hypothese | Zugeordnete Prüfung | Nicht feststellbar bleibt zum Beispiel |
|---|---|---|
| Anwendungsdienst gestoppt | Dienst ist Running oder Stopped | Fehlende Rechte, fehlender Dienst oder Übergangszustand |
| DNS-Name nicht auflösbar | Name der konfigurierten HTTPS-Anwendung auflösbar | Zeitüberschreitung oder sonstiger Resolverfehler |
| TLS-Verbindung gestört | TLS-Handshake mit normaler Zertifikatsprüfung | Nicht erreichbarer Server oder Zeitüberschreitung |
| HTTP-Abhängigkeit meldet Fehler | 2xx passt, 5xx widerspricht der Erwartung | Umleitung, 4xx, Authentifizierungsbedarf oder Transportfehler |

Die Modellannahme ist **ein dominanter Fehler**: Jede Alternative erwartet, dass ihre eigene Prüfung fehlschlägt und die anderen drei erfolgreich sind. Das ist eine begrenzte Arbeitshypothese, keine Aussage über alle möglichen Ausfallursachen. Mehrere Fehler oder vier erfolgreiche Prüfungen führen deshalb ausdrücklich zu einer Modelllücke. Ein erreichbarer HTTP-Endpunkt mit 2xx ist kein vollständiger fachlicher Anwendungstest.

Die nächste Prüfung wird danach gewählt, wie viele noch mögliche Hypothesenpaare sie unterscheidet. Bei Gleichstand gilt Dienst → DNS → TLS → Abhängigkeit. Auch wenn früh nur noch eine Hypothese übrig bleibt, müssen die übrigen Modellbedingungen geprüft werden. Alle vier passenden Ergebnisse sind weiterhin **kein Nachweis der ursprünglichen Ursache** und keine Reparaturfreigabe.

## Dev-Simulation

Die Oberfläche startet im Modus **Dev-Simulation (ohne Verbindung)**. Unter „Neuen Diagnosefall vorbereiten“ ein Szenario auswählen und die Fallvorschau speichern. Anschließend die vorgeschlagene Prüfung einzeln lokal simulieren. Verfügbar sind vier einzelne Fehler, mehrere Fehler, ausschließlich gesunde Prüfungen und nicht verfügbare Messwerte.

Das Szenario ist an den gespeicherten Fall gebunden. Zum Wechsel ein neues Szenario als neuen Fall anlegen. Jeder Beleg und jeder exportierte Bericht bleibt als Simulation gekennzeichnet. Es werden keine Hostverbindung, VM-Aktion oder Dienständerung ausgelöst. Die Simulation kann nicht als realer Diagnosefall fortgesetzt oder als Recovery-Beleg übernommen werden.

## Spätere lesende Prüfung

Der Adapter ist implementiert, wurde in dieser Entwicklung aber ausschließlich mit Ersatzimplementierungen und lokalem HTTP-Server geprüft. Für einen späteren echten Lauf wird ein direktes Windows-Profil benötigt. Der feste WinRM-Auftrag nutzt die aktuelle Windows-Identität, nicht gespeicherte RDP-Passwörter. Alle Prüfungen laufen aus Sicht dieses Windows-Rechners; Ergebnisse gelten nicht automatisch für andere Clients.

Der Fall bindet Profilidentität, Dienst, HTTPS-Anwendung und HTTP-Abhängigkeitsadresse. Erst die Vorschau eines konkreten Leseauftrags und dessen separate Freigabe stellen ihn in die bestehende Job-Warteschlange. Ein gewechseltes Profil oder eine abgelaufene Freigabe verhindert den Start eines noch wartenden Auftrags. Der Adapter enthält keine Reparatur-, VM- oder generierten Shell-Aktionen. HTTP-Weiterleitungen, Proxy- und automatische Credential-Nutzung sind deaktiviert; TLS-Prüfung wird nicht umgangen. Netzwerkprüfungen sind zeitlich begrenzt.

## Was-wäre-wenn-Vorschau für Prüfungen

**Was würde diese Prüfung klären?** zeigt für die ausgewählte verfügbare Prüfung drei mögliche Verläufe: erfüllt, nicht erfüllt und nicht feststellbar. Pro Verlauf werden die verbleibenden Hypothesen, die Zahl auswertbarer Prüfungen, die Modellbewertung und die danach empfohlene Prüfung angezeigt.

Die Vorschau berücksichtigt dieselben Frische- und Wiederholungsgrenzen wie die Diagnose. Ein einzelner passender Befund bleibt unvollständig; ein widersprüchlicher Befund kann alle Modellhypothesen ausschließen. Ein unbekanntes Ergebnis kann nach dem dritten Versuch zur nächsten verfügbaren Prüfung führen.

Dies sind ausdrücklich Annahmen ohne Wahrscheinlichkeitsangaben. Die Berechnung verwendet kurzlebige Fallkopien im Speicher; sie verändert den Originalfall nicht, speichert keine Beobachtung und erzeugt keinen ausführbaren Job. Vorschauergebnisse können nicht als Messwerte übernommen werden. Die Funktion benötigt keine Verbindung und keinen Modellaufruf.

## Reproduzierbarer Dev-Szenariovergleich

In der Diagnoseansicht führt **Dev-Szenariovergleich · sieben feste Fälle → Alle sieben Simulationen vergleichen** die sieben eingebauten Szenarien im Speicher aus. Jeder Lauf zeigt Erwartung, tatsächliche Einordnung, Prüfreihenfolge, Messwert und Anzahl der durch die jeweilige Prüfung unterscheidbaren Hypothesenpaare.

Die vier einzelnen Fehler müssen erst nach allen vier Prüfungen zu ihrer Modellhypothese passen. Der Mehrfachfehler muss einen Widerspruch und das gesunde Szenario eine Modelllücke ergeben. Fehlende Messwerte bleiben nach drei Versuchen je Prüfung unzureichend. Ein Lauf umfasst höchstens zwölf Prüfungen je Szenario und verwendet einen festen Zeitpunkt; dieselben Fixtures erzeugen dieselben Ergebnisse und Prüfreihenfolgen.

**Simulationsvergleich als JSON kopieren** exportiert ausschließlich die festen Szenarioergebnisse, Modellversion und Laufzeitpunkt. Der Vergleich verwendet weder gespeicherte Fälle noch ausgewählte Profile, persistiert keine Messwerte und stellt keine Jobs ein. Der Bericht ist ausdrücklich als Simulation und ohne Kausalitäts-/Reparaturnachweis gekennzeichnet. Er prüft das Modellverhalten, nicht KI-Qualität, reale Wiederherstellung oder Zeitersparnis gegenüber manueller Arbeit.

## KI-Vorschläge ohne automatische Modellaufrufe

„KI-Prüfauftrag kopieren“ erzeugt lokal einen strukturierten Auftrag aus Falltext, Modell und aktuellen Prüfergebnissen. Profilfelder und konfigurierte URLs werden nicht automatisch in diesen Auftrag aufgenommen; selbst eingegebener Falltext kann sie natürlich enthalten. Es gibt in diesem Ablauf keinen automatischen API-Aufruf.

Ein eingefügter JSON-Vorschlag muss genau `binding`, `as_of`, `probe` und `rationale` enthalten. Zugelassen sind nur die vier bekannten Prüfungen. Der Vorschlag muss zum unveränderten Fallzustand gehören, höchstens zwei Minuten alt sein und eine noch verfügbare Prüfung wählen. Nach sichtbarer Prüfung kann ausschließlich die Prüfauswahl übernommen werden. KI-Ausgaben können keine Messwerte, Befehle oder Zieländerungen hinzufügen. Eine anschließende echte Leseprüfung benötigt weiterhin ihre separate Freigabe.

## Belege, Ablauf und Speicherung

Nur Beobachtungen der letzten fünf Minuten beeinflussen den aktuellen Vergleich. Veraltete oder zukünftige Ergebnisse gelten nicht als aktuelle Befunde. Neuere Beobachtungen haben Vorrang vor verspätet eintreffenden älteren Beobachtungen. Eine nicht feststellbare neue Prüfung erhält keinen stillen Rückgriff auf einen alten Erfolgswert.

Jeder Auftrag hat eine eigene ID und ist an Fallkonfiguration und Modus gebunden. Falsche Bindung, doppelte Antworten, abgeschnittene Ausgaben oder verspätete Resultate liefern keinen positiven Nachweis. Pro Prüfung sind innerhalb des Zeitfensters höchstens drei Versuche möglich. Danach bleiben fehlende Ergebnisse ausdrücklich offen.

Fälle werden lokal unter `relayne-diagnostics.dpapi` mit CurrentUser-DPAPI gespeichert. Der Speicher ist auf 64 Fälle, 64 Beobachtungen pro Fall und 4 MiB begrenzt. Parallele veraltete Schreibzugriffe werden abgewiesen; unlesbarer Speicher sperrt weitere Übernahmen bis zum erfolgreichen Neuladen. Berichte werden ausschließlich durch die sichtbare Kopieraktion exportiert und sind als Diagnosemodell-Bericht ohne Kausalitäts- oder Reparaturbeweis gekennzeichnet.

## Verifikation am 12.09.2026

`cargo test --offline -- --test-threads=1`: 443 Anwendungstests und 16 Teamtests bestanden, 0 Fehler, 5 bestehende Tests ignoriert, 0 ausgefiltert. `cargo build --offline --bins` erfolgreich; bestehende Dead-Code-Warnungen bleiben bestehen. Die native Oberfläche wurde anhand der gekennzeichneten Dev-Simulation visuell geprüft (Screenshot: `docs/gui-concepts/relayne-differential-diagnosis.png`).

Ausschließlich Entwicklungsprüfungen: Simulationen, Testdoubles und lokales Loopback-HTTP. Keine Verbindung zu gespeicherten RDP-Hosts, keine Live-Hyper-V-Abnahme und keine externen Modellaufrufe.

## Dev-Szenariovergleich: Verifikation am 12.09.2026

`cargo test --offline diagnostic -- --test-threads=1`: **24 Tests bestanden, 0 Fehler**; gezielter Diagnose-Regressionslauf, 428 Anwendungstests und 16 Teamtests ausgefiltert. Vier neue Tests prüfen den Szenariovergleich, unvollständige Evidenz und die Oberfläche ohne Fall-/Jobänderung. Der zuvor dokumentierte vollständige Gesamtlauf bleibt ein früherer Stand.

`cargo build --offline --bin relayne` erfolgreich (51 bestehende Warnungen). Formatprüfung und `git diff --check` erfolgreich. Native Ansicht visuell geprüft: [Dev-Szenariovergleich](gui-concepts/relayne-diagnostic-comparison.png), sieben von sieben Simulationserwartungen erfüllt. Ausschließlich Dev; keine Live-Hosts oder externen Modellaufrufe.

## Prüfungsvorschau: Verifikation am 12.09.2026

`cargo test --offline diagnostic -- --test-threads=1`: **28 Tests bestanden, 0 Fehler**; gezielter Diagnose-Regressionslauf, 428 Anwendungstests und 16 Teamtests ausgefiltert. Vier neue Tests decken drei hypothetische Ergebnisse, unveränderte Originalfälle, Widersprüche, ausgeschöpfte Versuche, abgelaufene Evidenz und Rendering bei 640/1440 Pixeln ab.

`cargo build --offline --bin relayne`, Formatprüfung und `git diff --check` erfolgreich; 51 bestehende Build-Warnungen. Die native Ansicht wurde aufgenommen und der sichtbare Einstieg in die Vorschau geprüft: [Prüfungsvorschau](gui-concepts/relayne-diagnostic-foresight.png). Der gesamte Vorschauinhalt ist in der scrollbaren Diagnoseansicht erreichbar. Ausschließlich lokale Entwicklungsprüfungen, keine Live-Hosts und keine externen Modellaufrufe. Kein erneuter vollständiger Gesamttest für diese begrenzte Erweiterung.
