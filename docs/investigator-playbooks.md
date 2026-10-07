# Zusätzliche evidenzbasierte Playbooks

Die Weboberfläche bietet unter **Playbooks** denselben Katalog und dieselben Aktionen wie MCP: `playbooks.catalog` und `playbooks.run`. Ein Lauf erhält `case_id` und `playbook_id`; optional schützt `expected_version` vor Änderungen seit dem Öffnen des Falls. Er untersucht bereits im Fall gespeicherte Belege, ohne zusätzliche externe Quellen oder Modelle aufzurufen.

| ID | Untersuchung und Grenzen |
|---|---|
| `login_password_spray` | Fehlanmeldungen über mehrere Konten, getrennte erfolgreiche und blockierte Anmeldungen sowie alternative legitime Aktivität. Ein Login-Erfolg beweist keinen Ressourcenzugriff. |
| `token_misuse` | Derselbe Token bzw. dieselbe Sitzung und Anwendung in unterschiedlichen Kontexten innerhalb eines kurzen Zeitfensters. Kontextwechsel können legitim sein; das Ergebnis bleibt ein prüfbarer Verdacht. |
| `endpoint_process_chain` | Bekannte auffällige Eltern-/Kindkombinationen, etwa Office → Script-Launcher, mit separat erfassten Blockierungen. Kein Ersatz für vollständige Prozessforensik. |
| `cloud_exfiltration` | Erfolgreiche Objektzugriffe und ausgehender Verkehr werden anhand Identität, Ziel und Zeit korreliert. Blockierungen bleiben Gegenbelege. Eine Korrelation allein beweist keinen unbefugten Abfluss. |
| `adcs_esc1` | Aktuelle, zusammengehörige Vorlage, Enrollment-Berechtigungen und CA-Einstellungen. Unter anderem müssen die Zahl erforderlicher autorisierter Signaturen und die Genehmigungseinstellungen bekannt sein. Fehlende Voraussetzungen erzeugen Datenanforderungen. |

Der Katalog nennt die aktuellen normalisierten Feldverträge. Für Token-, Endpoint- und AD-CS-Daten erfolgt die Übernahme derzeit über `evidence.ingest`; native Live-Collector für diese Quellen sind nicht enthalten. Storage-/Netzwerkexporte können über die [geprüften Provider-Importe](investigator-integrations.md) eingelesen werden. Die Wahl eines Playbooks bestätigt weder die Herkunft manueller Belege noch eine Live-Berechtigung.

Beispiel:

```json
{"action":"playbooks.run","payload":{"case_id":"<Fall-ID>","playbook_id":"adcs_esc1","expected_version":7}}
```

Nur aktuelle, nicht abgelaufene Belege innerhalb des Falls und ohne zukünftigen Ereigniszeitpunkt dürfen einen Befund stützen. Quellenabdeckung, Gegenbelege und fehlende Felder bleiben sichtbar. Ergebnisse erhalten Playbook-Version, Belegreferenzen und Zeit; sie werden im Fall, Lagebild und Export gespeichert. Neue materielle Ergebnisse erfordern erneute menschliche Review. Identische Läufe erzeugen keine wiederholten Ergebnismeldungen. Keine Routine schließt einen Fall oder führt eine technische Reaktion aus.
