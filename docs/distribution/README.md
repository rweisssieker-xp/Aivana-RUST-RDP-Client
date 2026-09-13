# Relayne · Distribution / Auslieferung / Distribution / Distribuzione

| Locale | Guide |
|---|---|
| en-US | [English (US)](en-US/guide.md) |
| de | [Deutsch](de/guide.md) |
| fr | [Français](fr/guide.md) |
| it | [Italiano](it/guide.md) |

Learning repair recommendations / Lernende Reparaturempfehlungen / Recommandations de réparation / Raccomandazioni di riparazione:
[en-US](en-US/learning.md) · [de](de/learning.md) · [fr](fr/learning.md) · [it](it/learning.md)

Measured outcomes / Nachweisbare Ergebnisse / Résultats mesurés / Risultati misurati:
[en-US](en-US/outcomes.md) · [de](de/outcomes.md) · [fr](fr/outcomes.md) · [it](it/outcomes.md)

## en-US
Development distribution only. The guide and release view are translated; full localization of specialist panels and earlier documents remains open. Packaging uses an explicit file allowlist. Publisher signing, operational acceptance, final privacy/terms, third-party notices, payment and licensing are not complete.

## de
Nur Entwicklungsauslieferung. Handbuch und Release-Ansicht sind übersetzt; die vollständige Übersetzung der Fachansichten und älteren Dokumente steht aus. Die Paketierung verwendet eine ausdrückliche Dateiliste. Herausgebersignatur, Praxisabnahme, endgültiger Datenschutz/Vertragsbedingungen, Drittanbieterhinweise, Zahlung und Lizenzierung sind nicht abgeschlossen.

## fr
Distribution de développement uniquement. Le guide et la vue de distribution sont traduits ; la traduction complète des vues spécialisées et des anciens documents reste ouverte. La création du paquet repose sur une liste explicite de fichiers. Signature, validation opérationnelle, confidentialité/conditions finales, notices tierces, paiement et licences restent incomplets.

## it
Solo distribuzione di sviluppo. Guida e vista di distribuzione sono tradotte; la traduzione completa delle viste specialistiche e dei documenti precedenti è ancora aperta. Il pacchetto usa un elenco esplicito di file. Firma, collaudo operativo, privacy/condizioni definitive, avvisi di terze parti, pagamenti e licenze non sono completi.

## CLI

## Verification / Prüfung / Vérification / Verifica — 2026-09-13

- en-US: 455 application tests + 16 team tests passed; 0 failed, 5 ignored. Both binaries built. Installer isolation/integrity tests and four native language views verified. No live host acceptance.
- de: 455 Anwendungstests + 16 Teamtests bestanden; 0 Fehler, 5 ignoriert. Beide Programme gebaut. Isolierte Installer-/Integritätstests und vier native Sprachansichten geprüft. Keine Live-Host-Abnahme.
- fr: 455 tests application + 16 tests équipe réussis ; 0 échec, 5 ignorés. Deux programmes compilés. Installation isolée, intégrité et quatre vues linguistiques natives vérifiées. Aucune validation sur hôte réel.
- it: 455 test applicazione + 16 test team superati; 0 errori, 5 ignorati. Entrambi i programmi compilati. Installazione isolata, integrità e quattro viste linguistiche native verificate. Nessun collaudo su host reale.

[JSON](verification.json)

## Commands / Befehle / Commandes / Comandi

```powershell
cargo build --offline --bins
.\scripts\distribution\Test-Distribution.ps1
.\scripts\distribution\New-DevPackage.ps1 -BuildDirectory .\target\debug -OutputDirectory C:\temp\relayne-dev-package
.\target\debug\relayne.exe --release-readiness --language en-US
.\target\debug\relayne.exe --language de
```
