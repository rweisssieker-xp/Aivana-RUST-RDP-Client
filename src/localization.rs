//! Explicit locale selection; no network translation and no changes to user data.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Locale {
    #[default]
    #[serde(rename = "en-US")]
    EnUs,
    #[serde(rename = "de")]
    De,
    #[serde(rename = "fr")]
    Fr,
    #[serde(rename = "it")]
    It,
}
impl Locale {
    pub const ALL: [Self; 4] = [Self::EnUs, Self::De, Self::Fr, Self::It];
    pub fn tag(self) -> &'static str {
        match self {
            Self::EnUs => "en-US",
            Self::De => "de",
            Self::Fr => "fr",
            Self::It => "it",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::EnUs => "English (US)",
            Self::De => "Deutsch",
            Self::Fr => "Français",
            Self::It => "Italiano",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "en-us" | "us-en" => Some(Self::EnUs),
            "de" => Some(Self::De),
            "fr" => Some(Self::Fr),
            "it" => Some(Self::It),
            _ => None,
        }
    }
}
pub fn tr(locale: Locale, source: &str) -> &str {
    if let Some(row) = HELPER_ACCEPTANCE_CATALOG
        .iter()
        .find(|row| row[0] == source)
    {
        let index = match locale {
            Locale::De => 1,
            Locale::EnUs => 0,
            Locale::Fr => 2,
            Locale::It => 3,
        };
        return row[index];
    }
    let index = match locale {
        Locale::De => 0,
        Locale::EnUs => 1,
        Locale::Fr => 2,
        Locale::It => 3,
    };
    CATALOG
        .iter()
        .find(|row| row[0] == source)
        .map(|row| row[index])
        .unwrap_or(source)
}
const CATALOG: &[[&str; 4]] = &[
    ["Verifiziertes Betriebswissen", "Verified operating knowledge", "Connaissances opérationnelles vérifiées", "Conoscenza operativa verificata"],
    ["Berücksichtigt werden nur Produktionsbelege aus Relaynes geschütztem Journal und Belegspeicher.", "Only production evidence verified against Relayne's protected journal and receipt store can qualify.", "Seules les preuves de production vérifiées dans le journal et le registre protégés de Relayne sont prises en compte.", "Sono considerate solo le prove di produzione verificate nel journal e nell'archivio protetti di Relayne."],
    ["Verifizierte Produktionsbelege qualifizieren", "Qualify verified production evidence", "Qualifier les preuves de production vérifiées", "Qualifica le prove di produzione verificate"],
    ["Für diesen Fall sind keine Lernkandidaten gespeichert.", "No lesson candidates are recorded for this case.", "Aucun candidat d'apprentissage n'est enregistré pour ce cas.", "Nessun candidato di apprendimento è registrato per questo caso."],
    ["Lernregel freigeben", "Approve lesson", "Approuver la règle", "Approva la regola"],
    ["Lernregel ablehnen", "Reject lesson", "Rejeter la règle", "Rifiuta la regola"],
    ["Mit aktuellen Belegen erneut prüfen", "Revalidate against current evidence", "Revalider avec les preuves actuelles", "Rivalida con le prove attuali"],
    ["JSON-Bericht zum Betriebswissen kopieren", "Copy JSON knowledge report", "Copier le rapport JSON de connaissances", "Copia il rapporto JSON delle conoscenze"],
    ["Markdown-Bericht zum Betriebswissen kopieren", "Copy Markdown knowledge report", "Copier le rapport Markdown de connaissances", "Copia il rapporto Markdown delle conoscenze"],
    ["Aktuell passende Empfehlungen", "Evidence-matched recommendations", "Recommandations correspondant aux preuves", "Raccomandazioni corrispondenti alle prove"],
    ["Die aktuelle Produktionsbeleglage passt zu dieser freigegebenen Lernregel.", "Current verified evidence matches this reviewed lesson.", "Les preuves de production vérifiées correspondent à cette règle approuvée.", "Le prove di produzione verificate corrispondono a questa regola approvata."],
    ["Kandidat", "Candidate", "Candidat", "Candidato"],
    ["Verifiziert", "Verified", "Vérifié", "Verificato"],
    ["Abgelehnt", "Rejected", "Rejeté", "Rifiutato"],
    ["Veraltet", "Stale", "Obsolète", "Obsoleto"],
    ["Widerrufen", "Invalidated", "Invalidé", "Revocato"],
    ["Wissensspeicher nicht verfügbar", "Knowledge store unavailable", "Registre de connaissances indisponible", "Archivio delle conoscenze non disponibile"],
    ["Wissensspeicher konnte nicht geprüft werden", "Knowledge store could not be validated", "Le registre de connaissances n'a pas pu être validé", "Impossibile convalidare l'archivio delle conoscenze"],
    ["Kein neuer Lernkandidat qualifiziert; passende Belege sind möglicherweise bereits gespeichert.", "No new lesson qualified; matching evidence may already be recorded.", "Aucun nouveau candidat qualifié ; les preuves correspondantes sont peut-être déjà enregistrées.", "Nessun nuovo candidato qualificato; le prove corrispondenti potrebbero essere già registrate."],
    ["beleggebundene Lernkandidaten gespeichert", "evidence-backed lesson candidates saved", "candidats fondés sur des preuves enregistrés", "candidati basati su prove salvati"],
    ["Qualifizierung nicht verfügbar", "Lesson qualification unavailable", "Qualification de règle indisponible", "Qualifica della regola non disponibile"],
    ["Revision", "Revision", "Révision", "Revisione"],
    ["Belegreferenzen", "evidence references", "références de preuve", "riferimenti alle prove"],
    ["Fingerabdruck", "Fingerprint", "Empreinte", "Impronta"],
    ["Gültig bis", "Valid through", "Valide jusqu'au", "Valido fino al"],
    ["Lernregel freigegeben und gespeichert.", "Lesson approved and saved.", "Règle approuvée et enregistrée.", "Regola approvata e salvata."],
    ["Lernregel abgelehnt und gespeichert.", "Lesson rejected and saved.", "Règle rejetée et enregistrée.", "Regola rifiutata e salvata."],
    ["Prüfung wurde nicht gespeichert", "Review was not saved", "La vérification n'a pas été enregistrée", "La revisione non è stata salvata"],
    ["Lernregel mit aktuellen Produktionsbelegen erneut geprüft.", "Lesson revalidated against current production evidence.", "Règle revalidée avec les preuves de production actuelles.", "Regola rivalidata con le prove di produzione attuali."],
    ["Erneute Prüfung wurde nicht gespeichert", "Revalidation was not saved", "La revalidation n'a pas été enregistrée", "La rivalidazione non è stata salvata"],
    ["Aktuelle Belege können nicht geprüft werden", "Current evidence cannot be verified", "Les preuves actuelles ne peuvent pas être vérifiées", "Impossibile verificare le prove attuali"],
    ["Verifizierter Wissensbericht kopiert.", "Verified knowledge report copied.", "Rapport de connaissances vérifiées copié.", "Rapporto delle conoscenze verificate copiato."],
    ["Berichtsexport nicht verfügbar", "Report export unavailable", "Export du rapport indisponible", "Esportazione del rapporto non disponibile"],
    ["Als Regression endgültig invalidieren", "Permanently invalidate as regression", "Invalider définitivement comme régression", "Invalida definitivamente come regressione"],
    ["Lernregel als Regression endgültig invalidiert.", "Lesson permanently invalidated as regression.", "Règle invalidée définitivement comme régression.", "Regola invalidata definitivamente come regressione."],
    ["Invalidierung nicht gespeichert", "Invalidation was not saved", "L'invalidation n'a pas été enregistrée", "L'invalidazione non è stata salvata"],
    [
        "Alle Rechner",
        "All computers",
        "Tous les ordinateurs",
        "Tutti i computer",
    ],
    ["Favoriten", "Favorites", "Favoris", "Preferiti"],
    [
        "ARBEITSBEREICHE",
        "WORKSPACES",
        "ESPACES DE TRAVAIL",
        "AREE DI LAVORO",
    ],
    [
        "RECHNERZENTRALE",
        "COMPUTER CENTER",
        "CENTRE DES ORDINATEURS",
        "CENTRO COMPUTER",
    ],
    [
        "Suchen & Aktionen · Strg K",
        "Search & actions · Ctrl K",
        "Recherche et actions · Ctrl K",
        "Ricerca e azioni · Ctrl K",
    ],
    [
        "Klon → Produktion",
        "Clone → production",
        "Clone → production",
        "Clone → produzione",
    ],
    [
        "Änderungen & Rückkehr",
        "Changes & rollback",
        "Modifications et retour",
        "Modifiche e ripristino",
    ],
    [
        "Isoliertes Testlabor",
        "Isolated test lab",
        "Laboratoire isolé",
        "Laboratorio isolato",
    ],
    [
        "Aufträge & Pakete",
        "Jobs & packages",
        "Tâches et paquets",
        "Attività e pacchetti",
    ],
    [
        "Störung rekonstruieren",
        "Reconstruct incident",
        "Reconstituer l’incident",
        "Ricostruire l’incidente",
    ],
    [
        "SSH-Terminal",
        "SSH terminal",
        "Terminal SSH",
        "Terminale SSH",
    ],
    [
        "Abläufe & Wissen",
        "Procedures & knowledge",
        "Procédures et connaissances",
        "Procedure e conoscenze",
    ],
    [
        "Verkaufsbereitschaft",
        "Sales readiness",
        "Préparation à la vente",
        "Preparazione alla vendita",
    ],
    ["Sprache", "Language", "Langue", "Lingua"],
    [
        "Arbeitsbereich",
        "Workspace",
        "Espace de travail",
        "Area di lavoro",
    ],
    ["VERWALTEN", "MANAGE", "GÉRER", "GESTISCI"],
    [
        "Mission Control",
        "Mission Control",
        "Centre de contrôle",
        "Centro di controllo",
    ],
    [
        "Remote-Werkzeuge",
        "Remote tools",
        "Outils à distance",
        "Strumenti remoti",
    ],
    [
        "Sitzungsfenster",
        "Session windows",
        "Fenêtres de session",
        "Finestre delle sessioni",
    ],
    [
        "Inventar & Vault",
        "Inventory & vault",
        "Inventaire et coffre",
        "Inventario e cassaforte",
    ],
    [
        "Aufzeichnungen",
        "Recordings",
        "Enregistrements",
        "Registrazioni",
    ],
    [
        "Vormachen & Lernen",
        "Demonstrate & learn",
        "Démontrer et apprendre",
        "Dimostrare e apprendere",
    ],
    ["Team", "Team", "Équipe", "Team"],
    [
        "Bildschirm verstehen",
        "Understand screen",
        "Comprendre l’écran",
        "Comprendere lo schermo",
    ],
    [
        "Planen & Lernen",
        "Plan & learn",
        "Planifier et apprendre",
        "Pianificare e apprendere",
    ],
    [
        "Recovery Agent",
        "Recovery Agent",
        "Agent de récupération",
        "Agente di ripristino",
    ],
    [
        "Recovery-Pläne",
        "Recovery plans",
        "Plans de récupération",
        "Piani di ripristino",
    ],
    ["Hintergrund", "Background", "Arrière-plan", "In background"],
    [
        "Tickets & Katalog",
        "Tickets & catalog",
        "Tickets et catalogue",
        "Ticket e catalogo",
    ],
    [
        "Ursachen & Lösungen",
        "Causes & solutions",
        "Causes et solutions",
        "Cause e soluzioni",
    ],
    [
        "Prüfen & Ausführen",
        "Verify & execute",
        "Vérifier et exécuter",
        "Verificare ed eseguire",
    ],
    [
        "Änderungsverlauf",
        "Change history",
        "Historique des modifications",
        "Cronologia delle modifiche",
    ],
    [
        "Testlabor",
        "Test lab",
        "Laboratoire de test",
        "Laboratorio di test",
    ],
    [
        "Workflows",
        "Workflows",
        "Flux de travail",
        "Flussi di lavoro",
    ],
    ["Vorfälle", "Incidents", "Incidents", "Incidenti"],
    [
        "Produktionsfreigabe",
        "Production approval",
        "Autorisation de production",
        "Approvazione in produzione",
    ],
    ["Verbindungen", "Connections", "Connexions", "Connessioni"],
    ["Freigaben", "Approvals", "Autorisations", "Approvazioni"],
    [
        "Arbeitsbereiche",
        "Workspaces",
        "Espaces de travail",
        "Aree di lavoro",
    ],
    ["Einstellungen", "Settings", "Paramètres", "Impostazioni"],
    [
        "Entwicklungsversion — Verkauf noch nicht freigegeben",
        "Development build — sales not enabled",
        "Version de développement — vente non activée",
        "Versione di sviluppo — vendita non abilitata",
    ],
    [
        "Diese Ansicht dokumentiert den Stand. Sie führt keine Verbindung, Zahlung oder Lizenzaktivierung aus.",
        "This view documents readiness. It does not connect, charge, or activate a license.",
        "Cette vue documente la préparation. Elle ne se connecte pas, ne facture rien et n’active aucune licence.",
        "Questa vista documenta la preparazione. Non avvia connessioni, pagamenti o attivazioni di licenze.",
    ],
    [
        "Auslieferung und Integrität",
        "Distribution and integrity",
        "Distribution et intégrité",
        "Distribuzione e integrità",
    ],
    [
        "Lokale Paketierung, SHA-256-Prüfung und Installation pro Benutzer vorhanden. Öffentliche Signatur und Release-Abnahme stehen aus.",
        "Local packaging, SHA-256 verification, and per-user installation are available. Public signing and release acceptance remain open.",
        "La création de paquets locaux, la vérification SHA-256 et l’installation par utilisateur sont disponibles. La signature publique et la validation de version restent à effectuer.",
        "Sono disponibili pacchetti locali, verifica SHA-256 e installazione per utente. Firma pubblica e collaudo della versione restano da completare.",
    ],
    [
        "Zahlung und Lizenz",
        "Payment and licensing",
        "Paiement et licence",
        "Pagamento e licenza",
    ],
    [
        "Kein aktiver Checkout und keine kommerzielle Lizenzaktivierung. Preisidee: 9,99 EUR/Nutzer/Monat; Steuerbehandlung offen.",
        "No active checkout or commercial license activation. Proposed price: EUR 9.99/user/month; tax treatment unresolved.",
        "Aucun paiement actif ni activation de licence commerciale. Prix envisagé : 9,99 EUR/utilisateur/mois ; régime fiscal à confirmer.",
        "Nessun pagamento attivo o attivazione di licenza commerciale. Prezzo proposto: 9,99 EUR/utente/mese; trattamento fiscale da confermare.",
    ],
    [
        "Anbieter, Datenschutz und Support",
        "Seller, privacy, and support",
        "Vendeur, confidentialité et assistance",
        "Fornitore, privacy e assistenza",
    ],
    [
        "Anbieterangaben sind anhand des öffentlichen Impressums erfasst. Produktspezifischer Datenschutz, verbindliche Bedingungen und Supportzeiten stehen aus.",
        "Seller details are recorded from the public imprint. Product-specific privacy, binding terms, and support hours remain open.",
        "Les coordonnées du vendeur proviennent des mentions légales publiques. Confidentialité du produit, conditions contractuelles et horaires d’assistance restent à définir.",
        "I dati del fornitore provengono dalle note legali pubbliche. Privacy del prodotto, condizioni vincolanti e orari di assistenza restano da definire.",
    ],
    [
        "Praxisabnahme",
        "Operational acceptance",
        "Validation opérationnelle",
        "Collaudo operativo",
    ],
    [
        "Lokale Tests ersetzen keine Kundenabnahme für RDP, Gateway, WinRM oder Hyper-V. Keine Live-Prüfung in diesem Entwicklungsmodus.",
        "Local tests do not replace customer-environment acceptance for RDP, Gateway, WinRM, or Hyper-V. No live tests in this development mode.",
        "Les tests locaux ne remplacent pas la validation en environnement client pour RDP, Gateway, WinRM ou Hyper-V. Aucun test réel dans ce mode de développement.",
        "I test locali non sostituiscono il collaudo nell’ambiente del cliente per RDP, Gateway, WinRM o Hyper-V. Nessun test reale in questa modalità di sviluppo.",
    ],
    [
        "Übersetzungsumfang",
        "Translation coverage",
        "Couverture des traductions",
        "Copertura delle traduzioni",
    ],
    [
        "Navigation, diese Ansicht und das neue Auslieferungshandbuch: vier Sprachen. Bestehende Fachansichten und ältere technische Dokumente sind noch nicht vollständig übersetzt.",
        "Navigation, this view, and the new distribution guide: four languages. Existing specialist views and older technical documents are not fully translated yet.",
        "Navigation, cette vue et le nouveau guide de distribution : quatre langues. Les vues spécialisées existantes et les anciens documents techniques ne sont pas encore entièrement traduits.",
        "Navigazione, questa vista e la nuova guida di distribuzione: quattro lingue. Le viste specialistiche esistenti e i documenti tecnici precedenti non sono ancora interamente tradotti.",
    ],
    [
        "Handbuch und Betriebsgrenzen",
        "Guide and operating limits",
        "Guide et limites opérationnelles",
        "Guida e limiti operativi",
    ],
    [
        "Handbuch kopieren",
        "Copy guide",
        "Copier le guide",
        "Copia guida",
    ],
    [
        "Statusbericht kopieren",
        "Copy status report",
        "Copier le rapport d’état",
        "Copia rapporto di stato",
    ],
    [
        "Kauf nicht verfügbar",
        "Purchase unavailable",
        "Achat indisponible",
        "Acquisto non disponibile",
    ],
    [
        "Vor einem Verkauf müssen alle offenen Punkte belegt und die vollständige Übersetzung geprüft werden.",
        "Before selling, all open requirements need evidence and the full translation must be reviewed.",
        "Avant toute vente, les exigences ouvertes doivent être justifiées et la traduction complète doit être vérifiée.",
        "Prima della vendita, tutti i requisiti aperti devono essere documentati e la traduzione completa deve essere verificata.",
    ],
];
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_locale_catalog_is_complete_and_unique() {
        let mut keys = std::collections::HashSet::new();
        for row in CATALOG {
            assert!(keys.insert(row[0]));
            for locale in Locale::ALL {
                assert!(!tr(locale, row[0]).trim().is_empty());
            }
        }
        for row in HELPER_ACCEPTANCE_CATALOG {
            assert!(keys.insert(row[0]));
            for locale in Locale::ALL {
                let translated = tr(locale, row[0]);
                assert!(!translated.trim().is_empty());
                if locale != Locale::EnUs {
                    assert_ne!(translated, row[0], "missing {locale:?} translation for {}", row[0]);
                }
            }
        }
    }
    #[test]
    fn release_locale_roundtrip_and_alias() {
        for locale in Locale::ALL {
            assert_eq!(Locale::parse(locale.tag()), Some(locale));
            assert_eq!(
                serde_json::from_str::<Locale>(&serde_json::to_string(&locale).unwrap()).unwrap(),
                locale
            );
        }
        assert_eq!(Locale::parse("us-en"), Some(Locale::EnUs));
        assert_eq!(Locale::parse("xx"), None);
    }
}

const HELPER_ACCEPTANCE_CATALOG: &[[&str; 4]] = &[
    [
        "Helper acceptance",
        "Helper-Abnahme",
        "Validation de l’assistant",
        "Collaudo dell’assistente",
    ],
    [
        "Preflight reports show blockers; they do not mean scenarios were executed.",
        "Vorprüfberichte zeigen Blocker; sie bedeuten nicht, dass Szenarien ausgeführt wurden.",
        "Les rapports préalables signalent des blocages ; ils ne signifient pas que les scénarios ont été exécutés.",
        "I rapporti preliminari mostrano blocchi; non indicano che gli scenari siano stati eseguiti.",
    ],
    [
        "Acceptance report path",
        "Pfad des Abnahmeberichts",
        "Chemin du rapport de validation",
        "Percorso del rapporto di collaudo",
    ],
    [
        "Load report",
        "Bericht laden",
        "Charger le rapport",
        "Carica rapporto",
    ],
    [
        "Acceptance report loaded.",
        "Abnahmebericht geladen.",
        "Rapport de validation chargé.",
        "Rapporto di collaudo caricato.",
    ],
    [
        "Acceptance report unavailable or invalid.",
        "Abnahmebericht nicht verfügbar oder ungültig.",
        "Rapport de validation indisponible ou invalide.",
        "Rapporto di collaudo non disponibile o non valido.",
    ],
    [
        "Acceptance report invalid.",
        "Abnahmebericht ist ungültig.",
        "Le rapport de validation est invalide.",
        "Il rapporto di collaudo non è valido.",
    ],
    [
        "Simulation fixture preflight",
        "Vorprüfung mit Simulationsdaten",
        "Précontrôle sur fixture simulée",
        "Precontrollo con fixture simulata",
    ],
    [
        "Guest acceptance preflight",
        "Vorprüfung der Gastumgebung",
        "Précontrôle de l’environnement invité",
        "Precontrollo dell’ambiente guest",
    ],
    [
        "Measured guest fixture",
        "Gemessene Gastumgebung",
        "Fixture invitée mesurée",
        "Fixture guest misurata",
    ],
    [
        "Run",
        "Lauf",
        "Exécution",
        "Esecuzione",
    ],
    [
        "Case record",
        "Fallakte",
        "Dossier du cas",
        "Pratica del caso",
    ],
    [
        "Case revision",
        "Fallrevision",
        "Révision du cas",
        "Revisione del caso",
    ],
    [
        "Report historical context.",
        "Bericht gehört zu einem früheren Fallkontext.",
        "Le rapport correspond à un ancien contexte de cas.",
        "Il rapporto appartiene a un contesto del caso precedente.",
    ],
    [
        "Product acceptance: not established",
        "Produktabnahme: nicht belegt",
        "Validation produit : non établie",
        "Collaudo prodotto: non dimostrato",
    ],
    [
        "Sparse intake reload",
        "Unvollständige Falldaten und Speichern",
        "Saisie incomplète et rechargement",
        "Inserimento incompleto e ricaricamento",
    ],
    [
        "Native reads, blocker, imported spill",
        "Native Reads, Blocker und importierter Spill",
        "Lectures natives, blocage et débordement importé",
        "Letture native, blocco e spill importato",
    ],
    [
        "Selectivity maintenance",
        "Selektivität nach Wartung",
        "Sélectivité après maintenance",
        "Selettività dopo la manutenzione",
    ],
    [
        "Reviewed index mutation restoration",
        "Geprüfte Indexänderung und Wiederherstellung",
        "Modification d’index examinée et restauration",
        "Modifica indice esaminata e ripristino",
    ],
    [
        "API portal checks",
        "API- und Portalprüfungen",
        "Vérifications de l’API et des deux portails",
        "Verifiche API e di entrambi i portali",
    ],
    [
        "Binding edits reconciliation",
        "Bindungsänderungen und Abgleich",
        "Modifications de liaison et rapprochement",
        "Modifiche di associazione e riconciliazione",
    ],
    [
        "Lesson invalidation export",
        "Lernregel ungültig machen und exportieren",
        "Invalidation et export de leçon",
        "Invalidazione ed esportazione della lezione",
    ],
    [
        "Native capture states",
        "Native Aufnahmestände",
        "États de capture natifs",
        "Stati di acquisizione nativi",
    ],
    [
        "No persisted capture reference",
        "Keine gespeicherte Aufnahmereferenz",
        "Aucune référence de capture enregistrée",
        "Nessun riferimento di acquisizione salvato",
    ],
    [
        "Capture references are absent; no verified screenshot is shown.",
        "Aufnahmereferenzen fehlen; es wird kein verifiziertes Bild angezeigt.",
        "Les références de capture manquent ; aucune capture vérifiée n’est affichée.",
        "Mancano i riferimenti di acquisizione; non viene mostrata alcuna schermata verificata.",
    ],
    [
        "Requested",
        "Angefordert",
        "Demandée",
        "Richiesta",
    ],
    [
        "Approved",
        "Freigegeben",
        "Approuvée",
        "Approvata",
    ],
    [
        "Consumed",
        "Verbraucht",
        "Consommée",
        "Consumata",
    ],
    [
        "Verified",
        "Verifiziert",
        "Vérifiée",
        "Verificata",
    ],
    [
        "Capture intervention",
        "Aufnahme erfordert Eingreifen",
        "Intervention de capture",
        "Intervento di acquisizione",
    ],
    [
        "Not run",
        "Nicht ausgeführt",
        "Non exécuté",
        "Non eseguito",
    ],
    [
        "Passed",
        "Bestanden",
        "Réussi",
        "Superato",
    ],
    [
        "Failed",
        "Fehlgeschlagen",
        "Échec",
        "Non riuscito",
    ],
    [
        "Blocked",
        "Blockiert",
        "Bloqué",
        "Bloccato",
    ],
    [
        "Incomplete",
        "Unvollständig",
        "Incomplet",
        "Incompleto",
    ],
    [
        "Persisted case loaded; save/reload zero-call instrumentation has not run.",
        "Gespeicherter Fall geladen; die Null-Aufruf-Prüfung beim Speichern und Neuladen wurde nicht ausgeführt.",
        "Cas enregistré chargé ; la vérification d’absence d’appels lors de l’enregistrement et du rechargement n’a pas été exécutée.",
        "Caso salvato caricato; il controllo dell’assenza di chiamate durante il salvataggio e il ricaricamento non è stato eseguito.",
    ],
    [
        "Reviewed PostgreSQL scope exists; native collection, blocker, import workload receipts are required.",
        "Ein geprüfter PostgreSQL-Bereich ist vorhanden; native Erfassungs-, Blocker-, Import- und Workloadbelege fehlen.",
        "Un périmètre PostgreSQL examiné existe ; les preuves de collecte native, de blocage, d’importation et de charge sont requises.",
        "Esiste un ambito PostgreSQL verificato; sono necessarie prove di raccolta nativa, blocco, importazione e carico.",
    ],
    [
        "A reviewed PostgreSQL scope is required for native reads.",
        "Für native Lesezugriffe ist ein geprüfter PostgreSQL-Bereich erforderlich.",
        "Un périmètre PostgreSQL examiné est requis pour les lectures natives.",
        "Per le letture native è necessario un ambito PostgreSQL verificato.",
    ],
    [
        "Requires accepted Task 14 protected rehearsal and Task 15 native production action, intent and verification receipts.",
        "Erfordert den akzeptierten geschützten Task-14-Probelauf sowie native Task-15-Belege für Produktionsaktion, Absicht und Verifikation.",
        "Nécessite la répétition protégée acceptée de la tâche 14 et les preuves natives de la tâche 15 pour l’action de production, l’intention et la vérification.",
        "Richiede la prova protetta accettata del task 14 e le prove native del task 15 per azione di produzione, intenzione e verifica.",
    ],
    [
        "Requires accepted Task 14 protected rehearsal and Task 15 exact-index production and restoration receipts.",
        "Erfordert den akzeptierten geschützten Task-14-Probelauf sowie Task-15-Produktions- und Wiederherstellungsbelege für den exakten Index.",
        "Nécessite la répétition protégée acceptée de la tâche 14 et les preuves de production et de restauration de l’index exact de la tâche 15.",
        "Richiede la prova protetta accettata del task 14 e le prove di produzione e ripristino dell’indice esatto del task 15.",
    ],
    [
        "Three reviewed HTTP scopes exist; separate DB-backed API and portal functional receipts are still required.",
        "Drei geprüfte HTTP-Bereiche sind vorhanden; separate datenbankgestützte Funktionsbelege für API und Portale fehlen.",
        "Trois périmètres HTTP examinés existent ; des preuves fonctionnelles distinctes, adossées à la base, restent nécessaires pour l’API et les portails.",
        "Esistono tre ambiti HTTP verificati; sono ancora necessarie prove funzionali separate, basate sul database, per API e portali.",
    ],
    [
        "Three separately reviewed API/portal HTTP scopes are required.",
        "Drei separat geprüfte HTTP-Bereiche für API und Portale sind erforderlich.",
        "Trois périmètres HTTP distincts examinés pour l’API et les portails sont requis.",
        "Sono necessari tre ambiti HTTP distinti e verificati per API e portali.",
    ],
    [
        "Pre-dispatch edit and post-launch reconciliation witnesses have not been collected for this run.",
        "Für diesen Lauf wurden keine Belege zu Änderungen vor dem Start und zum Abgleich nach dem Start erfasst.",
        "Aucune preuve de modification avant lancement ni de rapprochement après lancement n’a été recueillie pour cette exécution.",
        "Per questa esecuzione non sono state raccolte prove di modifiche prima dell’avvio e riconciliazione dopo l’avvio.",
    ],
    [
        "Case is marked verified; exact lesson evidence, restart invalidation and export receipts are still required.",
        "Der Fall ist als verifiziert markiert; genaue Lernbelege sowie Belege für Invalidierung nach Neustart und Export fehlen.",
        "Le cas est marqué comme vérifié ; les preuves exactes de la leçon, de l’invalidation après redémarrage et de l’export restent requises.",
        "Il caso è contrassegnato come verificato; servono ancora prove precise della lezione, dell’invalidazione dopo il riavvio e dell’esportazione.",
    ],
    [
        "Requires an independently verified product outcome before lesson creation.",
        "Vor dem Erstellen einer Lernregel ist ein unabhängig verifiziertes Produktergebnis erforderlich.",
        "Un résultat produit vérifié de manière indépendante est requis avant la création d’une leçon.",
        "Prima di creare una lezione è necessario un risultato del prodotto verificato in modo indipendente.",
    ],
];
