//! Explicit locale selection; no network translation and no changes to user data.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Locale {
    #[serde(rename = "en-US")]
    EnUs,
    #[default]
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
