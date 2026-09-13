//! Static, evidence-limited distribution status. Never grants commercial entitlement.
use crate::localization::Locale;

pub const WEBSITE: &str = "https://www.aivana-gmbh.ai";
pub const SELLER: &str =
    "Aivana GmbH · Paulusstr. 45a - Hinterhaus - LOFT45 · 33602 Bielefeld · Germany";
pub const CONTACT: &str = "info@aivana-gmbh.ai · +49 521 92278996";
pub const REGISTER: &str = "Amtsgericht Bielefeld · HRB 46421 · USt-IdNr. DE459356027";
pub const SOURCE: &str = "https://aivana-gmbh.ai/Imprint";

pub const GATES: [(&str, &str); 5] = [
    (
        "Auslieferung und Integrität",
        "Lokale Paketierung, SHA-256-Prüfung und Installation pro Benutzer vorhanden. Öffentliche Signatur und Release-Abnahme stehen aus.",
    ),
    (
        "Zahlung und Lizenz",
        "Kein aktiver Checkout und keine kommerzielle Lizenzaktivierung. Preisidee: 9,99 EUR/Nutzer/Monat; Steuerbehandlung offen.",
    ),
    (
        "Anbieter, Datenschutz und Support",
        "Anbieterangaben sind anhand des öffentlichen Impressums erfasst. Produktspezifischer Datenschutz, verbindliche Bedingungen und Supportzeiten stehen aus.",
    ),
    (
        "Praxisabnahme",
        "Lokale Tests ersetzen keine Kundenabnahme für RDP, Gateway, WinRM oder Hyper-V. Keine Live-Prüfung in diesem Entwicklungsmodus.",
    ),
    (
        "Übersetzungsumfang",
        "Navigation, diese Ansicht und das neue Auslieferungshandbuch: vier Sprachen. Bestehende Fachansichten und ältere technische Dokumente sind noch nicht vollständig übersetzt.",
    ),
];

pub fn guide(locale: Locale) -> &'static str {
    match locale {
        Locale::EnUs => include_str!("../docs/distribution/en-US/guide.md"),
        Locale::De => include_str!("../docs/distribution/de/guide.md"),
        Locale::Fr => include_str!("../docs/distribution/fr/guide.md"),
        Locale::It => include_str!("../docs/distribution/it/guide.md"),
    }
}

pub fn report(locale: Locale) -> serde_json::Value {
    serde_json::json!({
        "schema": "relayne-sales-readiness-v1", "version": env!("CARGO_PKG_VERSION"),
        "locale": locale.tag(), "channel": "development", "sale_ready": false,
        "checkout_enabled": false, "commercial_entitlement": false,
        "seller": SELLER, "contact": CONTACT, "source": SOURCE, "source_checked": "2026-09-13",
        "open_requirements": GATES.iter().map(|(title,detail)| serde_json::json!({
            "title": crate::localization::tr(locale,title), "detail":crate::localization::tr(locale,detail)
        })).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_reports_never_grant_sales_or_entitlement() {
        for locale in Locale::ALL {
            let value = report(locale);
            assert_eq!(value["sale_ready"], false);
            assert_eq!(value["checkout_enabled"], false);
            assert_eq!(value["commercial_entitlement"], false);
            assert_eq!(value["open_requirements"].as_array().unwrap().len(), 5);
            assert!(guide(locale).contains("www.aivana-gmbh.ai"));
            assert!(guide(locale).contains("Install-Relayne.ps1"));
            assert!(guide(locale).contains("Uninstall-Relayne.ps1"));
        }
    }
}
