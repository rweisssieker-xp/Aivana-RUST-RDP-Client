# Signierte Reparaturpakete

Im Workflow-Bereich erzeugt „Signierschlüssel erzeugen“ einen lokalen Ed25519-Schlüssel. Der private PKCS8-Schlüssel wird mit Windows DPAPI geschützt und nie exportiert. Ein bestehender Schlüssel wird nicht überschrieben. „Öffentlichen Schlüssel anzeigen“ liefert den Base64-Schlüssel; sein SHA-256-Fingerabdruck kann unabhängig verglichen werden.

Empfänger tragen den geprüften öffentlichen Schlüssel explizit in ihren lokalen, DPAPI-geschützten Vertrauensspeicher ein. Export signiert die vollständigen Paketbytes mit Domänentrennung. Import prüft zuerst den vertrauten Herausgeber und die Signatur, danach Schema, Plan und innere Prüfsumme. Ein Import führt keine Schritte aus. Der Plan benötigt die übliche Inhaltsprüfung und Ausführungsfreigabe.

Paketdownload unterstützt eine feste HTTPS-Adresse ohne Zugangsdaten, Query oder Fragment. TLS-Prüfung bleibt aktiv, Weiterleitungen und Proxy-Nutzung sind deaktiviert, Antworten sind auf 512 KiB und 20 Sekunden begrenzt. Nach dem Download wird der aktuelle Vertrauensspeicher erneut geladen; ein zwischenzeitlich widerrufener Schlüssel wird abgewiesen.

„Widerrufen“ verhindert spätere Imports dieses Herausgebers. Bereits importierte lokale Entwürfe werden dadurch nicht gelöscht. Der ausdrücklich aktivierbare unsignierte lokale Import dient vorhandenen Entwürfen und erfordert weiterhin eine separate Ausführungsfreigabe. Feste Planwerte und Befehle können vertrauliche Inhalte enthalten und müssen vor dem Export geprüft werden; temporäre Laufzeit-Slots gehören nicht zum Paket.

Dies ist lokale Herausgeberverwaltung, kein zentraler Marketplace, keine automatische Schlüsselverteilung und keine Online-Sperrliste. Der Kryptotest prüft Signatur, fehlendes Vertrauen, manipulierte Inhalte und Widerruf. Weitere Abnahmeergebnisse stehen in `relayne-acceptance.md`.
