# Mac über Relayne steuern

1. Am Mac unter **Systemeinstellungen → Allgemein → Freigaben** die
   **Bildschirmfreigabe** aktivieren. Je nach macOS-Version befinden sich die
   Einstellungen unter dem Informationssymbol neben der Freigabe.
2. In den Computereinstellungen **VNC-Benutzer dürfen den Bildschirm mit einem
   Passwort steuern** aktivieren und ein separates VNC-Passwort setzen.
   Relayne unterstützt hierfür 1–8 ASCII-Zeichen. Das ist nicht das Passwort
   des macOS-Benutzerkontos. Falls Remote Management die Bildschirmfreigabe
   ersetzt, muss dort der entsprechende VNC-Zugriff freigegeben werden.
3. In Relayne ein Profil mit **VNC / Mac**, der IP-Adresse oder dem Hostnamen
   des Macs und Port **5900** anlegen. Das VNC-Passwort im Passwortfeld speichern.
   Benutzername und Domäne werden für diese Anmeldeart nicht verwendet.
4. Profil speichern und verbinden. Der Mac-Desktop erscheint in den vorhandenen
   Sitzungsfenstern. Maus, Ziehen, Mausrad und Tastatureingaben werden übertragen.
   Die Windows-Taste entspricht Command, Alt entspricht Option.

## Umfang und Grenzen

- RFB 3.3, 3.7 und 3.8; Passwortanmeldung mit VNC Authentication.
- Raw-Bilddaten, CopyRect und vom Server gemeldete Desktopgrößenänderungen.
- Bestehender geschützter Passwortspeicher; keine Passwörter in Profil-JSON.
- Keine Apple-Benutzerkontoanmeldung, Audioübertragung, Dateiübertragung,
  Zwischenablagesynchronisierung oder vom Client angeforderte Auflösungsänderung.
- Das VNC-Protokoll verschlüsselt die Bildschirmdaten nicht. Verwende ein
  vertrauenswürdiges lokales Netz oder VPN, keine öffentliche Portfreigabe.
- Die klassische VNC-Passwortanmeldung ist auf acht Zeichen begrenzt.
- Raw-Bilder benötigen mehr Bandbreite als komprimierte VNC-Verfahren.
  Maximal 16.777.216 Pixel pro Desktop; größere Desktops werden abgewiesen.
- Tastaturlayout, macOS-Berechtigungen und konkrete macOS-Version müssen an
  einem echten Mac geprüft werden. Automatisierte Tests verwenden einen lokalen
  RFB-Testserver; sie ersetzen keine macOS-Kompatibilitätsprüfung.

## Prüfung

`cargo test --bin relayne vnc_client` prüft Größenbegrenzungen, Bilddekodierung,
überlappende CopyRect-Bereiche, Eingaben sowie Anmeldung, Bildschirmübertragung
und Verbindungsabbau gegen einen lokalen TCP-Testserver.
