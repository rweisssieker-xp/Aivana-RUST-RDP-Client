Add-Type -AssemblyName System.Speech
$relayneLong = @{
 de = @(
 'Wenn Systeme ausfallen, brauchen IT-Teams einen klaren nächsten Schritt. Relayne verbindet Remote-Zugriff mit geprüften Wiederherstellungsabläufen.',
 'Nutzen Sie RDP und SSH in einem gemeinsamen Arbeitsplatz. Verknüpfen Sie den Zugriff auf Ihre Systeme mit gemeinsamem Betriebswissen für Ihr Team.',
 'Erproben Sie unterstützte Reparaturen zuerst in einem isolierten Klon. Prüfen Sie dort, ob der Dienst und die festgelegten Anwendungstests erfolgreich sind.',
 'Prüfnachweise unterstützen die Vorbereitung für die Produktion. Ihr Team prüft die Ergebnisse und gibt den Produktionsschritt ausdrücklich frei.',
 'Relayne richtet sich an IT-Teams und Dienstleister. Die Abläufe benötigen passende Infrastruktur. Beginnen Sie mit einem konkreten Pilotfall und prüfen Sie den Nutzen.'
 )
 en = @(
 'When systems fail, IT teams need a clear next step. Relayne connects remote access with verified recovery workflows to support your team.',
 'Use RDP and SSH in one shared workspace. Connect access to your systems with operational knowledge that your team can use together.',
 'Rehearse supported repairs in an isolated clone first. Check whether the service and your defined application tests succeed before moving forward.',
 'Recorded test evidence supports preparation for production. Your team reviews the results and explicitly approves the production step.',
 'Relayne is designed for IT teams and service providers. Workflows require suitable infrastructure. Start with a concrete pilot case and evaluate the value for your team.'
 )
}
$relayneSynth = New-Object System.Speech.Synthesis.SpeechSynthesizer
foreach ($relayneLang in @('de','en')) {
 $relayneSynth.SelectVoice($(if ($relayneLang -eq 'de') { 'Microsoft Hedda Desktop' } else { 'Microsoft Zira Desktop' }))
 $relayneSynth.Rate = 1
 for ($relayneIndex = 0; $relayneIndex -lt 5; $relayneIndex++) {
  $relayneSynth.SetOutputToWaveFile("$PSScriptRoot/$relayneLang-long-$relayneIndex.wav")
  $relayneSynth.Speak($relayneLong[$relayneLang][$relayneIndex])
  $relayneSynth.SetOutputToNull()
 }
}
$relayneSynth.Dispose()
