Add-Type -AssemblyName System.Speech
$relayneScenes = Get-Content -LiteralPath "$PSScriptRoot/script.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$relayneSynth = New-Object System.Speech.Synthesis.SpeechSynthesizer
foreach ($relayneLang in @('de','en')) {
    $relayneVoice = if ($relayneLang -eq 'de') { 'Microsoft Hedda Desktop' } else { 'Microsoft Zira Desktop' }
    $relayneSynth.SelectVoice($relayneVoice)
    $relayneSynth.Rate = 0
    $relayneIndex = 0
    foreach ($relayneScene in $relayneScenes.$relayneLang) {
        $relayneSynth.SetOutputToWaveFile("$PSScriptRoot/$relayneLang-$relayneIndex.wav")
        $relayneSynth.Speak($relayneScene[2])
        $relayneSynth.SetOutputToNull()
        $relayneIndex++
    }
}
$relayneSynth.Dispose()
