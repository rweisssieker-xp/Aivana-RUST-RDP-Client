# Relayne — guida alla distribuzione e all’utilizzo

Bozza di sviluppo · 2026-09-13 · it

## Stato e ambito
Questa è una distribuzione di sviluppo non firmata, non una versione commerciale approvata. Ripristino remoto e protocolli hanno test locali, senza collaudo completo nell’ambiente del cliente. La nuova vista di distribuzione e questa guida sono disponibili in en-US, de, fr e it. Viste specialistiche e documenti tecnici precedenti restano parzialmente in tedesco; la traduzione completa è un requisito per il rilascio.

## Fornitore e contatti
Aivana GmbH
Paulusstr. 45a - Hinterhaus - LOFT45
33602 Bielefeld, Germany
info@aivana-gmbh.ai · +49 521 92278996
Amtsgericht Bielefeld · HRB 46421 · DE459356027
https://www.aivana-gmbh.ai
https://aivana-gmbh.ai/Imprint

Note legali pubbliche verificate il 13/09/2026. Amministratore: Udo Bergmann. È il contatto aziendale generale, non un impegno sui tempi di assistenza né un responsabile della protezione dei dati appositamente designato. La pagina privacy del sito si dichiara attualmente un testo di esempio. Restano da approvare condizioni e privacy specifiche del prodotto.

## Requisiti e installazione
Windows x64. Chiudere Relayne prima dell’installazione. Non servono privilegi amministrativi. Il pacchetto non installa Hyper-V, non abilita accessi remoti, non configura host e non crea credenziali. I requisiti dei protocolli esterni richiedono un collaudo separato.
Estrarre l’intero pacchetto in una nuova cartella. Verificare: powershell -File .\Test-Package.ps1 -PackageRoot .
Solo per questo pacchetto di sviluppo non firmato: powershell -File .\Install-Relayne.ps1 -Language it -AllowUnsignedDev
Sono copiati solo i file del manifesto in una nuova cartella di versione sotto LOCALAPPDATA\Relayne\versions. Le versioni esistenti non vengono sovrascritte. Avviare manualmente il percorso relayne.exe restituito. Scegliere la lingua nell’applicazione; alcune viste specialistiche restano non tradotte.

## Aggiornamenti e ritorno alla versione precedente
Installare ogni pacchetto accanto alla versione precedente. Nessun servizio di download o aggiornamento automatico incluso. Chiudere l’applicazione e avviare l’eseguibile precedente. Prima salvare i dati: tornare a un vecchio binario non annulla modifiche al database o alla configurazione. Nessuna compatibilità dei dati è garantita senza test. Una verifica fallita lascia intatte le installazioni esistenti.

## Disinstallazione
Eseguire powershell -File .\Uninstall-Relayne.ps1 -Version VERSION -Language it da un pacchetto attendibile. Viene rimossa solo la cartella di versione verificata. Profili, credenziali, registri e dati utente vengono conservati. La rimozione non annulla un abbonamento. In questa versione di sviluppo non esiste un abbonamento attivo.

## Integrità e limiti di sicurezza
Test-Package.ps1 verifica un elenco rigoroso di file e le impronte SHA-256. Rileva la corruzione, ma un manifesto non firmato non autentica l’editore. Firma pubblica e canale di distribuzione affidabile restano necessari. Install-Relayne.ps1 rifiuta il pacchetto senza AllowUnsignedDev esplicito. Non crea account, attività pianificate, servizi, regole firewall o connessioni remote.

## Dati e privacy — bozza tecnica
Profili, impostazioni, prove e registri sono memorizzati localmente. Gli archivi di credenziali e casi protetti usano Windows DPAPI dove implementato; non tutti i file sono cifrati. La protezione dell’account Windows e dei file resta importante. Un host remoto, server del team o fornitore IA opzionale configurato può ricevere dati nel relativo flusso applicativo; questo installatore e questa vista non li inviano. Controllare testi, schermate ed esportazioni prima di condividerli; la rimozione automatica dei segreti non è garantita. Conservazione, basi giuridiche, accordi di trattamento, trasferimenti internazionali e cancellazione richiedono una revisione specifica. Questo lavoro non aggiunge telemetria o invio automatico di segnalazioni di arresto anomalo.

## Assistenza e incidenti
Comunicare versione, versione Windows, passaggi, risultato atteso/effettivo e registri ripuliti al contatto generale. Non inviare password, token, schermate dei clienti o dettagli degli host senza un canale sicuro concordato. Non sono promessi tempi di risposta. Segnalazioni di sicurezza, responsabilità di escalation e ambienti supportati devono essere definiti prima della vendita.

## Prezzo, licenza e recesso — nessuna offerta
9,99 EUR per utente al mese è una proposta. Trattamento IVA inclusa/esclusa, fatturazione, pagamenti, rimborsi, recesso e assistenza non sono definitivi. Pagamento e attivazione commerciale sono disabilitati. Questa guida non concede una licenza commerciale e non costituisce contratto o consulenza legale. Avvisi sulle dipendenze di terze parti e compatibilità delle licenze richiedono revisione prima della distribuzione esterna.

## Prove di rilascio
Il manifesto contiene versione, revisione sorgente, modifiche non registrate, canale di sviluppo e impronte esatte. Ambienti locali, profili, segreti, registri di test e dati dei clienti sono esclusi. Per il rilascio futuro conservare impronte dei binari testati e risultati effettivi; il superamento dei test di sviluppo non dimostra da solo la prontezza alla vendita.
