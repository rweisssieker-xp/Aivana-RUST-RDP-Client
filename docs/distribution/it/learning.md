# Raccomandazioni di riparazione basate sui risultati

La nuova sezione Cause e soluzioni classifica i risultati di ripristino dei servizi per l’endpoint di produzione selezionato. Non addestra modelli e non contatta fornitori IA. La classifica viene ricalcolata in modo deterministico dal registro di esecuzione attuale, senza un archivio separato di prove apprese.

## Regole delle prove
Contribuiscono solo risultati completati negli ultimi 90 giorni. Date future o scadute, identità esecuzione/destinazione duplicate, collegamenti al piano non validi e altri endpoint sono esclusi. Le prove vengono mostrate separatamente e non migliorano mai la classifica di produzione. Avvio, riavvio e controlli di salute diversi restano distinti.

Una riparazione documentata richiede la verifica esistente delle prove prima/azione/dopo, controllo iniziale fallito, controllo HTTP finale riuscito e transizione reale o riavvio verificato. Un servizio già sano o un solo controllo TCP non dimostra una riparazione. Errori, ripristini ed esiti non verificati restano visibili.

## Classifica e revoca
Ogni categoria di produzione è limitata a cinque risultati: +5 per riparazione documentata, −8 per errore/ripristino combinati, −4 per esito non verificato. Sono pesi espliciti, non probabilità. Una raccomandazione richiede almeno una riparazione documentata in produzione e l’ultimo successo deve essere successivo a ogni esito negativo o non verificato. In caso di parità resta bloccata. L’ordinamento è deterministico.

## Uso e limiti
Selezionare un profilo, esaminare conteggi e riferimenti delle prove, quindi preparare un nuovo piano di verifica se la raccomandazione è supportata. Restano attive la protezione delle attività in corso e le nuove verifiche/autorizzazioni. La classifica non avvia azioni. La copia esplicita del rapporto include nomi dei servizi e identificativi delle prove; controllare prima di condividere.

Lo stesso endpoint non garantisce software, configurazione o permessi invariati. Nessun apprendimento tra clienti, prova causale o promessa di produttività misurata. I risultati esclusi vengono contati ma non costituiscono prove positive. Le precedenti viste delle soluzioni restano disponibili separatamente. I nuovi testi sono disponibili in en-US, de, fr e it.
# Lacune delle prove
Le lacune storiche sono esplicite: controllo HTTP mancante, errore iniziale non documentato, transizione del servizio mancante o prove prima/azione/dopo incomplete o contraddittorie. Spiegano l’incertezza storica, non lo stato attuale dell’host.

## Verifica — 2026-09-13

Cinque test mirati di apprendimento/traduzione e 18 test di regressione dell’esecuzione superati (quattro test in comune). Compilazione offline e formattazione verificate. Nessuna nuova suite completa, accesso a host reali o chiamata a modelli esterni. Restano gli avvisi di compilazione esistenti.
