# Risultati misurati delle riparazioni

In Cause e soluzioni, selezionare un profilo di produzione e aprire Risultati misurati nelle raccomandazioni. Il rapporto usa gli esiti completati del registro di esecuzione negli ultimi 90 giorni per quell’endpoint. Nessuna chiamata di rete o IA.

## Misure
Produzione e ambiente di prova mostrano separatamente riparazioni documentate, errori, ripristini ed esiti non verificati. Valgono le regole rigorose delle raccomandazioni: collegamento esatto a piano e destinazione, esclusione dei duplicati, errore iniziale, successo HTTP e transizione reale o riavvio verificato. Gli esiti esclusi sono conteggiati a parte.

L’intervallo mediano va dall’osservazione iniziale registrata della destinazione al controllo riuscito. La conclusione successiva di un lotto di destinazioni non lo prolunga. Solo i successi documentati forniscono campioni temporali; il numero di campioni è mostrato insieme alle riparazioni. I dati mancanti non diventano zero. Ogni campione contiene identificativi di esecuzione/destinazione e orari UTC.

## Limiti di interpretazione
Non è durata totale dell’incidente, MTTR, lavoro umano, disponibilità, perdita evitata o tempo risparmiato. Misurare solo i successi introduce una selezione; gli errori restano separati e non diventano riparazioni rapide. Non vengono registrati confronto manuale o costi finanziari: risparmio di lavoro e ROI sono esplicitamente non misurati. Non si presuppongono equivalenza dell’ambiente o efficacia causale.

## Esportazione e privacy
Copia rapporto in JSON inserisce negli appunti identificativo del profilo selezionato, periodo, conteggi separati e prove temporali. Non esporta credenziali o indirizzi degli host e non autorizza esecuzioni. Gli identificativi possono comunque essere sensibili: controllare prima della condivisione. I dati sorgente restano invariati. Nuova interfaccia e documentazione in en-US, de, fr e it.

## Verifica — 2026-09-13

Quattro test mirati di risultati/interfaccia e 21 test di regressione dell’esecuzione superati (tre comuni). La nuova vista è stata renderizzata in quattro lingue a 640 e 1440 pixel. Compilazione offline e formattazione verificate. Nessuna nuova suite completa o connessione reale; restano gli avvisi esistenti.
