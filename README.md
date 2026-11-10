# Bluetooth 5.4

- Studente:  Tirelli Andrea
- Corso:     Crittografia Applicata - 2024

<br />

**Obiettivo del progetto**:

In questo progetto che prevede come argomento **Bluetooth**, in particolare la versione **5.4**, un analisi in ambito crittografico e di sicurezza del protocollo e dei nuovi standard introdotti con essa.
In particolare, lo studio e ricerca del progetto mira a due macro argomenti:

- **Pairing Bluetooth**
- **Encrypted Advertising Data**

In prima fase, il **pairing bluetooth** ci serve per capire come due dispositivi, nettamente diversi tra di loro, possano stabilire un *link* di connessione sicuro; come vengono scelti i metodi di **pairing** e **generazione della chiave**.
Infine avremmò una chiara idea come funziona il pairing bluetooth, ma soprattutto di quali oggetti crittografici abbiamo a disposizione per il secondo argomento, ovvero **Encrypted Advertising Data**.

Encrypted Advertising Data c'è bisogno di garantire garanzie di sicurezza come:

- **confidenzialità**
- **autenticità** (di conseguenza anche **integrità**)

Quello che verrà mostrato sarà il contesto presente e perché per ottenere uno schema **AEAD** non possiamo seguire le *best practice* della letteratura, come:

- **2 chiavi diverse per cifratura e autenticità**
- **encrypt-then-MAC**

Quale è stata la soluzione proposta e implementata (come standard) nel protocollo v5.4 e le varie motivazioni.

## Responsible use

Everything in this repository is a simulation: devices, pairings and attacks run in Python against simulated peers
and the Bluetooth Core Specification's sample data. No code talks to a radio or to a real device. The attack
scenarios exist to study and explain the weaknesses and their fixes; do not use them against devices you do not own
or are not authorised to test.
