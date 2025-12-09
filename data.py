# PER ESEGUIRE QUESTO SCRIPT:
# 1. Assicurati che tu sia nella stessa cartella di db_initializer.py.
# 2. Esegui: python db_initializer.py
#
# Questo script userà la libreria standard sqlite3 per creare o popolare un database locale.

import sqlite3
import datetime

# Nome del file database SQLite locale
DATABASE_FILE = 'instance.db'

def initialize_database():
    """
    Crea le tabelle necessarie e inserisce i dati iniziali di base nel database SQLite.
    """
    conn = None
    try:
        # Connessione al database (lo crea se non esiste)
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        print(f"Connessione a SQLite stabilita con successo nel file: {DATABASE_FILE}")

        print("\n--- Avvio della reinizializzazione del database SQLite ---")

        # 1. Creazione della tabella utenti
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS utenti (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                ruolo TEXT NOT NULL,
                attivo INTEGER NOT NULL,
                data_registrazione TEXT NOT NULL
            );
        """)
        print("Tabella 'utenti' creata o già esistente.")

        # 2. Creazione della tabella articoli
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS articoli (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titolo TEXT NOT NULL,
                contenuto TEXT NOT NULL,
                autore TEXT NOT NULL,
                pubblicato INTEGER NOT NULL,
                data_pubblicazione TEXT
            );
        """)
        print("Tabella 'articoli' creata o già esistente.")

        # --- Inserimento Dati ---

        # Dati di esempio per gli utenti
        utenti_data = [
            ("Mario Rossi", "mario.rossi@esempio.it", "admin", 1, datetime.datetime.now().isoformat()),
            ("Giulia Bianchi", "giulia.bianchi@esempio.it", "utente", 1, datetime.datetime.now().isoformat())
        ]

        print("\nInserimento dati nella collezione 'utenti'...")
        for nome, email, ruolo, attivo, data in utenti_data:
            try:
                cursor.execute("""
                    INSERT INTO utenti (nome, email, ruolo, attivo, data_registrazione) 
                    VALUES (?, ?, ?, ?, ?)
                """, (nome, email, ruolo, attivo, data))
                print(f"Utente aggiunto: {nome}")
            except sqlite3.IntegrityError:
                print(f"ATTENZIONE: Utente {nome} già esistente (email duplicata). Saltato.")
            except Exception as e:
                print(f"Errore nell'aggiungere l'utente {nome}: {e}")

        # Dati di esempio per gli articoli
        articoli_data = [
            ("Introduzione a Python e SQLite", "Questo articolo spiega come usare Python per popolare un database locale.", "Mario Rossi", 1, datetime.datetime.now().isoformat()),
            ("Guida rapida a Tailwind CSS", "Una guida per l'utilizzo delle utility class di Tailwind per uno styling rapido.", "Giulia Bianchi", 0, None)
        ]
        
        print("\nInserimento dati nella collezione 'articoli'...")
        for titolo, contenuto, autore, pubblicato, data_pubblicazione in articoli_data:
            try:
                cursor.execute("""
                    INSERT INTO articoli (titolo, contenuto, autore, pubblicato, data_pubblicazione) 
                    VALUES (?, ?, ?, ?, ?)
                """, (titolo, contenuto, autore, pubblicato, data_pubblicazione))
                print(f"Articolo aggiunto: {titolo}")
            except Exception as e:
                print(f"Errore nell'aggiungere l'articolo {titolo}: {e}")

        # Commit delle modifiche (salvataggio permanente)
        conn.commit()
        
        # Simulo il documento di configurazione (in SQLite sarebbe un'altra tabella)
        print("\nNota: La configurazione è stata omessa, ma l'inizializzazione del database è completata.")


        print("\n--- Inizializzazione del database SQLite completata ---")

    except Exception as e:
        print(f"\nERRORE FATALE: Impossibile completare l'operazione sul database: {e}")
    finally:
        if conn:
            conn.close()

# Esecuzione della funzione principale
if __name__ == "__main__":
    initialize_database()