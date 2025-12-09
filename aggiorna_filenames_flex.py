import sqlite3
import os

# -------------------------------
# Percorso del database
# -------------------------------
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'database.db')

# Cartella dove sono salvate le immagini
uploads_folder = os.path.join(basedir, 'static', 'uploads')

# -------------------------------
# Connessione al DB
# -------------------------------
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# -------------------------------
# Assicurati che la colonna filename esista
# -------------------------------
try:
    cur.execute("ALTER TABLE ricetta ADD COLUMN filename TEXT")
    print("✅ Colonna 'filename' aggiunta con successo!")
except sqlite3.OperationalError:
    print("ℹ️ La colonna 'filename' esiste già.")

# -------------------------------
# Recupera tutte le ricette
# -------------------------------
cur.execute("SELECT id_ricetta, titolo_ricetta FROM ricetta")
ricette = cur.fetchall()

# -------------------------------
# Aggiorna filename basandoti sul titolo della ricetta
# -------------------------------
for ricetta in ricette:
    id_ricetta = ricetta[0]
    titolo = ricetta[1].lower().replace(' ', '')  # Rimuove spazi per confronto flessibile

    found_file = None
    for file in os.listdir(uploads_folder):
        name, ext = os.path.splitext(file)
        if titolo in name.lower().replace(' ', ''):
            found_file = file
            break

    if found_file:
        cur.execute(
            "UPDATE ricetta SET filename = ? WHERE id_ricetta = ?",
            (found_file, id_ricetta)
        )
        print(f"✅ Aggiornata ricetta {id_ricetta} con file: {found_file}")
    else:
        print(f"⚠️ Nessuna immagine trovata per ricetta {id_ricetta} ({ricetta[1]})")

# -------------------------------
# Salva modifiche e chiudi DB
# -------------------------------
conn.commit()
conn.close()
print("✅ Aggiornamento completato.")
