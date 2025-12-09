import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

try:
    cur.execute("ALTER TABLE utente ADD COLUMN password_hash TEXT")
    print("✅ Colonna password_hash aggiunta!")
except sqlite3.OperationalError:
    print("ℹ️ La colonna password_hash esiste già.")

conn.commit()
conn.close()
