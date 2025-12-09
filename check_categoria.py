import sqlite3, os

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, "database.db")

conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Controlla se la tabella categoria esiste
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='categoria'")
if not cur.fetchone():
    print("❌ La tabella 'categoria' non esiste.")
    conn.close()
    exit()

# Controlla se 'Altro' esiste
cur.execute("SELECT * FROM categoria WHERE nome_categoria = 'Altro'")
if cur.fetchone():
    print("ℹ️ La categoria 'Altro' esiste già.")
else:
    cur.execute("INSERT INTO categoria (nome_categoria) VALUES ('Altro')")
    conn.commit()
    print("✅ Categoria 'Altro' aggiunta con successo!")

# Mostra tutte le categorie
print("\n📋 Categorie attuali:")
for row in cur.execute("SELECT * FROM categoria"):
    print(row)

conn.close()
