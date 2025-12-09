# primo.py
#from app2 import app, db, Like   # importa l'app Flask, il db e il modello

#with app.app_context():          # attiva il contesto
#    print(db.session.query(Like).count())
from werkzeug.security import generate_password_hash
print(generate_password_hash("admin123", method="pbkdf2:sha256"))