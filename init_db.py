from app2 import app, db, User, Recipe, Category, Like
from datetime import datetime
import os
import random
from werkzeug.security import generate_password_hash, check_password_hash
# Funzione per generare un hash di password
#def hash_password(password):
    # Assumiamo che 'bcrypt' sia importato e inizializzato correttamente in app2.py
#    return bcrypt.generate_password_hash(password).decode('utf-8')

with app.app_context():
    
    print("\n==============================================")
    print("INIZIALIZZAZIONE DEL DATABASE (PULIZIA E POPOLAMENTO)")
    print("==============================================")
    
    # --- 1. PULIZIA ---
    db.drop_all()
    print("Schema precedente rimosso (db.drop_all()).")
    
    # --- 2. CREAZIONE DELLO SCHEMA ---
    db.create_all()
    print("Schema del database ricreato (db.create_all()).")

    # --- 3. POPOLAMENTO DEI DATI ---
    try:
        # A. Utenti
        password_admin_hash = generate_password_hash('TestAdmin123')
        password_user_hash = generate_password_hash('password123')

        admin_user = User(
            username='AdminTest', 
            email='admin@ricettario.it', 
            password_hash=password_admin_hash, 
            ruolo='admin',
            
            data_registrazione=datetime.utcnow()
        )
        basic_user = User(
            username='UtenteProva', 
            email='utente@ricettario.it', 
            password_hash=password_user_hash, 
            
            ruolo='utente',
            data_registrazione=datetime.utcnow()
        )
        db.session.add_all([admin_user, basic_user])
        db.session.commit()
        print("Utenti di prova aggiunti (AdminTest, UtenteProva).")

        # B. Categorie
        cat_primi = Category(name='Primi')
        cat_secondi = Category(name='Secondi')
        cat_dolci = Category(name='Dolci')
        cat_altro = Category(name='Altro')
        db.session.add_all([cat_primi, cat_secondi, cat_dolci, cat_altro])
        db.session.commit()
        print("Categorie di prova aggiunte (Primi Piatti, Secondi Piatti).")

        # C. Ricette
        ricetta_admin = Recipe(
            title='Spaghetti al Ragù Perfetti',
            description='Una ricetta classica italiana per un ragù ricco e saporito.',
            ingredients='Spaghetti, carne macinata, pomodoro, cipolla, carote, sedano.',
            instructions='Soffriggere le verdure, aggiungere la carne, sfumare con vino rosso e cuocere lentamente con il pomodoro.',
            preparation_time=60,
            cooking_time=120,
            servings=4,
            is_private=False,
            author_id=admin_user.id,
            category_id=cat_primi.id,
            filename='spaghetti_ragu.jpg',
            creation_date=datetime.utcnow()
        )
        db.session.add(ricetta_admin)
        db.session.commit()
        print(f"Ricetta di prova aggiunta: {ricetta_admin.title}")

        # D. Like (Test per la colonna 'timestamp')
        like_test = Like(
            id_utente=basic_user.id,
            id_ricetta=ricetta_admin.id,
            timestamp=datetime.utcnow()
        )
        db.session.add(like_test)
        db.session.commit()
        print("Like di prova aggiunto per testare la colonna 'timestamp'.")


        print("\n✅ Popolamento completato con successo!")

    except Exception as e:
        db.session.rollback()
        print(f"\nERRORE durante il popolamento dei dati: {e}")
        
    print("==============================================")