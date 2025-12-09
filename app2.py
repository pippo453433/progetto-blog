from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from sqlalchemy import func, UniqueConstraint
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user
import re
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from flask_sslify import SSLify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach
import logging
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, PrimaryKeyConstraint,  or_
from sqlalchemy.orm import relationship, synonym
import sys
from uuid import uuid4
from datetime import datetime, timezone, timedelta
import time
from flask_wtf.file import FileField, FileAllowed
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length
#from sqlalchemy.ext.hybrid import synonym
from flask_login import LoginManager, UserMixin
from flask import g
from dateutil import parser







# --- Configurazione Iniziale ---
basedir = os.path.abspath(os.path.dirname(__file__))
INSTANCE_FOLDER = os.path.join(basedir, 'instance')
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
logging.basicConfig(level=logging.WARNING)

app = Flask(__name__)
VALID_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "outlook.it", "libero.it", "tiscali.it", "virgilio.it", "alice.it"
]
app.secret_key = 'la_tua_chiave_segreta_molto_lunga_e_casuale'
csrf = CSRFProtect(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.permanent_session_lifetime = timedelta(minutes=15)
#sslify = SSLify(app) # Commentato per ambiente locale, riattivalo in produzione

limiter = Limiter(
    app = app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

app.url_map.strict_slashes = False

# Usa un percorso assoluto per il database per evitare ambiguità
DB_FILENAME = 'database.db'
db_path = os.path.join(INSTANCE_FOLDER, DB_FILENAME)
os.makedirs(INSTANCE_FOLDER, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Filtro per Jinja2 (Per formattare le date direttamente nel template) ---
# Questo filtro permette di usare {{ data | datetimeformat }} nel template.
@app.template_filter('datetimeformat')
def format_datetime(value, format_string='%d/%m/%Y'):
    """Filtro per formattare gli oggetti datetime o stringhe data in un formato leggibile."""
    if value is None:
        return ""
    
    # Se è già un oggetto datetime, usalo direttamente
    if isinstance(value, datetime):
        return value.strftime(format_string)
        
    # Se è una stringa, prova a convertirla
    if isinstance(value, str):
        # Tenta di analizzare i formati più comuni
        SQL_DATE_FORMATS = ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y-%m-%d %H:%M']
        for fmt in SQL_DATE_FORMATS:
            try:
                dt_object = datetime.strptime(value, fmt)
                return dt_object.strftime(format_string)
            except ValueError:
                continue
        return value # Ritorna la stringa originale se non riesce a parsare
    
    return str(value)

# --- Definizione dei Modelli ---
class RecipeForm(FlaskForm):
    title = StringField('Titolo', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Descrizione Breve', validators=[DataRequired(), Length(max=255)])
    ingredients = TextAreaField('Ingredienti', validators=[DataRequired()])
    instructions = TextAreaField('Istruzioni', validators=[DataRequired()])
    # SelectField per la categoria, coercita a intero per l'ID del DB
    category = SelectField('Categoria', coerce=int, validators=[DataRequired()]) 
    photo = FileField('Carica Immagine', validators = [
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Solo immagini: JPG, PNG, GIF!')
    ])
    submit = SubmitField('Salva Ricetta')

class EditRecipeForm(FlaskForm):
    title = StringField('Titolo', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Descrizione Breve', validators=[DataRequired()])
    category = SelectField('Categoria', coerce=int, validators=[DataRequired()])
    photo = FileField('Carica Nuova Immagine (Opzionale)', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Solo immagini: JPG, PNG, GIF!')
    ])
    submit = SubmitField('Aggiorna Ricetta')



class User(db.Model, UserMixin):
    __tablename__ = 'utente' 
    id_utente = db.Column(db.Integer, primary_key=True)
    username = db.Column('nome_utente', db.String(80), unique=True, nullable=False) 
    email = db.Column('email', db.String(100), unique=True, nullable=False)
    password_hash = db.Column('password_hash', db.String(255), nullable=False)
    ruolo = db.Column('ruolo', db.String(20), default='utente')
    data_registrazione = db.Column('data_registrazione', db.DateTime)
    
    id = synonym('id_utente') 
    
    recipes = db.relationship(
        'Recipe', 
        back_populates='author', 
        lazy='dynamic', 
        foreign_keys='Recipe.id_autore',
        cascade="all, delete-orphan"

    )
    likes = db.relationship('Like', back_populates='user', lazy='dynamic', cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<User {self.username}>'
        
    def get_id(self):
        return str(self.id_utente)
        
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    

class CategoriaForm(FlaskForm):
    """Form per l'aggiunta di una nuova categoria."""
    name = StringField('Nome Categoria', validators=[
        DataRequired(message='Il nome è obbligatorio'),
        Length(min=2, max=50, message='Il nome deve avere tra i 2 e i 50 caratteri')
    ])
    submit = SubmitField('Aggiungi Categoria')

class Category(db.Model):
    __tablename__ = 'categoria'
    id_categoria = db.Column(db.Integer, primary_key=True)
    name = db.Column('nome', db.String(50), unique=True, nullable=False)
    
    id = synonym('id_categoria')
    
    recipes = db.relationship('Recipe', back_populates='category', lazy='dynamic')
    
    def __repr__(self):
        return f'<Category {self.name}>'

class MockRecipe:
    def __init__(self, title, description, category_id, user_id):
        self.title = title
        self.description = description
        self.category_id = category_id
        self.user_id = user_id
    
    @staticmethod
    def query_get_or_404(id_ricetta):
        # Placeholder: in un'app reale, questo recupererebbe dal database
        # Esempio: ricetta dell'utente 1, ma l'utente corrente è 2
        if id_ricetta == 1:
            return MockRecipe("Carbonara", "Ricetta classica con guanciale croccante e tuorlo cremoso", 1, 1)
        return None # Simula il 404
    
# Simulo l'oggetto current_user (devi importarlo da flask_login)
#class MockUser:
#    def __init__(self, id):
#        self.id = id
# Assumiamo che l'utente loggato abbia ID = 2
#current_user = MockUser(id=2)

class Recipe(db.Model):
    __tablename__ = 'ricetta'
    id_ricetta = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    # --- CAMPI AGGIUNTI PER LE RICETTE ---
    ingredients = db.Column('ingredienti', db.Text, nullable=False)
    instructions = db.Column('istruzioni', db.Text, nullable=False)
    preparation_time = db.Column('tempo_prep', db.Integer, default=0)
    cooking_time = db.Column('tempo_cottura', db.Integer, default=0)
    servings = db.Column('porzioni', db.Integer, default=1)
    is_private = db.Column('is_privata', db.Boolean, default=False)

    id_autore = db.Column(db.Integer, db.ForeignKey('utente.id_utente'), nullable=False)
    category_id = db.Column(
        'id_categoria',
        db.Integer,
        db.ForeignKey('categoria.id_categoria'),
        nullable=False
    )
    
    description = db.Column('descrizione', db.Text, nullable=False)
    filename = db.Column('filename', db.String(100), nullable=True)
    creation_date = db.Column('data_creazione_ricetta', db.String(10), default=lambda: time.strftime("%Y-%m-%d"))
    
    id = synonym('id_ricetta') 
    author_id = synonym('id_autore') 
    
    author = db.relationship(
        'User', 
        back_populates='recipes', 
        foreign_keys=[id_autore] 
    )
    category = db.relationship('Category', back_populates='recipes', foreign_keys='Recipe.category_id')
    likes = db.relationship('Like', back_populates='recipe', lazy='dynamic') 

    def __repr__(self):
        return f'Recipe("{self.title}", Author_ID: {self.author_id})'
        
    @property
    def total_likes(self):
        return db.session.scalar(db.select(func.count(Like.id_ricetta)).where(Like.id_ricetta == self.id_ricetta))
    @classmethod
    def top_by_likes(cls, limit=10):
        return (
            db.session.query(cls, func.count(Like.id_like).label("num_likes"))
            .outerjoin(Like, cls.id_ricetta == Like.id_ricetta)
            .group_by(cls.id_ricetta)
            .order_by(func.count(Like.id_like).desc())
            .limit(limit)
            .all()

        )
    
class Like(db.Model):
    __tablename__ = 'like'
    id_like = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    id_utente = db.Column(db.Integer, db.ForeignKey('utente.id_utente'), nullable=False)
    id_ricetta = db.Column(db.Integer, db.ForeignKey('ricetta.id_ricetta'), nullable=False) 

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False )
    id = db.synonym('id_likes')
    user_id = synonym('id_utente')
    recipe_id = synonym('id_ricetta')
    
    user = db.relationship(
        'User', 
        back_populates='likes',
        foreign_keys=[id_utente]
    )
    recipe = db.relationship(
        'Recipe', 
        back_populates='likes',
        foreign_keys=[id_ricetta]
    )
    
    def __repr__(self):
        return f'<Like UserID: {self.id_utente} | RecipeID: {self.id_ricetta}>'
        
    __table_args__ = (
        UniqueConstraint('id_utente', 'id_ricetta', name='_user_recipe_uc'),
    )
class RicettaForm(FlaskForm):
    title = StringField('Titolo', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Descrizione Breve', validators=[DataRequired(), Length(max=500)])
    category = SelectField('Categoria', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Salva Ricetta')

def fake_csrf_token():
    return 'fake_csrf_token' + str(int(time.time()))

@app.after_request
def add_security_headers(response):
    # --- Content Security Policy ---
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com https://kit.fontawesome.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "img-src 'self' data: https://*; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "connect-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
    )

    # --- Altri header di sicurezza ---
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), fullscreen=(), payment=()"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

    return response

# --- Secure Cookies ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=not app.debug,
    SESSION_COOKIE_SAMESITE='Lax'
)




# --- Funzione di Inizializzazione del Database ---

def init_db(app, db_path):
    """
    Crea o ricrea il database e inserisce i dati iniziali (Utenti, Categorie, Ricette, Like).
    
    ATTENZIONE: Questo script elimina il file del database esistente e lo ricrea.
    """
    print(f"--- Avvio Inizializzazione Database su: {db_path} ---")
    
    # *** LOGICA DI PULIZIA: AVVIENE FUORI DAL CONTESTO PER LA GESTIONE DEI FILE ***
    if os.path.exists(db_path):
        try:
            # Eliminazione per garantire che le query di conteggio User.query.count() siano 0
            os.remove(db_path)
            print(f"File database esistente eliminato: {db_path}. Ricreazione in corso...")
        except PermissionError:
            print("=========================================================================")
            print("ERRORE CRITICO: Impossibile eliminare il file del database (PermissionError).")
            print(f"Il file: {db_path} è utilizzato da un altro processo.")
            print("SOLUZIONE: Chiudi TUTTE le istanze del terminale/server Flask e riprova.")
            print("=========================================================================")
            sys.exit(1) # Forza l'uscita
            
    # *** TUTTE LE OPERAZIONI DB DEVONO AVVENIRE ALL'INTERNO DEL CONTESTO ***
    with app.app_context():
        # 1. Ricreazione dello schema pulito
        db.create_all()
        print("Schema del database ricreato con successo.")
        
        # 2. Inserimento Categorie (User.query.count() sarà 0 qui)
        if Category.query.count() == 0:
            db.session.add_all([
                Category(name='Primi'),
                Category(name='Secondi'),
                Category(name='Dolci'),
                Category(name='Altro')
            ])
            db.session.commit()
            print("Categorie iniziali inserite.")
            
        # 3. Inserimento Utenti (User.query.count() sarà 0 qui)
        if User.query.count() == 0:
            admin_user = User(username='admin_user', email='admin@example.com', ruolo='admin', data_registrazione=func.now())
            admin_user.set_password('Password@123')
            db.session.add(admin_user)

            normal_user = User(username='normal_user', email='user@example.com', ruolo='utente', data_registrazione=func.now())
            normal_user.set_password('Password@123')
            db.session.add(normal_user)
            db.session.commit()
            
            # DEBUG: Conferma l'hash per l'utente admin
            admin_check = db.session.scalar(db.select(User).filter_by(email='admin@example.com'))
            if admin_check:
                print(f"DEBUG SEED: Utente 'admin@example.com' creato. Hash: {admin_check.password_hash[:30]}...")
                
            print("Utenti iniziali inseriti.")
            
        # 4. Inserimento Ricette e Like
        if Recipe.query.count() == 0:
            # Recupero degli ID appena creati
            admin_id = db.session.scalar(db.select(User.id).where(User.ruolo == 'admin'))
            normal_user_id = db.session.scalar(db.select(User.id).where(User.username == 'normal_user'))
            
            # Recupero delle categorie
            primi_cat = db.session.scalar(db.select(Category).filter_by(name='Primi'))
            dolci_cat = db.session.scalar(db.select(Category).filter_by(name='Dolci'))
            altro_cat = db.session.scalar(db.select(Category).filter_by(name='Altro'))
            
            if admin_id and normal_user_id and primi_cat and dolci_cat and altro_cat:
                ricetta1 = Recipe(title='Carbonara', author_id=admin_id, category_id=primi_cat.id, description='Ricetta classica con guanciale croccante e tuorlo cremoso')
                ricetta2 = Recipe(title="Tiramisù", author_id=admin_id, category_id=dolci_cat.id, description="Dessert al cucchiaio con mascarpone e caffè.")
                ricetta3 = Recipe(title="Pizza Margherita", author_id=admin_id, category_id=altro_cat.id, description="Pizza con pomodoro, mozzarella e basilico fresco.")
                db.session.add_all([ricetta1, ricetta2, ricetta3])
                db.session.commit()
                
                # ... (Logica per Like omessa per brevità ma presente nel tuo script originale)
                print("Ricette e Like iniziali inseriti.")

        print("--- Configurazione del database completata. ---")

if not os.path.exists(db_path):
    print("Database non trovato, inizializzazione in corso")
    init_db(app, db_path)
# --- Rotta di prova (temporanea) ---

@app.route('/test_db')
def test_db():
    # Solo per testare che il server si avvii senza errori
    # Esempio di recupero dati per mostrare che il DB funziona
    users = User.query.all()
    if users:
        user_list = ", ".join([u.username for u in users])
        return f"<h1>Server Attivo!</h1><p>Utenti nel DB: {user_list}</p>"
    return "<h1>Server Attivo!</h1><p>DB vuoto o in errore.</p>"

def get_user_recipes_data(id_utente):
    """Recupera le ricette create dall'utente e quelle a cui ha messo like."""
    ricette_mie = []
    ricette_like = []

    # 1. Ricette create dall'utente loggato
    try:
        mie_ricette_query = db.session.execute(
            db.select(
                Recipe, 
                Category.name.label('categoria_nome'), 
                func.count(Like.recipe_id).label('num_likes')
            )
            .outerjoin(Category, Recipe.category_id == Category.id)
            .outerjoin(Like, Recipe.id == Like.recipe_id)
            .where(Recipe.author_id == id_utente)
            .group_by(Recipe.id, Category.name)
            .order_by(Recipe.id.desc())
        ).all()
        
        for r, categoria_nome, num_likes in mie_ricette_query:
            ricette_mie.append({
                'id_ricetta': r.id,
                'titolo_ricetta': r.title,
                'descrizione': r.description,
                'filename': r.filename,
                'categoria_nome': categoria_nome or "N/A",
                'num_likes': num_likes or 0,
                'is_liked': True, 
                'e_mia': True
            })
            
    except Exception as e:
        app.logger.error(f"Errore query 'mie ricette' per utente {id_utente}: {e}")
        flash('⚠️ Impossibile caricare le tue ricette.', 'error')

    # 2. Ricette a cui l'utente ha messo like
    try:
        ricette_likes_query = db.session.execute(
            db.select(
                Recipe, 
                User.username.label('autore_nome'), 
                Category.name.label('categoria_nome'), 
                func.count(Like.recipe_id).label('num_likes')
            )
            .join(Like, Recipe.id == Like.recipe_id)
            .join(User, Recipe.author_id == User.id) 
            .outerjoin(Category, Recipe.category_id == Category.id)
            .where(Like.user_id == id_utente)
            .group_by(Recipe.id, User.username, Category.name)
            .order_by(Recipe.id.desc())
        ).all()
        
        for r, autore_nome, categoria_nome, num_likes in ricette_likes_query:
            if r.author_id != id_utente:
                ricette_like.append({
                    'id_ricetta': r.id,
                    'titolo_ricetta': r.title,
                    'descrizione': r.description,
                    'filename': r.filename,
                    'autore_nome': autore_nome,
                    'categoria_nome': categoria_nome or "N/A",
                    'num_likes': num_likes or 0,
                    'is_liked': True,
                    'e_mia': False
                })
                
    except Exception as e:
        app.logger.error(f"Errore query 'ricette piaciute' per utente {id_utente}: {e}")
        flash('⚠️ Impossibile caricare le ricette che ti sono piaciute.', 'error')

    return ricette_mie, ricette_like

def admin_required(f):
    """
    Limita l'accesso solo agli utenti con ruolo 'admin'.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Assumendo che il ruolo sia salvato nell'attributo 'ruolo' dell'oggetto current_user
        if not current_user.is_authenticated or current_user.ruolo.lower() != 'admin':
            flash('Accesso negato: devi essere un Amministratore.', 'danger') 
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function
        
# -------------------------------
# Ruolo richiesto decorator
def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if 'id_utente' not in session:
            flash("🔒 Devi effettuare il login per accedere.")
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view
def ruolo_richiesto(ruoli):
    def decorator(f):
        @wraps(f)
        def wrapped_view(*args, **kwargs):
            if 'id_utente' not in session:
                flash("🔒 Devi effettuare il login per accedere.", "error")
                return redirect(url_for('login'))
            ruolo_utente = session.get('ruolo')
            if ruolo_utente not in ruoli:
                app.logger.warning(f"Accesso negato per utente {session['id_utente']} (Ruolo: {ruolo_utente}) alla rotta {request.path}")
                flash("❌ Non hai i permessi necessari per accedere a questa pagina.", "error")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return wrapped_view 
    return decorator

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#@app.context_processor
#def inject_global_vars():
    # ASSICURATI DI USARE LA CLASSE MODELLO (Category)
#    try:
        # DB.session.execute(DB.select(Category)).scalars().all() è la sintassi moderna
#        all_categories = db.session.execute(db.select(Category)).scalars().all()
#        categorie_formattate = [
#            {'id_categoria': cat.id_categoria, 'nome_categoria': cat.nome}
#            for cat in all_categories
#        ]
#    except Exception as e:
#        print(f"Errore nel context processor: {e}")
#        categorie_formattate = []
        
#    return dict(categorie=categorie_formattate, all_categories=all_categories)

@app.context_processor
def inject_global_vars():
    # ASSICURATI DI USARE LA CLASSE MODELLO (Category)
    try:
        # 1. Recupera tutti gli oggetti Category dal database
        all_categories = db.session.execute(db.select(Category)).scalars().all()
        
        print("-" * 30)
        print(f"DEBUG: Trovate {len(all_categories)} categorie dal DB.")
        
        # 2. Formattiamo gli oggetti per abbinarli alle chiavi del template (id_categoria e nome_categoria)
        categorie_formattate = []
        for cat in all_categories:
            # ASSUNZIONE CRUCIALE: Le colonne del modello Category sono:
            # cat.id_categoria (per l'ID) e cat.name (per il nome)
            
            # Se la tua colonna per il nome è 'nome' e non 'name', cambia 'cat.name' con 'cat.nome'
            category_name = getattr(cat, 'name', None) # Prova prima 'name'
            if category_name is None:
                 category_name = getattr(cat, 'nome', 'N/A') # Altrimenti prova 'nome' o usa 'N/A'
                 
            categorie_formattate.append({
                'id_categoria': cat.id_categoria,
                'nome_categoria': category_name
            })
            print(f"DEBUG: Categoria formattata: ID={cat.id_categoria}, Nome={category_name}")
        
    except Exception as e:
        # Se c'è un errore (es. la tabella non esiste o la colonna non ha il nome giusto), lo stampiamo.
        print("-" * 30)
        print(f"FATAL ERROR nel context processor: {e}")
        print("ATTENZIONE: Le categorie non saranno visualizzate nel menù.")
        categorie_formattate = []
        
    print("-" * 30)
    # 3. Ritorniamo la lista sotto la chiave 'categorie', come richiesto dal form nuova_ricetta.html
    return dict(categorie=categorie_formattate)


# -------------------------------
# Home: ricette casuali
# -------------------------------
@app.route('/', defaults={'category_id': None})
@app.route('/home')
@app.route('/category_id/<int:category_id>')
def home(category_id=None):
    """Mostra la homepage con un filtro di categoria opzionale (per ID)."""

    try:
        all_categories = db.session.execute(db.select(Category).order_by(Category.name)).scalars().all()
    except Exception as e:
        # Gestione dell'errore nel caso il database non risponda
        print(f"Errore nel recupero delle categorie: {e}")
        all_categories = []
        
    query = db.select(Recipe).order_by(Recipe.creation_date.desc())
    current_category_name = None
    if category_id is not None:
        current_category = db.session.scalars(db.select(Category).where(Category.id == category_id))
        
        if current_category:
            query = query.where(Recipe.category_id == current_category.id)
            current_category_name = current_category.name
        else:
            flash(f'Categoria con ID "{category_id}" non trovata', 'warning')
            
    ricette_objects = db.session.execute(query).scalars().all()
    ricette_list = [formatta_ricetta(recipe_obj) for recipe_obj in ricette_objects]
        
    # CORREZIONE 2: Passare la lista di ricette con il nome chiave corretto ('ricette_list')
    return render_template('home.html',
                           title='Le Nostre Ricette', 
                           ricette=ricette_list, 
                           all_categories=all_categories, 
                           current_category_name=current_category_name)


@app.route('/nuova_ricetta', methods=['GET', 'POST'])
def create_recipe():
    # 1. AUTENTICAZIONE E UTENTE CORRENTE
    user_id = session.get('id_utente')
    if not user_id:
        flash('Devi effettuare il login per creare una ricetta.', 'warning')
        return redirect(url_for('login'))
    
    current_user = db.session.get(User, user_id)

    if not current_user:
        session.pop('id_utente', None)
        flash('Utente non trovato, per favore effettua nuovamente il login.', 'danger')
        return redirect(url_for('login'))
    
    # Recupero delle categorie all'inizio per poterle ripassare in caso di errore nel POST
    all_categories = db.session.execute(db.select(Category)).scalars().all()

    if request.method == 'POST':
        # RECUPERO DEI DATI ESISTENTI NEL TUO FORM HTML (Titolo, Descrizione, Categoria)
        title_from_form = request.form.get('titolo')
        description_from_form = request.form.get('descrizione')
        category_id_str = request.form.get('id_categoria')
        
        # *** ADATTAMENTO CHIAVE: Assegna valori di default per i campi non presenti nel form ***
        ingredients = "Non specificato nel form" 
        instructions = "Non specificato nel form" 
        preparation_time = 0
        cooking_time = 0
        servings = 1
        is_private = False

        # CONTROLLO CAMPI OBBLIGATORI (Titolo, Descrizione, Categoria)
        if not title_from_form or not description_from_form or not category_id_str:
            flash('Per favore, compila tutti i campi obbligatori (Titolo, Descrizione, Categoria).', 'danger')
            # Ritorna il form con le categorie caricate
            return render_template('nuova_ricetta.html', 
                                   title='Aggiungi una nuova ricetta',
                                   categorie=all_categories,
                                   current_user=current_user), 400

        # Conversione e validazione dell'ID categoria
        try:
            category_id = int(category_id_str)
        except ValueError:
            flash('Errore: ID categoria non valido.', 'danger')
            return redirect(url_for('create_recipe'))

        # 2. Verifica che la categoria esista nel DB
        category_obj = db.session.get(Category, category_id) 
        
        if not category_obj:
            flash(f'Errore: La categoria selezionata non è valida.', 'danger')
            return redirect(url_for('create_recipe'))

        # 3. Logica di salvataggio
        try:
            new_recipe = Recipe(
                title=title_from_form,
                description=description_from_form,
                ingredients=ingredients,
                instructions=instructions,
                preparation_time=preparation_time,
                cooking_time=cooking_time,
                servings=servings,
                is_private=is_private,
                author=current_user, 
                category=category_obj,
                filename=None
            )

            db.session.add(new_recipe)
            db.session.commit()
            flash('Ricetta salvata con successo!', 'success')
            return redirect(url_for('home'))

        except Exception as e:
            # BLOCCO DI DEBUG ESTESO
            db.session.rollback()
            print("-" * 50)
            print("FATAL ERROR - ERRORE DI SALVATAGGIO RICETTA NEL DB:")
            print(f"Tipo di errore: {type(e).__name__}")
            print(f"Messaggio: {e}")
            print("-" * 50)
            
            flash('Errore imprevisto durante il salvataggio della ricetta. Controlla la console del server per i dettagli.', 'danger')
            return redirect(url_for('create_recipe'))

    # Se la richiesta è GET, mostra il form
    # *** CORREZIONE: Passiamo la lista con la chiave 'categorie' (al plurale) come richiesto dal tuo template ***
    return render_template('nuova_ricetta.html', 
                           title='Aggiungi una nuova ricetta',
                           categorie=all_categories, # Questa chiave corrisponde al tuo loop nel template
                           current_user=current_user)




# --- Funzione Helper per la Mappatura dei Dati ---
def formatta_ricetta(recipe_obj):
    """
    Trasforma un oggetto Recipe in un dizionario per il template, 
    includendo l'autore, la categoria, il conteggio dei like e lo stato del like dell'utente corrente.
    """
    like_count = 0
    liked_by_user = False
    
    try:
        # Recupera il conteggio totale dei like
        # Esempio corretto: select(func.count(Like.recipe_id))
        like_count = db.session.scalar(
            select(func.count(Like.recipe_id)).where(Like.recipe_id == recipe_obj.id)
        ) or 0
        
        # Controlla se l'utente corrente ha messo like
        user_id = session.get('user_id')
        if user_id:
            existing_like = db.session.scalar(
                select(Like).where(
                    (Like.user_id == user_id) & (Like.recipe_id == recipe_obj.id)
                )
            )
            if existing_like is not None:
                 liked_by_user = True
            
    except Exception as e:
        # Se il modello Like non esiste nel DB o c'è un altro errore, i like saranno 0.
        print(f"ATTENZIONE: Modello Like non disponibile o errore DB: {e}. I like saranno 0.")
        pass
        
    # --- CORREZIONE DEL PROBLEMA STRFTIME ---
    data_creazione = recipe_obj.creation_date
    if isinstance(data_creazione, datetime):
        # Se è un oggetto datetime, formattalo
        formatted_date = data_creazione.strftime('%d/%m/%Y')
    else:
        # Se è una stringa (come avviene per i dati vecchi), usala direttamente
        formatted_date = str(data_creazione)
    # ----------------------------------------
        
    return {
        'id': recipe_obj.id,
        'titolo': recipe_obj.title,
        'descrizione': recipe_obj.description,
        'id_ricetta': recipe_obj.id,
        # Sfrutta le relazioni dell'oggetto Recipe per autore e categoria
        'nome_autore': recipe_obj.author.username if recipe_obj.author else 'Sconosciuto',
        'nome_categoria': recipe_obj.category.name if recipe_obj.category else 'Altro',
        
        'data_creazione': formatted_date, # Usa il valore formattato o la stringa esistente
        'conteggio_like': like_count,
        'piaciuto_dall_utente': liked_by_user,
    }


# -------------------------------
# Registrazione
# -------------------------------
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        password = request.form['password']
        
        try:
            domain = email.split('@')[1].lower()
        except IndexError:
            flash('⚠️ Indirizzo email non valido.', 'error')
            return redirect(url_for('register'))
        if domain not in VALID_DOMAINS:
            flash('⚠️ Dominio email non valido. Usa un dominio comune come gmail.com, yahoo.com, outlook.com, ecc.', 'error')
            return redirect(url_for('register'))

        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$'
        if not re.match(pattern, password):
            flash('⚠️ Password deve avere almeno 8 caratteri, una maiuscola, una minuscola, un numero e un simbolo speciale.', 'error')
            return redirect(url_for('register'))
        if db.session.scalar(db.select(User).filter_by(email=email)):
            flash("⚠️ Utente o email già registrati.", "warning")
            return redirect(url_for('register'))
        
        try:
            nuovo_utente = User(username=nome, email=email, ruolo='utente')
            nuovo_utente.set_password(password)
            db.session.add(nuovo_utente)
            db.session.commit()
            flash("✅ Registrazione completata! Ora effettua il login.")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Errore in fase di registrazione per {email}: {e}")
            flash("⚠️ Si è verificato un errore imprevisto durante la registrazione.", "error")
            return redirect(url_for('register'))
    return render_template('register.html')
        


# -------------------------------
# Login
# -------------------------------
from flask_login import login_user

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user_sa = db.session.scalar(db.select(User).filter_by(email=email))
        if user_sa and user_sa.check_password(password):
            login_user(user_sa)
            session['utente'] = user_sa.username
            session['id_utente'] = user_sa.id # Usa l'attributo mappato .id
            session['ruolo'] = user_sa.ruolo
            session.permanent = True
            flash(f'👋 Benvenuto, {user_sa.username}!', 'success')
            if user_sa.ruolo == 'admin':
               return redirect(url_for('dashboard_admin'))
            return redirect(url_for('home'))
        else:
            flash('❌ Credenziali non valide.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

# Funzione ausiliaria per la conversione e formattazione
def formatta_data_safe(data_obj, formato='%d/%m/%Y'):
    """
    Tenta di formattare un oggetto data/ora in modo sicuro.
    Gestisce oggetti datetime nativi, None e stringhe data.
    """
    if data_obj is None:
        return 'N/A'
    
    # 1. Caso Oggetto Datetime NATIVO (il più comune e corretto)
    if isinstance(data_obj, datetime):
        try:
            return data_obj.strftime(formato)
        except ValueError:
            # Fallback se il formato è sbagliato o l'oggetto è corrotto
            return str(data_obj)
    
    # 2. Caso Stringa (se il database o una query ha restituito una stringa)
    if isinstance(data_obj, str):
        try:
            # Tenta un parsing flessibile della stringa (molto più robusto di fromisoformat)
            dt_obj = parser.parse(data_obj)
            return dt_obj.strftime(formato)
        except Exception:
            # Se il parsing fallisce, restituisce la stringa originale
            return data_obj 
            
    # 3. Altri tipi (es. interi, ecc.)
    return str(data_obj)
# -------------------------------
# Dashboard Admin

@app.route('/dashboard_admin')
@login_required
@ruolo_richiesto(['admin'])
def dashboard_admin():
    """Mostra la dashboard di amministrazione."""

    # Assumi che CategoriaForm e ruolo_richiesto siano importati
    categoria_form = CategoriaForm() 
    
    # 1. STATISTICHE
    stats = {
        'utenti': db.session.scalar(db.select(db.func.count()).select_from(User)),
        'ricette': db.session.scalar(db.select(db.func.count()).select_from(Recipe)),
        'likes': db.session.scalar(db.select(db.func.count()).select_from(Like)),
        'categorie': db.session.scalar(db.select(db.func.count()).select_from(Category))
    }
    
    # 2. UTENTI
    utenti_obj_list = db.session.execute(
        db.select(User).order_by(User.data_registrazione.desc())
    ).scalars().all()

    # 3. RICETTE (QUERY PRINCIPALE)
    ricette_query = db.session.execute(
        db.select(
            Recipe.id.label('id_ricetta'),
            Recipe.title.label('titolo_ricetta'),
            Recipe.creation_date.label('data_creazione_ricetta'),
            Recipe.description.label('descrizione'),
            Recipe.filename.label('filename'),
            User.username.label('autore_nome'),
            Category.name.label('categoria_nome'),
            db.func.count(Like.user_id).label('num_likes')
        )
        .join(User, Recipe.author_id == User.id)
        .outerjoin(Category, Recipe.category_id == Category.id)
        .outerjoin(Like, Recipe.id == Like.recipe_id)
        .group_by(
            Recipe.id, User.username, Category.name, 
            Recipe.title, Recipe.creation_date, Recipe.description, Recipe.filename
        )
        .order_by(Recipe.creation_date.desc())
    ).all()
    
    ricette = []
    for row in ricette_query:
        # --- CORREZIONE CHIAVE: Uso la nuova funzione di utility ---
        data_formattata = formatta_data_safe(row.data_creazione_ricetta, '%d/%m/%Y')
        ricette.append({
            'id_ricetta': row.id_ricetta,
            'titolo_ricetta': row.titolo_ricetta,
            'data_creazione_ricetta': data_formattata,
            'descrizione': row.descrizione,
            'filename': row.filename,
            'autore': row.autore_nome,
            'categoria': row.categoria_nome,
            'num_likes': row.num_likes if row.num_likes else 0
        })

    # 4. GESTIONE CATEGORIE (Per la tabella categorie)
    categorie_db = db.session.execute(db.select(Category)).scalars().all()
    categoria_stats = []
    for cat in categorie_db:
        ricette_associate = db.session.scalar(
            db.select(db.func.count(Recipe.id))
            .where(Recipe.category_id == cat.id)
        )
        categoria_stats.append({
            'id': cat.id,
            'name': cat.name,
            'ricette_associate': ricette_associate if ricette_associate else 0
        })
        
    # 5. DETTAGLIO LIKE
    
    # Top 10 ricette per like
    ricette_top_like_query = db.session.execute(
        db.select(
            Recipe.id.label('id_ricetta'),
            Recipe.title.label('titolo_ricetta'),
            db.func.count(Like.id_like).label('num_likes')
        )
        .outerjoin(Like, Recipe.id == Like.id_ricetta)
        .group_by(Recipe.id, Recipe.title)
        .order_by(db.desc(db.func.count(Like.id_like)))
        .limit(10)
    ).all()
    ricette_top_like = []
    for row in ricette_top_like_query:
        ricette_top_like.append({ 
            'id_ricetta': row._mapping['id_ricetta'],
            'titolo_ricetta': row._mapping['titolo_ricetta'],
            'num_likes': row._mapping['num_likes']
        })

    # Ultimi 50 like registrati
    ultimi_like_query = db.session.execute(
        db.select(
            Like.timestamp,
            User.username.label('utente_nome'),
            Recipe.title.label('ricetta_titolo'),
            Recipe.id.label('id_ricetta') 
        )
        .join(User, Like.id_utente == User.id)
        .join(Recipe, Like.id_ricetta == Recipe.id)
        .order_by(Like.timestamp.desc())
        .limit(50)
    ).all()
   


    ultimi_like_registrati = []
    for row in ultimi_like_query:
        # --- CORREZIONE CHIAVE: Uso la nuova funzione di utility per il timestamp ---
        timestamp_formattato = formatta_data_safe(row._mapping['timestamp'], '%d/%m/%Y %H:%M')
        ultimi_like_registrati.append({
            'timestamp': timestamp_formattato,
            'utente': row._mapping['utente_nome'],
            'ricetta': row._mapping['ricetta_titolo'],
            'id_ricetta': row._mapping['id_ricetta'] 
        })
    
    # 6. RENDERING
    return render_template('dashboard_admin.html',
                           stats = stats,
                           ricette = ricette,
                           utenti = utenti_obj_list,
                           current_user = current_user,
                           categoria_form = categoria_form,
                           categoria_per_tabella = categoria_stats,
                           ricette_top_like = ricette_top_like, 
                           ultimi_like_registrati = ultimi_like_registrati 
                           )

#elimina categoria
@app.route('/elimina_categoria/<int:id_categoria>', methods=['POST'])
@login_required
@ruolo_richiesto(['admin']) # Usiamo la tua funzione custom ruolo_richiesto
def elimina_categoria(id_categoria):
    """
    Gestisce la cancellazione di una categoria tramite richiesta POST (solo se non ha ricette).
    """
    # Usiamo db.session.get() per recuperare per ID
    categoria = db.session.get(Category, id_categoria) 

    if not categoria:
        flash(f'ERRORE: Categoria con ID {id_categoria} non trovata.', 'danger')
        return redirect(url_for('dashboard_admin') + '#gestione_categorie')

    # 1. Controllo di sicurezza: verifica che non ci siano ricette associate
    # Usiamo una query diretta per contare le ricette collegate in modo moderno
    ricette_count = db.session.scalar(
        db.select(db.func.count(Recipe.id)).where(Recipe.category_id == id_categoria)
    )
    
    # 2. SE CI SONO RICETTE, BLOCCA L'ELIMINAZIONE
    if ricette_count > 0:
        # Usiamo il nome corretto della categoria se esiste
        nome_categoria = getattr(categoria, 'name', 'Sconosciuta') 
        flash(f'ERRORE: Impossibile eliminare la categoria "{nome_categoria}". Ci sono {ricette_count} ricette collegate.', 'danger')
        # Reindirizza alla dashboard, mantenendo attiva la tab "Gestione Categorie"
        return redirect(url_for('dashboard_admin') + '#gestione_categorie')

    try:
        # 3. Elimina la categoria e committa la sessione
        nome_categoria = getattr(categoria, 'name', 'Sconosciuta') 
        db.session.delete(categoria)
        db.session.commit()
        flash(f'Categoria "{nome_categoria}" eliminata con successo.', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"ERRORE DB ELIMINAZIONE CATEGORIA: {e}")
        flash('Si è verificato un errore durante l\'eliminazione della categoria.', 'danger')

    # Reindirizza alla dashboard, mantenendo attiva la tab "Gestione Categorie"
    return redirect(url_for('dashboard_admin') + '#gestione_categorie')


    
@app.route('/elimina_utente/<int:id_utente>', methods=['POST'])
@login_required
@ruolo_richiesto(['admin'])
def elimina_utente(id_utente):
    """Elimina un utente dal DB SQLAlchemy (site.db)."""

    user = db.session.get(User, id_utente)
    if user:
        if user.id == session.get('id_utente'):
            flash('❌ Non puoi eliminare il tuo account mentre sei loggato.', 'error')
            return redirect(url_for('dashboard_admin'))
        try:
            db.session.execute(db.delete(Like).where(Like.user_id == id_utente))
            db.session.execute(db.delete(Recipe).where(Recipe.author_id == id_utente))
            db.session.delete(user)
            db.session.commit()
            flash(f'✅ Utente "{user.username}" eliminato con successo.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"ERRORE ELIMINAZIONE UTENTE: {e}")
            flash('❌ Errore durante l\'eliminazione dell\'utente.', 'error')
    else:
        flash(f'❌ Utente con ID {id_utente} non trovato.', 'error')
    return redirect(url_for('dashboard_admin'))

#AGGIUNGI CATEGORIA
@app.route('/aggiungi_categoria', methods=['POST'])
@login_required

@ruolo_richiesto(['admin'])
def aggiungi_categoria():
    """Gestisce l'aggiunta di una nuova categoria dalla dashboard admin."""
    
    # 1. Inizializza il form
    form = CategoriaForm()
    if form.validate_on_submit():
        nuovo_name = form.name.data
        esistente = Category.query.filter_by(name=nuovo_name).first()
        if esistente:
            flash(f'ERRORE: La categoria "{nuovo_name}" esiste già.', 'warning')
        else:
            try:
                nuova_categoria = Category(name=nuovo_name)
                db.session.add(nuova_categoria)
                db.session.commit()
                flash(f'Categoria "{nuovo_name}" aggiunta con successo!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'ERRORE del database durante l\'aggiunta: {e}', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'ERRORE in {field}: {error}', 'danger')
    return redirect(url_for('dashboard_admin', _anchor='categorie-gestione'))

#RIMUOVI CATEGORIA
@app.route('/delete_category/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    try:
        category_to_delete = Category.query.get_or_404(category_id)
        recipes_count = Recipe.query.filter_by(id_categoria=category_id).count()
        if recipes_count > 0:
            flash(f'ERRORE: Impossibile eliminare la categoria "{category_to_delete.nome}" perché ha {recipes_count} ricette associate.', 'danger')
        else:
            db.session.delete(category_to_delete)
            db.session.commit()
            flash(f'Categoria "{category_to_delete.nome}" eliminata con successo.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'ERRORE del database durante l\'eliminazione: {e}', 'danger')
    return redirect(url_for('dashboard_admin', _anchor='categorie-gestione'))

#modifica categoria
@app.route('/modifica_categoria/<int:id_categoria>', methods=['GET', 'POST'])
@login_required
@ruolo_richiesto(['admin'])
def modifica_categoria(id_categoria):
    id_categoria = request.form.get('id_categoria')
    # Recupera la categoria o restituisce un errore 404 se non esiste
    categoria = db.get_or_404(Category, id_categoria)
    
    # Crea un'istanza del form e pre-popola i dati
    form = CategoriaForm(obj=categoria)

    if form.validate_on_submit():
        # 1. Modifica i dati della categoria
        nuovo_nome = form.nome.data
        
        # 2. Controllo duplicati (escludendo se stesso)
        esistente = db.session.execute(
            db.select(Category).filter(
                Category.name == nuovo_nome,
                Category.id != id_categoria
            )
        ).scalar_one_or_none()

        if esistente:
            flash(f'ERRORE: Una categoria con nome "{nuovo_nome}" esiste già.', 'warning')
            return redirect(url_for('dashboard_admin', _anchor='categorie-tab'))
        
        try:
            # 3. Aggiorna il database
            categoria.name = nuovo_nome
            db.session.commit()
            flash(f'Categoria "{nuovo_nome}" modificata con successo!', 'success')
            return redirect(url_for('dashboard_admin', _anchor='categorie-tab'))
        except Exception as e:
            db.session.rollback()
            flash(f'ERRORE del database durante la modifica: {e}', 'danger')
            return redirect(url_for('dashboard_admin', _anchor='categorie-tab'))
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash('Errore nel campo "{field}": {error}', 'danger')
    # Per il metodo GET o se la validazione fallisce
    return render_template('dashboard_admin', _anchor='categorie-tab')

#modifica ricetta
@app.route('/modifica_ricetta/<int:id_ricetta>', methods=['GET', 'POST'])
@login_required
@ruolo_richiesto(['admin', 'user']) 
def modifica_ricetta(id_ricetta):
    # Recupero dati sessione
    logged_in_user_id_session = session.get('id_utente')
    logged_in_user_ruolo = session.get('ruolo')

    # Recupera la ricetta
    ricetta = db.session.scalar(db.select(Recipe).filter_by(id=id_ricetta))
    
    if ricetta is None:
        flash(f'❌ Ricetta non trovata (ID: {id_ricetta}).', 'error')
        if logged_in_user_ruolo == 'admin':
            return redirect(url_for('dashboard_admin'))
        return redirect(url_for('home'))
    
    # Preparazione per il Controllo di Autorizzazione
    is_admin = logged_in_user_ruolo == 'admin'

    # Conversione ID a intero per il confronto
    try:
        logged_in_user_id = int(logged_in_user_id_session)
    except (ValueError, TypeError):
        logged_in_user_id = None 
    
    # Controllo Autorizzazioni
    if not is_admin and (ricetta.author_id != logged_in_user_id):
        flash('❌ Non sei autorizzato a modificare questa ricetta.', 'error')
        return redirect(url_for('dettaglio_ricetta', id_ricetta=ricetta.id))
        
    # Prepara Form e Categorie
    categorie = db.session.scalars(db.select(Category)).all()
    form = EditRecipeForm()
    form.category.choices = [(c.id, c.name) for c in categorie]

    if form.validate_on_submit():
        try: 
            ricetta.title = form.title.data
            ricetta.description = form.description.data
            ricetta.category_id = form.category.data

            if form.photo.data:
                filename = secure_filename(form.photo.data.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                form.photo.data.save(save_path)
                ricetta.photo_path = filename

            db.session.commit()
            flash(f'✅ Ricetta "{ricetta.title}" aggiornata con successo!', 'success')
            if is_admin:
                return redirect(url_for('dashboard_admin'))
            else:
                return redirect(url_for('dettaglio_ricetta', id_ricetta=ricetta.id))
        except Exception as e:
            db.session.rollback()
            flash(f'❌ Errore durante l\'aggiornamento: {e}', 'error')
            print(f"ERRORE DB AGGIORNAMENTO: {e}")
            return redirect(url_for('modifica_ricetta', id_ricetta=ricetta.id))
    elif request.method == 'GET':
        form.title.data = ricetta.title
        form.description.data = ricetta.description
        form.category.data = ricetta.category_id
    
    return render_template('edit_recipe_page.html', 
                           title=f'Modifica Ricetta: {ricetta.title}',
                           form=form,
                           ricetta_id=ricetta.id)









#Modifica ruolo utente
@app.route('/modifica_ruolo/<int:id_utente>', methods=['POST'])
@login_required
@ruolo_richiesto(['admin'])
def modifica_ruolo(id_utente):
    """Modifica il ruolo di un utente nel DB SQLAlchemy (site.db)."""

    logged_in_user_id = current_user.id_utente
    user = db.session.scalar(db.select(User).filter_by(id_utente=id_utente))

    if user is None:
        flash('❌ Utente non trovato.', 'error')
        return redirect(url_for('dashboard_admin'))
    
    if user.id_utente == logged_in_user_id:
        flash("❌ Non puoi modificare il tuo ruolo mentre sei loggato come Admin.", 'warning')
        return redirect(url_for('dashboard_admin'))
    
    nuovo_ruolo = 'user' if user.ruolo == 'admin' else 'admin'
    username_per_flash = user.username
    try:
        user.ruolo = nuovo_ruolo
        db.session.commit()
        db.session.remove()
        flash(f'✅ Ruolo di "{username_per_flash}" modificato in "{nuovo_ruolo.upper()}" con successo!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'❌ Errore durante la modifica del ruolo: {e}', 'error')
        print(f"ERRORE DB MODIFICA RUOLO: {e}")

    return redirect(url_for('dashboard_admin'))
        
        
    

@app.route('/admin')
def admin_dashboard():
    
    # Dati fittizi necessari per far funzionare il template
    stats = {'utenti': 150, 'ricette': 420, 'likes': 3500, 'categorie': 12}
    ricette = [
        {'id_ricetta': 1, 'titolo_ricetta': 'Carbonara Perfetta', 'autore': 'Mario Rossi', 'categoria': 'Primi', 'data_creazione_ricetta': '2024-05-01', 'num_likes': 85},
        {'id_ricetta': 2, 'titolo_ricetta': 'Tiramisù Veloce', 'autore': 'Elena Bianchi', 'categoria': 'Dolci', 'data_creazione_ricetta': '2024-04-15', 'num_likes': 55},
    ]
    utenti = [
        {'id_utente': 1, 'nome_utente': 'admin_user', 'email': 'admin@example.com', 'ruolo': 'admin', 'data_registrazione': '2023-01-01'},
        {'id_utente': 2, 'nome_utente': 'normale_user', 'email': 'user@example.com', 'ruolo': 'user', 'data_registrazione': '2023-05-10'},
    ]
    return render_template('dashboard_admin.html', 
                            stats=stats, 
                            ricette=ricette, 
                            utenti=utenti,
                            csrf_token=fake_csrf_token() # Aggiungo un finto token per evitare errori Jinja
                        )
    
    
# -------------------------------
# Elimina Ricetta (Solo Admin)
# -------------------------------
@app.route('/elimina_ricetta/<int:id_ricetta>', methods=['POST'])
@login_required
@ruolo_richiesto(['admin'])
def elimina_ricetta(id_ricetta):
    """Elimina una ricetta dal DB SQLAlchemy (site.db)."""

    ricetta = db.session.get(Recipe, id_ricetta)
    if ricetta:
        try:
            db.session.execute(db.delete(Like).where(Like.recipe_id == id_ricetta))
            db.session.delete(ricetta)
            db.session.commit()
            flash(f'✅ Ricetta "{ricetta.title}" eliminata con successo.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"ERRORE DI ELIMINAZIONE RICETTA: {e}")
            flash('❌ Errore interno del server durante l\'eliminazione della ricetta.', 'error')
    else:
        flash(f"⚠️ Ricetta con ID {id_ricetta} non trovata.", "warning")
    return redirect(url_for('dashboard_admin'))
    
# -------------------------------
# Logout
# -------------------------------
@app.route('/logout')
def logout():
    """Effettua il logout utente."""
    session.clear()
    flash("👋 Logout effettuato correttamente.", "info")
    return redirect(url_for('login'))
#def allowed_file(filename):
#    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



# -------------------------------
# Nuova ricetta
# -------------------------------
@app.route('/nuova_ricetta', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def nuova_ricetta():
    """Aggiunge una nuova ricetta nel DB SQLite."""
    categorie_db_objects = db.session.execute(db.select(Category).order_by(Category.name)).scalars().all()
    categorie = [{
        'id_categoria': c.id, 
        'nome_categoria': c.name
    } for c in categorie_db_objects]
    if request.method == 'POST':
        titolo_input = request.form['titolo']
        descrizione_input = request.form['descrizione']
        category_id = request.form['id_categoria']
        id_autore = session['id_utente']
        
        titolo_pulito = bleach.clean(titolo_input, tags=[], attributes={}, strip=True)
        descrizione_per_db = bleach.clean(descrizione_input, tags=['b', 'i', 'p', 'a', 'br'], attributes={'a': ['href', 'title']}, strip=True)
        
        filename = None
        file = request.files.get('image')
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            try:
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            except Exception as e:
                app.logger.error(f"Errore nel salvataggio del file per utente {id_autore}: {e}")
                flash('⚠️ Errore nel caricamento dell\'immagine. La ricetta verrà salvata senza foto.', 'warning')
                filename = None
                
        try:
            nuova_ricetta_obj = Recipe(
                title=titolo_pulito, 
                description=descrizione_per_db, 
                author_id=id_autore, 
                category_id=category_id, 
                filename=filename
            )
            db.session.add(nuova_ricetta_obj)
            db.session.commit()
            flash('✅ Ricetta aggiunta con successo!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Errore nell'inserimento DB per utente {id_autore}: {e}")
            flash('⚠️ Errore imprevisto durante il salvataggio della ricetta.', 'error')
            return redirect(url_for('nuova_ricetta'))
            
    return render_template('nuova_ricetta.html', categorie=categorie)

# -------------------------------
# Dettaglio ricetta
# -------------------------------
@app.route('/dettaglio/<int:id_ricetta>')
@limiter.limit("150 per minute")
def dettaglio_ricetta(id_ricetta):
    """Mostra i dettagli di una ricetta dal DB SQLite."""
    query_result = db.session.execute(
        db.select(
            Recipe,
            User.username.label('autore_nome'),
            Category.name.label('categoria_nome'),
            func.count(Like.id_ricetta).label('num_likes')

        )
        .join(User, Recipe.id_autore == User.id_utente)
        .outerjoin(Category, Recipe.category_id == Category.id_categoria)
        .outerjoin(Like, Recipe.id_ricetta == Like.id_ricetta)
        .where(Recipe.id_ricetta == id_ricetta)
        .group_by(Recipe.id_ricetta, User.username, Category.name) # Aggiungo per evitare avvisi di aggregazione
    ).first()
    if not query_result:
        flash(f'⚠️ Ricetta non trovata (ID: {id_ricetta}).', 'warning')
        return redirect(url_for('home'))
    ricetta, autore_nome, categoria_nome, num_likes = query_result
    print("DEBUG autore_nome:", autore_nome)
    print("DEBUG categoria_nome:", categoria_nome)
    print("DEBUG num_likes:", num_likes)
    print("DEBUG ricetta:", ricetta)

    is_liked = False
    if 'id_utente' in session:
        is_liked = db.session.scalar(
            db.select(Like).filter_by(user_id=session['id_utente'], id_ricetta=id_ricetta)
        ) is not None
    dati_ricetta = {
        'id_ricetta': ricetta.id_ricetta,
        'titolo_ricetta': ricetta.title,
        'descrizione': ricetta.description,
        'filename': ricetta.filename,
        'nome_utente': autore_nome or 'Sconosciuto',     # ← chiave allineata
        'nome_categoria': categoria_nome or 'Altro',     # ← chiave allineata
        'num_likes': num_likes or 0,
        'is_liked': is_liked
    }
    from_page = request.args.get('from_page')
    return render_template('dettaglio_ricetta.html', ricetta=dati_ricetta, from_page=from_page)


#@app.route('/dashboard_admin')
#def dashboard_admin():
    # Top 10 ricette ordinate per numero di like
#    ricette_top_like = db.session.execute(
#        db.select(Recipe)
#        .order_by(Recipe.num_likes.desc())
#        .limit(10)
#    ).scalars().all()


    # Ultimi 50 like registrati
#    ultimi_like_registrati = db.session.execute(
#        db.select(Like)
#        .order_by(Like.timestamp.desc())
#        .limit(50)
#    ).scalars().all()

#    return render_template(
#        "dashboard_admin.html",   # il tuo unico file
#        ricette_top_like=ricette_top_like,
#        ultimi_like_registrati=ultimi_like_registrati
#    )

# -------------------------------
# Toggle like (AJAX)
# -------------------------------
@app.route('/like/<int:id_ricetta>', methods=['POST'])
@csrf.exempt
@limiter.limit("30 per hour")
def toggle_like(id_ricetta):
    """Aggiunge/rimuove un like nel DB SQLite."""
    if 'id_utente' not in session:
        return jsonify({'success': False, 'message': 'Devi fare login'}), 401

    id_utente = session['id_utente']
    try:
        existing_like = db.session.scalar(
            db.select(Like).filter_by(user_id=id_utente, recipe_id=id_ricetta)
        )
        if existing_like:
            db.session.delete(existing_like)
            is_liked = False
        else:
            new_like = Like(user_id=id_utente, recipe_id=id_ricetta)
            db.session.add(new_like)
            is_liked = True
        db.session.commit()
        total_likes = db.session.scalar(
            db.select(func.count(Like.recipe_id)).where(Like.recipe_id == id_ricetta)

        )
        return jsonify({'success': True, 'total_likes': total_likes, 'is_liked': is_liked})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Errore nel toggle like per ricetta {id_ricetta}, utente {id_utente}: {e}")
        return jsonify({'success': False, 'message': 'Errore interno del server'}), 500
    
    

    
    

    
# -------------------------------
# Mostra ricette per categoria
# -------------------------------
@app.route('/categorie/<nome_categoria>')
def mostra_categoria(nome_categoria):
    """Mostra tutte le ricette per una specifica categoria dal DB SQLite."""
    
    category_obj = db.session.scalar(db.select(Category).filter_by(name=nome_categoria))
    if not category_obj:
        flash(f'⚠️ Categoria "{nome_categoria}" non trovata.', 'warning')
        return redirect(url_for('home'))
        
    ricette_query = db.session.execute(
        db.select(Recipe, User.username.label('autore_nome'), func.count(Like.recipe_id).label('num_likes'))
        .join(User, Recipe.author_id == User.id)
        .outerjoin(Like, Recipe.id == Like.recipe_id)
        .where(Recipe.category_id == category_obj.id)
        .group_by(Recipe.id, User.username)
        .order_by(Recipe.title.asc())
    ).all()
    ricette = []
    for r, autore_nome, num_likes in ricette_query:
        ricette.append({
            'id_ricetta': r.id,
            'titolo_ricetta': r.title,
            'descrizione': r.description,
            'filename': r.filename,
            'autore_nome': autore_nome,
            'categoria_nome': nome_categoria,
            'num_likes': num_likes
        })
    return render_template('categoria.html', ricette=ricette, categoria_nome=nome_categoria)



    

#DIARIO RICETTE DASHBOARD PERSONALE
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
@limiter.limit("60 per minute")
def dashboard():
    """Mostra le ricette create dall'utente e quelle a cui ha messo like (DB SQLAlchemy)."""
    
    id_utente = session.get('id_utente')
    if not id_utente:
        # Se l'utente non è loggato, reindirizza (anche se @login_required dovrebbe gestirlo)
        flash('Sessione utente non trovata.', 'error')
        return redirect(url_for('login')) # Assumi che esista una rotta 'login'
    if request.method == 'POST':
        id_ricetta = int(request.form.get('id_ricetta'))
        existing_like = db.session.scalar(
            db.select(Like).filter_by(user_id=id_utente, recipe_id=id_ricetta)
        )
        if existing_like:
            db.session.delete(existing_like)
        else:
            nuovo_like = Like(user_id=id_utente, recipe_id=id_ricetta)
            db.session.add(nuovo_like)
        db.session.commit()
    

    # 1. Recupera le ricette create dall'utente loggato
    try:
        mie_ricette_query = db.session.execute(
            db.select(
                Recipe, 
                Category.name.label('categoria_nome'), 
                func.count(Like.recipe_id).label('num_likes')
            )
            .outerjoin(Category, Recipe.category_id == Category.id)
            .outerjoin(Like, Recipe.id == Like.recipe_id)
            .where(Recipe.author_id == id_utente)
            .group_by(Recipe.id, Category.name) # Aggiunto Category.name al group_by per compatibilità strict
            .order_by(Recipe.id.desc())
        ).all()
    except Exception as e:
        app.logger.error(f"Errore query 'mie ricette' per utente {id_utente}: {e}")
        flash('⚠️ Impossibile caricare le tue ricette.', 'error')
        mie_ricette_query = []

    ricette_mie = []
    for r, categoria_nome, num_likes in mie_ricette_query:
        # Nota: i nomi dei campi sono stati adattati al formato originale del tuo template (es. id_ricetta)
        ricette_mie.append({
            'id_ricetta': r.id,
            'titolo_ricetta': r.title,
            'descrizione': r.description,
            'filename': r.filename,
            'categoria_nome': categoria_nome or "N/A",
            'num_likes': num_likes or 0,
            'is_liked': True,
            'e_mia': True
        })

    # 2. Recupera le ricette a cui l'utente ha messo like
    try:
        ricette_likes_query = db.session.execute(
            db.select(
                Recipe, 
                User.username.label('autore_nome'), 
                Category.name.label('categoria_nome'), 
                func.count(Like.recipe_id).label('num_likes')
            )
            .join(Like, Recipe.id == Like.recipe_id)
            .join(User, Recipe.author_id == User.id) 
            .outerjoin(Category, Recipe.category_id == Category.id)
            .where(Like.user_id == id_utente)
            .group_by(Recipe.id, User.username, Category.name)
            .order_by(Recipe.id.desc())
        ).all()
    except Exception as e:
        app.logger.error(f"Errore query 'ricette piaciute' per utente {id_utente}: {e}")
        flash('⚠️ Impossibile caricare le ricette che ti sono piaciute.', 'error')
        ricette_likes_query = []

    ricette_like = []
    for r, autore_nome, categoria_nome, num_likes in ricette_likes_query:
        ricette_like.append({
            'id_ricetta': r.id,
            'titolo_ricetta': r.title,
            'descrizione': r.description,
            'filename': r.filename,
            'autore_nome': autore_nome,
            'categoria_nome': categoria_nome or "N/A",
            'num_likes': num_likes or 0,
            'is_liked': True,
            'e_mia': False
        })

    # Ora usiamo i risultati elaborati con SQLAlchemy
    return render_template('dashboard.html', ricette_mie=ricette_mie, ricette_like=ricette_like, id_utente=id_utente, csrf_token=fake_csrf_token())

# -------------------------------
# diario ricette dashboard personale
# -------------------------------
@app.route('/diario')
@login_required
@limiter.limit("60 per minute")
def diario_ricette():
    """Mostra le ricette create dall'utente e quelle a cui ha messo like (DB SQLite)."""
    
    # La logica è identica a '/dashboard', quindi la replichiamo qui per completare la rotta.
    
    id_utente = session.get('id_utente')
    if not id_utente:
        flash('Sessione utente non trovata.', 'error')
        return redirect(url_for('login')) 

    # 1. Recupera le ricette create dall'utente loggato
    try:
        mie_ricette_query = db.session.execute(
            db.select(
                Recipe, 
                Category.name.label('categoria_nome'), 
                func.count(Like.recipe_id).label('num_likes')
            )
            .outerjoin(Category, Recipe.category_id == Category.id)
            .outerjoin(Like, Recipe.id == Like.recipe_id)
            .where(Recipe.author_id == id_utente)
            .group_by(Recipe.id, Category.name)
            .order_by(Recipe.id.desc())
        ).all()
    except Exception as e:
        app.logger.error(f"Errore query 'mie ricette' per utente {id_utente}: {e}")
        flash('⚠️ Impossibile caricare le tue ricette.', 'error')
        mie_ricette_query = []

    ricette_mie = []
    for r, categoria_nome, num_likes in mie_ricette_query:
        ricette_mie.append({
            'id_ricetta': r.id,
            'titolo_ricetta': r.title,
            'descrizione': r.description,
            'filename': r.filename,
            'categoria_nome': categoria_nome or "N/A",
            'num_likes': num_likes
        })

    # 2. Recupera le ricette a cui l'utente ha messo like
    try:
        ricette_likes_query = db.session.execute(
            db.select(
                Recipe, 
                User.username.label('autore_nome'), 
                Category.name.label('categoria_nome'), 
                func.count(Like.recipe_id).label('num_likes')
            )
            .join(Like, Recipe.id == Like.recipe_id)
            .join(User, Recipe.author_id == User.id) 
            .outerjoin(Category, Recipe.category_id == Category.id)
            .where(Like.user_id == id_utente)
            .group_by(Recipe.id, User.username, Category.name)
            .order_by(Recipe.id.desc())
        ).all()
    except Exception as e:
        app.logger.error(f"Errore query 'ricette piaciute' per utente {id_utente}: {e}")
        flash('⚠️ Impossibile caricare le ricette che ti sono piaciute.', 'error')
        ricette_likes_query = []

    ricette_like = []
    for r, autore_nome, categoria_nome, num_likes in ricette_likes_query:
        ricette_like.append({
            'id_ricetta': r.id,
            'titolo_ricetta': r.title,
            'descrizione': r.description,
            'filename': r.filename,
            'autore_nome': autore_nome,
            'categoria_nome': categoria_nome or "N/A",
            'num_likes': num_likes
        })

    # Utilizza lo stesso template per la dashboard personale
    return render_template('dashboard.html', ricette_mie=ricette_mie, ricette_like=ricette_like, id_utente=id_utente)
    


def allowed_file(filename):
   
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -------------------------------
# Avvio app
# -------------------------------
import app2
if __name__ == '__main__':
    
    init_db(app, 'ricetta.db')
    
    app.run(debug=True)
