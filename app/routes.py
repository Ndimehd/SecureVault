from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import db, User, Entry, Folder, SharedEntry, AuditLog, generate_password
from .forms import LoginForm, RegisterForm, EntryForm, FolderForm, ShareForm, OTPSetupForm, MasterPasswordForm
import pyotp
import qrcode
import io
import base64
import secrets
from datetime import datetime, timedelta
import json

main = Blueprint('main', __name__)

def log_audit(action, resource_type, resource_id=None, details=None):
    """Enregistre une action dans le journal d'audit"""
    audit = AuditLog(
        user_id=current_user.id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=details
    )
    db.session.add(audit)
    db.session.commit()

@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('login.html', form=LoginForm())

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            # Vérification 2FA si activée
            if user.is_2fa_enabled:
                if not form.otp_code.data:
                    flash('Code OTP requis', 'error')
                    return render_template('login.html', form=form)
                
                totp = pyotp.TOTP(user.totp_secret)
                if not totp.verify(form.otp_code.data):
                    flash('Code OTP invalide', 'error')
                    log_audit('LOGIN_FAILED_2FA', 'USER', user.id)
                    return render_template('login.html', form=form)
            
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_audit('LOGIN_SUCCESS', 'USER')
            
            # Demander le mot de passe maître
            return redirect(url_for('main.master_password'))
        else:
            flash('Email ou mot de passe incorrect', 'error')
            if user:
                log_audit('LOGIN_FAILED', 'USER', user.id)
    
    return render_template('login.html', form=form)

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Vérifier si l'utilisateur existe déjà
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Cette adresse email est déjà utilisée', 'error')
            return render_template('register.html', form=form)
        
        # Génération du salt unique
        salt = secrets.token_hex(16)
        
        user = User(
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data),
            salt=salt
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Compte créé avec succès', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('register.html', form=form)

@main.route('/master-password', methods=['GET', 'POST'])
@login_required
def master_password():
    form = MasterPasswordForm()
    if form.validate_on_submit():
        # Stocker la clé de chiffrement en session (temporairement)
        try:
            encryption_key = current_user.get_encryption_key(form.master_password.data)
            session['encryption_key'] = base64.b64encode(encryption_key).decode()
            session['last_activity'] = datetime.utcnow().isoformat()
            log_audit('MASTER_PASSWORD_VERIFIED', 'USER')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            flash('Mot de passe maître incorrect', 'error')
            log_audit('MASTER_PASSWORD_FAILED', 'USER')
    
    return render_template('verify_otp.html', form=form, title="Mot de passe maître")

@main.route('/dashboard')
@login_required
def dashboard():
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    # Récupérer les dossiers de l'utilisateur
    folders = Folder.query.filter_by(user_id=current_user.id, parent_id=None).all()
    
    # Récupérer les entrées sans dossier
    entries = Entry.query.filter_by(user_id=current_user.id, folder_id=None).all()
    
    # Récupérer les entrées partagées
    shared_entries = db.session.query(Entry).join(SharedEntry).filter(
        SharedEntry.user_id == current_user.id
    ).all()
    
    # Statistiques du tableau de bord
    stats = {
        'total_entries': Entry.query.filter_by(user_id=current_user.id).count(),
        'total_folders': Folder.query.filter_by(user_id=current_user.id).count(),
        'shared_entries': len(shared_entries),
        'recent_activity': AuditLog.query.filter_by(user_id=current_user.id)
                                       .order_by(AuditLog.timestamp.desc())
                                       .limit(5).all()
    }
    
    log_audit('DASHBOARD_ACCESS', 'DASHBOARD')
    
    return render_template('dashboard.html', 
                         folders=folders, 
                         entries=entries, 
                         shared_entries=shared_entries,
                         stats=stats)

@main.route('/folder/<int:folder_id>')
@login_required
def view_folder(folder_id):
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    folder = Folder.query.get_or_404(folder_id)
    
    # Vérifier que l'utilisateur est propriétaire du dossier
    if folder.user_id != current_user.id:
        flash('Accès refusé', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Récupérer les sous-dossiers
    subfolders = Folder.query.filter_by(parent_id=folder_id, user_id=current_user.id).all()
    
    # Récupérer les entrées du dossier
    entries = Entry.query.filter_by(folder_id=folder_id, user_id=current_user.id).all()
    
    # Construire le chemin de navigation
    breadcrumb = []
    current_folder = folder
    while current_folder:
        breadcrumb.insert(0, current_folder)
        current_folder = current_folder.parent
    
    log_audit('FOLDER_VIEWED', 'FOLDER', folder_id)
    
    return render_template('folder_view.html', 
                         folder=folder, 
                         subfolders=subfolders,
                         entries=entries,
                         breadcrumb=breadcrumb)

@main.route('/add-entry', methods=['GET', 'POST'])
@login_required
def add_entry():
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    form = EntryForm()
    
    # Peupler les choix de dossiers
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    form.folder_id.choices = [(0, 'Aucun dossier')] + [(f.id, f.name) for f in folders]
    
    if form.validate_on_submit():
        # Préparer les données selon le type
        if form.entry_type.data == 'password':
            password = form.password.data
            if form.generate_password.data:
                password = generate_password(
                    length=form.password_length.data or 16,
                    include_symbols=form.include_symbols.data
                )
            
            data = {
                'username': form.username.data,
                'password': password,
                'url': form.url.data,
                'notes': form.notes.data if hasattr(form, 'notes') else ''
            }
        else:
            data = {
                'content': form.content.data
            }
        
        # Créer l'entrée
        entry = Entry(
            title=form.title.data,
            entry_type=form.entry_type.data,
            user_id=current_user.id,
            folder_id=form.folder_id.data if form.folder_id.data != 0 else None
        )
        
        # Chiffrer les données
        encryption_key = base64.b64decode(session['encryption_key'])
        entry.encrypt_data(json.dumps(data), encryption_key)
        
        db.session.add(entry)
        db.session.commit()
        
        log_audit('ENTRY_CREATED', 'ENTRY', entry.id, f'Type: {entry.entry_type}')
        flash('Entrée créée avec succès', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('add_entry.html', form=form)

@main.route('/edit-entry/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    entry = Entry.query.get_or_404(entry_id)
    
    # Vérifier les permissions
    if entry.user_id != current_user.id:
        shared = SharedEntry.query.filter_by(
            entry_id=entry_id,
            user_id=current_user.id,
            permission='write'
        ).first()
        if not shared:
            flash('Accès refusé', 'error')
            return redirect(url_for('main.dashboard'))
    
    form = EntryForm(obj=entry)
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    form.folder_id.choices = [(0, 'Aucun dossier')] + [(f.id, f.name) for f in folders]
    
    if request.method == 'GET':
        # Déchiffrer et pré-remplir les données
        try:
            encryption_key = base64.b64decode(session['encryption_key'])
            decrypted_data = json.loads(entry.decrypt_data(encryption_key))
            
            if entry.entry_type == 'password':
                form.username.data = decrypted_data.get('username', '')
                form.password.data = decrypted_data.get('password', '')
                form.url.data = decrypted_data.get('url', '')
                if hasattr(form, 'notes'):
                    form.notes.data = decrypted_data.get('notes', '')
            else:
                form.content.data = decrypted_data.get('content', '')
        except Exception as e:
            flash('Erreur lors du déchiffrement', 'error')
            return redirect(url_for('main.dashboard'))
    
    if form.validate_on_submit():
        # Préparer les nouvelles données
        if form.entry_type.data == 'password':
            data = {
                'username': form.username.data,
                'password': form.password.data,
                'url': form.url.data,
                'notes': form.notes.data if hasattr(form, 'notes') else ''
            }
        else:
            data = {
                'content': form.content.data
            }
        
        # Chiffrer et sauvegarder
        encryption_key = base64.b64decode(session['encryption_key'])
        entry.encrypt_data(json.dumps(data), encryption_key)
        entry.title = form.title.data
        entry.folder_id = form.folder_id.data if form.folder_id.data != 0 else None
        
        db.session.commit()
        
        log_audit('ENTRY_UPDATED', 'ENTRY', entry.id)
        flash('Entrée mise à jour', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('edit_entry.html', form=form, entry=entry)

@main.route('/view-entry/<int:entry_id>')
@login_required
def view_entry(entry_id):
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    entry = Entry.query.get_or_404(entry_id)
    
    # Vérifier les permissions
    if entry.user_id != current_user.id:
        shared = SharedEntry.query.filter_by(
            entry_id=entry_id,
            user_id=current_user.id
        ).first()
        if not shared:
            flash('Accès refusé', 'error')
            return redirect(url_for('main.dashboard'))
    
    try:
        encryption_key = base64.b64decode(session['encryption_key'])
        decrypted_data = json.loads(entry.decrypt_data(encryption_key))
        
        log_audit('ENTRY_VIEWED', 'ENTRY', entry.id)
        
        return jsonify({
            'success': True,
            'title': entry.title,
            'type': entry.entry_type,
            'data': decrypted_data,
            'created_at': entry.created_at.isoformat() if entry.created_at else None,
            'updated_at': entry.updated_at.isoformat() if entry.updated_at else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Erreur de déchiffrement'})

@main.route('/delete-entry/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry = Entry.query.get_or_404(entry_id)
    
    if entry.user_id != current_user.id:
        flash('Accès refusé', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Supprimer les partages associés
    SharedEntry.query.filter_by(entry_id=entry_id).delete()
    
    db.session.delete(entry)
    db.session.commit()
    
    log_audit('ENTRY_DELETED', 'ENTRY', entry_id)
    flash('Entrée supprimée', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/add-folder', methods=['GET', 'POST'])
@login_required
def add_folder():
    form = FolderForm()
    
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    form.parent_id.choices = [(0, 'Aucun parent')] + [(f.id, f.name) for f in folders]
    
    if form.validate_on_submit():
        folder = Folder(
            name=form.name.data,
            user_id=current_user.id,
            parent_id=form.parent_id.data if form.parent_id.data != 0 else None
        )
        
        db.session.add(folder)
        db.session.commit()
        
        log_audit('FOLDER_CREATED', 'FOLDER', folder.id)
        flash('Dossier créé', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('add_folder.html', form=form)

@main.route('/edit-folder/<int:folder_id>', methods=['GET', 'POST'])
@login_required
def edit_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    
    if folder.user_id != current_user.id:
        flash('Accès refusé', 'error')
        return redirect(url_for('main.dashboard'))
    
    form = FolderForm(obj=folder)
    
    # Exclure le dossier lui-même et ses descendants des choix parents
    folders = Folder.query.filter_by(user_id=current_user.id).filter(Folder.id != folder_id).all()
    form.parent_id.choices = [(0, 'Aucun parent')] + [(f.id, f.name) for f in folders]
    
    if form.validate_on_submit():
        folder.name = form.name.data
        folder.parent_id = form.parent_id.data if form.parent_id.data != 0 else None
        
        db.session.commit()
        
        log_audit('FOLDER_UPDATED', 'FOLDER', folder.id)
        flash('Dossier mis à jour', 'success')
        return redirect(url_for('main.dashboard'))
    
    return render_template('edit_folder.html', form=form, folder=folder)

@main.route('/delete-folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    
    if folder.user_id != current_user.id:
        flash('Accès refusé', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Vérifier s'il y a des entrées ou sous-dossiers
    entries_count = Entry.query.filter_by(folder_id=folder_id).count()
    subfolders_count = Folder.query.filter_by(parent_id=folder_id).count()
    
    if entries_count > 0 or subfolders_count > 0:
        flash('Impossible de supprimer un dossier non vide', 'error')
        return redirect(url_for('main.dashboard'))
    
    db.session.delete(folder)
    db.session.commit()
    
    log_audit('FOLDER_DELETED', 'FOLDER', folder_id)
    flash('Dossier supprimé', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/share-entry/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def share_entry(entry_id):
    entry = Entry.query.get_or_404(entry_id)
    
    if entry.user_id != current_user.id:
        flash('Seul le propriétaire peut partager une entrée', 'error')
        return redirect(url_for('main.dashboard'))
    
    form = ShareForm()
    
    if form.validate_on_submit():
        target_user = User.query.filter_by(email=form.email.data).first()
        
        if not target_user:
            flash('Utilisateur non trouvé', 'error')
            return render_template('share_entry.html', form=form, entry=entry)
        
        if target_user.id == current_user.id:
            flash('Vous ne pouvez pas partager avec vous-même', 'error')
            return render_template('share_entry.html', form=form, entry=entry)
        
        # Vérifier si déjà partagé
        existing_share = SharedEntry.query.filter_by(
            entry_id=entry_id,
            user_id=target_user.id
        ).first()
        
        if existing_share:
            existing_share.permission = form.permission.data
            flash('Permissions mises à jour', 'success')
        else:
            share = SharedEntry(
                entry_id=entry_id,
                user_id=target_user.id,
                permission=form.permission.data,
                shared_by=current_user.id
            )
            db.session.add(share)
            flash('Entrée partagée avec succès', 'success')
        
        db.session.commit()
        
        log_audit('ENTRY_SHARED', 'ENTRY', entry_id, 
                 f'Shared with {target_user.email} with {form.permission.data} permission')
        return redirect(url_for('main.dashboard'))
    
    # Récupérer les partages existants
    shares = db.session.query(SharedEntry, User).join(User, SharedEntry.user_id == User.id)\
                      .filter(SharedEntry.entry_id == entry_id).all()
    
    return render_template('share_entry.html', form=form, entry=entry, shares=shares)

@main.route('/revoke-share/<int:entry_id>/<int:user_id>', methods=['POST'])
@login_required
def revoke_share(entry_id, user_id):
    entry = Entry.query.get_or_404(entry_id)
    
    if entry.user_id != current_user.id:
        flash('Seul le propriétaire peut révoquer un partage', 'error')
        return redirect(url_for('main.dashboard'))
    
    share = SharedEntry.query.filter_by(entry_id=entry_id, user_id=user_id).first()
    if share:
        db.session.delete(share)
        db.session.commit()
        
        log_audit('ENTRY_SHARE_REVOKED', 'ENTRY', entry_id, f'Revoked for user {user_id}')
        flash('Partage révoqué', 'success')
    
    return redirect(url_for('main.share_entry', entry_id=entry_id))

@main.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.is_2fa_enabled:
        flash('2FA déjà activée', 'info')
        return redirect(url_for('main.dashboard'))
    
    form = OTPSetupForm()
    
    if not current_user.totp_secret:
        # Générer un nouveau secret TOTP
        secret = pyotp.random_base32()
        current_user.totp_secret = secret
        db.session.commit()
    
    # Générer le QR code
    totp = pyotp.TOTP(current_user.totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="SecureVault"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code_data = base64.b64encode(buffer.getvalue()).decode()
    
    if form.validate_on_submit():
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(form.otp_code.data):
            current_user.is_2fa_enabled = True
            db.session.commit()
            
            log_audit('2FA_ENABLED', 'USER')
            flash('Authentification à deux facteurs activée', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Code OTP invalide', 'error')
    
    return render_template('setup_2fa.html', 
                         form=form, 
                         qr_code=qr_code_data,
                         secret=current_user.totp_secret)

@main.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    if not current_user.is_2fa_enabled:
        flash('2FA n\'est pas activée', 'info')
        return redirect(url_for('main.dashboard'))
    
    current_user.is_2fa_enabled = False
    current_user.totp_secret = None
    db.session.commit()
    
    log_audit('2FA_DISABLED', 'USER')
    flash('Authentification à deux facteurs désactivée', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        data = request.get_json()
        
        if 'email' in data:
            # Vérifier si l'email n'est pas déjà utilisé
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'success': False, 'error': 'Email déjà utilisé'})
            
            current_user.email = data['email']
            log_audit('PROFILE_EMAIL_UPDATED', 'USER')
        
        if 'password' in data and data['password']:
            current_user.password_hash = generate_password_hash(data['password'])
            log_audit('PROFILE_PASSWORD_UPDATED', 'USER')
        
        db.session.commit()
        return jsonify({'success': True})
    
    return render_template('profile.html')

@main.route('/search')
@login_required
def search():
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    query = request.args.get('q', '').strip()
    if not query:
        return render_template('search.html', entries=[], query='')
    
    # Rechercher dans les titres (non chiffrés)
    entries = Entry.query.filter(
        Entry.user_id == current_user.id,
        Entry.title.contains(query)
    ).all()
    
    # Ajouter les entrées partagées
    shared_entries = db.session.query(Entry).join(SharedEntry).filter(
        SharedEntry.user_id == current_user.id,
        Entry.title.contains(query)
    ).all()
    
    entries.extend(shared_entries)
    
    log_audit('SEARCH_PERFORMED', 'SEARCH', details=f'Query: {query}')
    
    return render_template('search.html', entries=entries, query=query)

@main.route('/audit-log')
@login_required
def audit_log():
    page = request.args.get('page', 1, type=int)
    per_page = 50

    logs = AuditLog.query.filter_by(user_id=current_user.id)\
                .order_by(AuditLog.timestamp.desc())\
                .paginate(page=page, per_page=per_page, error_out=False)

    return render_template('audit_log.html', logs=logs.items, pagination=logs)

@main.route('/export-data')
@login_required
def export_data():
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    # Récupérer toutes les entrées de l'utilisateur
    entries = Entry.query.filter_by(user_id=current_user.id).all()
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    
    export_data = {
        'export_date': datetime.utcnow().isoformat(),
        'user_email': current_user.email,
        'folders': [],
        'entries': []
    }
    
    # Exporter les dossiers
    for folder in folders:
        export_data['folders'].append({
            'id': folder.id,
            'name': folder.name,
            'parent_id': folder.parent_id,
            'created_at': folder.created_at.isoformat() if folder.created_at else None
        })
    
    # Exporter les entrées (déchiffrées)
    encryption_key = base64.b64decode(session['encryption_key'])
    for entry in entries:
        try:
            decrypted_data = json.loads(entry.decrypt_data(encryption_key))
            export_data['entries'].append({
                'id': entry.id,
                'title': entry.title,
                'type': entry.entry_type,
                'folder_id': entry.folder_id,
                'data': decrypted_data,
                'created_at': entry.created_at.isoformat() if entry.created_at else None,
                'updated_at': entry.updated_at.isoformat() if entry.updated_at else None
            })
        except Exception as e:
            continue  # Ignorer les entrées qui ne peuvent pas être déchiffrées
    
    log_audit('DATA_EXPORTED', 'USER')
    
    return jsonify(export_data)

@main.route('/generate-password-api')
@login_required
def generate_password_api():
    length = request.args.get('length', 16, type=int)
    include_symbols = request.args.get('symbols', 'true').lower() == 'true'

    password = generate_password(
        length=length, 
        include_symbols=include_symbols
    )
    return jsonify({'password': password})

@main.route('/check-password-strength')
@login_required
def check_password_strength():
    password = request.args.get('password', '')
    
    # Calcul simple de la force du mot de passe
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append('Utilisez au moins 8 caractères')
    
    if len(password) >= 12:
        score += 1
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append('Ajoutez des lettres majuscules')
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append('Ajoutez des lettres minuscules')
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append('Ajoutez des chiffres')
    
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        score += 1
    else:
        feedback.append('Ajoutez des caractères spéciaux')
    
    # Déterminer la force
    if score <= 2:
        strength = 'Faible'
        color = 'red'
    elif score <= 4:
        strength = 'Moyen'
        color = 'orange'
    elif score <= 5:
        strength = 'Fort'
        color = 'green'
    else:
        strength = 'Très fort'
        color = 'darkgreen'
    
    return jsonify({
        'score': score,
        'strength': strength,
        'color': color,
        'feedback': feedback
    })

@main.route('/backup-codes')
@login_required
def backup_codes():
    """Générer des codes de sauvegarde pour l'authentification"""
    if not current_user.is_2fa_enabled:
        flash('Activez d\'abord l\'authentification à deux facteurs', 'error')
        return redirect(url_for('main.setup_2fa'))
    
    # Générer 10 codes de sauvegarde
    codes = [secrets.token_hex(4).upper() for _ in range(10)]
    
    # Stocker les codes chiffrés (vous devriez les hasher en production)
    current_user.backup_codes = json.dumps([generate_password_hash(code) for code in codes])
    db.session.commit()
    
    log_audit('BACKUP_CODES_GENERATED', 'USER')
    
    return render_template('backup_codes.html', codes=codes)

@main.route('/verify-backup-code', methods=['POST'])
def verify_backup_code():
    """Vérifier un code de sauvegarde lors de la connexion"""
    data = request.get_json()
    email = data.get('email')
    code = data.get('backup_code')
    
    user = User.query.filter_by(email=email).first()
    if not user or not user.backup_codes:
        return jsonify({'success': False, 'error': 'Code invalide'})
    
    stored_codes = json.loads(user.backup_codes)
    
    # Vérifier si le code correspond à l'un des codes stockés
    for i, stored_code in enumerate(stored_codes):
        if check_password_hash(stored_code, code.upper()):
            # Supprimer le code utilisé
            stored_codes.pop(i)
            user.backup_codes = json.dumps(stored_codes)
            db.session.commit()
            
            log_audit('BACKUP_CODE_USED', 'USER', user.id)
            return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Code invalide'})

@main.route('/security-settings')
@login_required
def security_settings():
    """Page des paramètres de sécurité"""
    return render_template('security_settings.html')

@main.route('/change-master-password', methods=['GET', 'POST'])
@login_required
def change_master_password():
    """Changer le mot de passe maître et re-chiffrer toutes les données"""
    if request.method == 'POST':
        data = request.get_json()
        current_master = data.get('current_master_password')
        new_master = data.get('new_master_password')
        
        try:
            # Vérifier l'ancien mot de passe maître
            old_key = current_user.get_encryption_key(current_master)
            
            # Générer la nouvelle clé
            new_key = current_user.derive_key_from_password(new_master)
            
            # Re-chiffrer toutes les entrées
            entries = Entry.query.filter_by(user_id=current_user.id).all()
            
            for entry in entries:
                # Déchiffrer avec l'ancienne clé
                decrypted_data = entry.decrypt_data(old_key)
                # Re-chiffrer avec la nouvelle clé
                entry.encrypt_data(decrypted_data, new_key)
            
            # Mettre à jour le salt de l'utilisateur
            current_user.salt = secrets.token_hex(16)
            db.session.commit()
            
            # Mettre à jour la session
            session['encryption_key'] = base64.b64encode(new_key).decode()
            
            log_audit('MASTER_PASSWORD_CHANGED', 'USER')
            return jsonify({'success': True})
            
        except Exception as e:
            return jsonify({'success': False, 'error': 'Mot de passe maître actuel incorrect'})
    
    return render_template('change_master_password.html')

@main.route('/session-timeout')
@login_required
def session_timeout():
    """Endpoint pour vérifier le timeout de session"""
    if 'last_activity' not in session:
        return jsonify({'expired': True})
    
    last_activity = datetime.fromisoformat(session['last_activity'])
    timeout_minutes = 30  # Timeout après 30 minutes d'inactivité
    
    if datetime.utcnow() - last_activity > timedelta(minutes=timeout_minutes):
        session.pop('encryption_key', None)
        return jsonify({'expired': True})
    
    # Mettre à jour l'activité
    session['last_activity'] = datetime.utcnow().isoformat()
    return jsonify({'expired': False})

@main.route('/lock-vault')
@login_required
def lock_vault():
    """Verrouiller le coffre-fort (supprimer la clé de session)"""
    session.pop('encryption_key', None)
    log_audit('VAULT_LOCKED', 'USER')
    flash('Coffre-fort verrouillé', 'info')
    return redirect(url_for('main.master_password'))

@main.route('/duplicate-entry/<int:entry_id>', methods=['POST'])
@login_required
def duplicate_entry(entry_id):
    """Dupliquer une entrée existante"""
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    original_entry = Entry.query.get_or_404(entry_id)
    
    # Vérifier les permissions
    if original_entry.user_id != current_user.id:
        shared = SharedEntry.query.filter_by(
            entry_id=entry_id,
            user_id=current_user.id
        ).first()
        if not shared:
            flash('Accès refusé', 'error')
            return redirect(url_for('main.dashboard'))
    
    try:
        # Créer une copie de l'entrée
        new_entry = Entry(
            title=f"{original_entry.title} (Copie)",
            entry_type=original_entry.entry_type,
            user_id=current_user.id,
            folder_id=original_entry.folder_id,
            encrypted_data=original_entry.encrypted_data,
            iv=original_entry.iv
        )
        
        db.session.add(new_entry)
        db.session.commit()
        
        log_audit('ENTRY_DUPLICATED', 'ENTRY', new_entry.id, f'From entry {entry_id}')
        flash('Entrée dupliquée avec succès', 'success')
        
    except Exception as e:
        flash('Erreur lors de la duplication', 'error')
    
    return redirect(url_for('main.dashboard'))

@main.route('/move-entry/<int:entry_id>', methods=['POST'])
@login_required
def move_entry(entry_id):
    """Déplacer une entrée vers un autre dossier"""
    entry = Entry.query.get_or_404(entry_id)
    
    if entry.user_id != current_user.id:
        flash('Accès refusé', 'error')
        return redirect(url_for('main.dashboard'))
    
    data = request.get_json()
    new_folder_id = data.get('folder_id')
    
    if new_folder_id == 0:
        new_folder_id = None
    elif new_folder_id:
        # Vérifier que le dossier appartient à l'utilisateur
        folder = Folder.query.get(new_folder_id)
        if not folder or folder.user_id != current_user.id:
            return jsonify({'success': False, 'error': 'Dossier invalide'})
    
    old_folder_id = entry.folder_id
    entry.folder_id = new_folder_id
    db.session.commit()
    
    log_audit('ENTRY_MOVED', 'ENTRY', entry_id, 
             f'From folder {old_folder_id} to folder {new_folder_id}')
    
    return jsonify({'success': True})

@main.route('/recent-entries')
@login_required
def recent_entries():
    """Récupérer les entrées récemment modifiées"""
    if 'encryption_key' not in session:
        return redirect(url_for('main.master_password'))
    
    # Récupérer les 10 entrées les plus récentes
    recent = Entry.query.filter_by(user_id=current_user.id)\
                       .order_by(Entry.updated_at.desc())\
                       .limit(10).all()
    
    entries_data = []
    for entry in recent:
        entries_data.append({
            'id': entry.id,
            'title': entry.title,
            'type': entry.entry_type,
            'updated_at': entry.updated_at.isoformat() if entry.updated_at else None
        })
    
    return jsonify({'entries': entries_data})

@main.route('/logout')
@login_required
def logout():
    log_audit('LOGOUT', 'USER')
    logout_user()
    session.clear()
    flash('Déconnexion réussie', 'success')
    return redirect(url_for('main.login'))

# Auto-lock après inactivité
@main.before_request
def auto_lock():
    """Vérifier l'inactivité et verrouiller automatiquement"""
    if current_user.is_authenticated and 'encryption_key' in session:
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            timeout_minutes = 30  # Configurable
            
            if datetime.utcnow() - last_activity > timedelta(minutes=timeout_minutes):
                session.pop('encryption_key', None)
                flash('Session expirée par inactivité', 'warning')
                return redirect(url_for('main.master_password'))
        
        # Mettre à jour l'activité pour les requêtes non-AJAX
        # Correction : remplacer request.is_xhr par la vérification du header
        if not (request.headers.get('X-Requested-With') == 'XMLHttpRequest') and request.endpoint != 'main.session_timeout':
            session['last_activity'] = datetime.utcnow().isoformat()

# Gestionnaire d'erreurs
@main.errorhandler(404)
def not_found(error):
    return render_template('error.html', 
                         error_code=404, 
                         error_message="Page non trouvée"), 404

@main.errorhandler(403)
def forbidden(error):
    return render_template('error.html', 
                         error_code=403, 
                         error_message="Accès interdit"), 403

@main.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', 
                         error_code=500, 
                         error_message="Erreur interne du serveur"), 500

# Fonctions utilitaires
@main.route('/health')
def health_check():
    """Endpoint de santé pour le monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })