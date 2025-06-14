from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from .models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    otp_code = StringField('Code OTP (si activé)', validators=[Length(min=0, max=6)])

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de passe', validators=[
        DataRequired(), 
        Length(min=8, message='Le mot de passe doit contenir au moins 8 caractères')
    ])
    password_confirm = PasswordField('Confirmer le mot de passe', validators=[
        DataRequired(),
        EqualTo('password', message='Les mots de passe ne correspondent pas')
    ])

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Cette adresse email est déjà utilisée')

class EntryForm(FlaskForm):
    title = StringField('Titre', validators=[DataRequired(), Length(max=200)])
    entry_type = SelectField('Type', choices=[
        ('password', 'Mot de passe'),
        ('note', 'Note'),
        ('file', 'Fichier texte')
    ], validators=[DataRequired()])
    folder_id = SelectField('Dossier', coerce=int, validators=[])
    
    # Champs pour mot de passe
    username = StringField('Nom d\'utilisateur')
    password = PasswordField('Mot de passe')
    url = StringField('URL')
    
    # Champ pour note/fichier
    content = TextAreaField('Contenu')
    
    # Options de génération de mot de passe
    generate_password = BooleanField('Générer un mot de passe')
    password_length = IntegerField('Longueur', default=16)
    include_symbols = BooleanField('Inclure des symboles', default=True)

class FolderForm(FlaskForm):
    name = StringField('Nom du dossier', validators=[DataRequired(), Length(max=100)])
    parent_id = SelectField('Dossier parent', coerce=int, validators=[])

class ShareForm(FlaskForm):
    email = StringField('Email de l\'utilisateur', validators=[DataRequired(), Email()])
    permission = SelectField('Permission', choices=[
        ('read', 'Lecture seule'),
        ('write', 'Lecture et modification')
    ], validators=[DataRequired()])

    def validate_email(self, field):
        user = User.query.filter_by(email=field.data).first()
        if not user:
            raise ValidationError('Utilisateur non trouvé')

class OTPSetupForm(FlaskForm):
    otp_code = StringField('Code OTP', validators=[DataRequired(), Length(min=6, max=6)])

class MasterPasswordForm(FlaskForm):
    master_password = PasswordField('Mot de passe maître', validators=[DataRequired()])