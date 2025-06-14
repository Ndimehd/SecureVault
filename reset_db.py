from app import create_app
from app.models import db
import os

def reset_database():
    """Supprime et recrée la base de données"""
    app = create_app()
    
    with app.app_context():
        # Supprimer toutes les tables
        db.drop_all()
        print("Tables supprimées")
        
        # Recréer toutes les tables
        db.create_all()
        print("Tables recréées avec succès!")

if __name__ == '__main__':
    # Supprimer le fichier de base de données s'il existe
    db_file = 'securevault.db'
    if os.path.exists(db_file):
        os.remove(db_file)
        print(f"Fichier {db_file} supprimé")
    
    reset_database()