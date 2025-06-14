# SecureVault

SecureVault est une application sécurisée de gestion de notes chiffrées avec :

- Authentification à deux facteurs (2FA)
- Chiffrement de notes avec une clé unique par utilisateur 
- Journalisation des actions (audit log)
- Interface intuitive avec Bootstrap

> Projet réalisé dans le cadre du cours de Programmation Sécurisée (M1 SSI).

## Démarrer le projet

```bash
python -m venv venv
source .\venv\Scripts\activate 
pip install -r requirements.txt
python run.py