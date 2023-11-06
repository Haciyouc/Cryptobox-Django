# Cryptobox1

Ce projet est une boîte à outils polyvalente de cryptographie, offrant une gamme de fonctionnalités de chiffrement, de décryptage et d'analyse, ainsi que des outils pour la stéganographie. Les principales fonctionnalités de ce projet incluent :

1. **Chiffrement et Déchiffrement :** Ce projet propose des implémentations des algorithmes de chiffrement classiques, tels que le chiffre de César, le chiffre de décalage, le chiffre affine, et le chiffre du miroir. Vous pouvez utiliser ces outils pour chiffrer et déchiffrer des messages en toute sécurité.

2. **Attaques par Dictionnaire et Force Brute :** En plus du chiffrement, ce projet propose des outils pour effectuer des attaques par dictionnaire et de force brute sur les mots de passe chiffrés. Ces outils vous permettent d'évaluer la résistance de vos mots de passe chiffrés.

3. **Stéganographie :** Vous trouverez également des outils pour l'encodage et le décodage de données cachées dans des médias, tels que des images, des fichiers audio, ou des vidéos. La stéganographie est une technique permettant de dissimuler des informations secrètes dans des supports multimédias.

## Installation

Pour installer et exécuter ce projet, suivez les étapes suivantes :

1. Téléchargez et installez une version récente de Python 3 à partir de [Python.org](https://www.python.org/downloads/).

2. Créez un répertoire pour votre projet, par exemple "TP1", et naviguez dans ce répertoire.

3. Ouvrez un terminal de ligne de commande depuis ce répertoire.

4. Créez un environnement virtuel pour isoler les dépendances de packages localement en utilisant la commande suivante :
   - Sur Linux :  ```python -m venv env_name ```
   - Sur Windows :  ```python -m venv env_name ```

5. Activez l'environnement virtuel :
   - Sur Linux :  ```source env_name/bin/activate ```
   - Sur Windows :  ```env_name\Scripts\activate ```

6. Installez le framework Django dans l'environnement virtuel en utilisant la commande  ```pip install django ```.

7. Après avoir installé Django, placez le code téléchargé dans le même répertoire que l'environnement virtuel.

8. Utilisez les commandes suivantes pour vous déplacer dans le répertoire du projet et installer les dépendances à partir du fichier `requirements.txt` :
 ```cd ssadd  ```
 ```pip install -r requirements.txt ```


10. Synchronisez votre base de données pour la première fois avec la commande :  ```python manage.py migrate ```.

11. Créez un utilisateur initial nommé "admin" avec le mot de passe "password123" en utilisant la commande :
 ```
 python manage.py createsuperuser --email admin@exemple.com --username admin
 ```

11. Lancez le serveur Django sur une machine locale pour tester l'installation avec la commande : `python manage.py runserver`.

Si vous voyez le message "Starting development server at http://ip@:port/", l'installation s'est déroulée avec succès, et le serveur de développement est en cours d'exécution à l'adresse locale (par exemple : 127.0.0.1) et sur un certain port (par exemple : 8000).
