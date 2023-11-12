import re
import hashlib


def password_valider(pwd):
    return re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=]).{8}$', pwd)

def enregistrer():
    email=input("entrer votre email: ")
    pwd=input("entrer votre mot de passe: ")
    if password_valider(pwd):
        with open("enregistrement.txt", "a") as file:
            file.write(f"email: {email}, password:{pwd}\n")
        print("enregistrement reussi")
    else:
        print("le mot de passe ne respecte pas les criteres @;,ect...")

def authentifier():
    email=input("entrer votre email: ")
    pwd=input("entrer votre mot de passe: ")
    with open("enregistrement.txt", "r") as file:
        credential=file.read()
    if f"email: {email}, password: {pwd}\n" in credential:
        print("authentification reussie")
        return True
    else:
        print("authentification incorrecte, re_enregistrer")
        return False

def cesar_26_lettres():
    choisi=input("voulez vous chiffrer tapper(c) ou dechiffrer tapper(d): ")
    if choisi=='c':
        mot=input("entrer le mot a chiffrer: ")
        decalage=int(input("entrer le decalage: "))
        chiffre=""

        for char in mot:
            if char.isalpha():
                decalage_cesar=(ord(char)-ord('a')+decalage)%26+ord('a')
                chiffre+=chr(decalage_cesar)
            else:
                chiffre+=char
        print("mot chiffré: ",chiffre)
    elif choisi=='d':
        mot_chiffre=input("entrer le mot chiffré: ")
        decalage=int(input("entrer le decalage: "))
        mot_dechiffre=""
        for char in mot_chiffre:
            if char.isalpha():
                decalage_cesar=(ord(char)-ord('a')-decalage)%26+ord('a')
                mot_dechiffre+=chr(decalage_cesar)
            else:
                mot_dechiffre+=char
        print("mot dechiffré: ",mot_dechiffre)
    else:
        print("action non reconnue,,,entrez 'c' pour chiffrer ou 'd' pour dechiffrer.")

def cesar_ASCII():
    mot=input("entrer le mot: ")
    decalage=int(input("entrer le décalage: "))
    chiffre=""

    for char in mot:
        if char.isascii():
            decalage_cesar=(ord(char)+decalage)% 128
            chiffre+=chr(decalage_cesar)
        else:
            chiffre+=char
    print("Mot chiffré: ", chiffre)

def afficher_menu():
    while True:
        print("menu principal:")
        print("A- un mot a hacher")
        print("B- decalage par CESAR")
        print("C- collecter une DATASET")
        choix = input("selectionnez une option(A, B, C): ")
        if choix=="A" or choix=="a": 
            action = input("taper (1) haché le mot par sha256  OU  (2) attaquer par dictionnaire ? ")
            if action=="1":
                hacher_mot()
            elif action=="2":
                dictionary_attack()
        elif choix=="B" or choix=="b":
            action = input("taper (1) CESAR avec code ASCII   OU   (2) CESAR dans les 26 lettres  ? ")
            if action=="1":
                cesar_ASCII()
            elif action=="2":
                cesar_26_lettres() 
        elif choix=="C" or choix=="c":
            action=input("taper (1) pour dataset YFINANCE + courbe   OU   (2) pour dataset basic de votre choix: ")
            if action=='1':
                dataset_yfinance()
            elif action=='2':
                dataset_basic()
        else:
            print("option invalide, réessayer.")

def hacher_mot():
    import getpass
    mot=getpass.getpass("entrez le mot a hacher: ")
    hashed=hashlib.sha256(mot.encode()).hexdigest()
    print("mot haché: ",hashed)

def dictionary_attack():
    password_inserer = input("entrer le mot de passe a rechercher dans le dictionnaire: ")
    with open('dic.txt','r') as file:
        for ligne in file:
            password_in_dic=ligne.strip()
            password_hacher=hashlib.sha256(password_in_dic.encode()).hexdigest()
            if password_hacher==password_inserer:
                print(f"le mot de passe {password_inserer} a été trouver dans le dictionnaire")
                return password_inserer
    print(f"le mot de passe {password_inserer} n'a pas été trouver dans le dictionnaire")
    afficher_menu()
    return None
 
def dataset_basic():
    print("remplir une dataset : ")   
    dataset={} 
    while True:
        email=input("entrer l'adresse email de l'utilisateur (oubien) 'q' pour quitter): ")
        if email.lower()=='q':
            break 
        pwd=input("entrer le mot de passe de l'utilisateur: ")
        dataset[email]=pwd 
    print("DATASET collecté :")
    for email, pwd in dataset.items():
        print(f"email: {email}, password: {pwd}")

import yfinance as yf
import matplotlib.pyplot as plt
def dataset_yfinance():
    try:
        symbole='MSFT'# c pour microsoft
        data=yf.download(symbole, start='2022-10-01', end='2023-10-01')
        plt.plot(data.index,data['Close'])
        plt.title(f'cours de cloture pour {symbole}')
        plt.xlabel('date')
        plt.ylabel('cours de cloture')
        plt.show()
        data_dict=data.to_dict()
        print("dataset pour microsoft")
        print(data_dict)
        return data_dict
    except Exception as e:
        print(f"yfinance error:{str(e)}")
        return None
data_as_dict=dataset_yfinance()

est_authentifie=False
while not est_authentifie:
    print("1- enregistrement")
    print("2- authentification")
    choix = input("selectionner une option (1,2): ")
    if choix=="1":
        enregistrer()
    elif choix=="2":
        est_authentifie=authentifier()
        if not est_authentifie:
            print("authentification incorrecte, re_enregistrer")
    else:
        print("option invalide,réessayer")
if est_authentifie:
    afficher_menu()
