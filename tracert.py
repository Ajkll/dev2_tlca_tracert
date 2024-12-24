import argparse
import subprocess
import platform
import sys as s
from urllib.parse import urlsplit
import socket
import re

class UnsupportedOSError(Exception):
    pass

class NoValideIpFoundError(Exception):
    pass

def get_os_cmd(dst=None, tracert=False, ping=False):
    user_os = platform.system().lower()
    if ping:
        return ["ping", "-c", "1", dst] if user_os != "windows" else ["ping", dst]
    elif tracert:
        if user_os == "windows":
            return ["tracert", dst]
        elif user_os == "linux": 
            return ["traceroute", dst]
        else:
            raise UnsupportedOSError()
    else:
        raise ValueError("Commande invalide")

def is_valid_ip(arg_ip):
    try:
        socket.inet_aton(arg_ip) 
        return True
    except socket.error:
        return False

def extract_ips(subprocess_stdout_result,destination):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b' #chatgpt ma obtenue cette expression réguliére qui identifie la forme d'une ip valide dans un texte , l'explication de comment elle fonctionne est préciser dans le wiki!
    all_verified_ip = re.findall(ip_pattern, subprocess_stdout_result)  
    final_list_ip = [] 
    
    for ip in all_verified_ip:  
        if ip != destination: #j'ai exclue l'ip de base
            final_list_ip.append(ip) 

    return final_list_ip  


def is_output_file(tracert_liste_of_ip, output_file, open_mode="w"):
    if len(tracert_liste_of_ip) > 0 and output_file:
        with open(output_file, open_mode) as f:
            for line in tracert_liste_of_ip:
                f.write(line + "\n")
    else:
        NoValideIpFoundError() #on pourrais aussi avoir un erreur si le mode passer en argument existe pas
        


def is_progressive(command,destination, output_file=None):
    
    tracert_liste_of_ip = []
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as p:
        for line in p.stdout:
            liste_ip = extract_ips(line,destination)
            if liste_ip:
                for ip in liste_ip:
                    tracert_liste_of_ip.append(ip)
                    print(tracert_liste_of_ip)
        is_output_file(tracert_liste_of_ip, output_file, open_mode="a") #j'ai choisie de remplire le fichier de sortie que lorsque on a toute les ip


def traceroute(destination, progressive=False, output_file=None):
    try:
        result = get_os_cmd(dst=destination, tracert=True)
        if progressive:
            is_progressive(result,destination, output_file)
        else:
            final_result = subprocess.run(result, stdout=subprocess.PIPE, text=True)
            if final_result.returncode == 0:
                liste_ip = extract_ips(final_result.stdout,destination)
                tracert_liste_of_ip = []
                for ip in liste_ip:
                    tracert_liste_of_ip.append(ip)
                    print(tracert_liste_of_ip)
                is_output_file(liste_ip, output_file)
            else:
                print(f"Traceroute a echouer {final_result.stderr}")
    except UnsupportedOSError as e:
        print(e)
        s.exit(1)
    except subprocess.CalledProcessError:
        print("erreur dans le subprocess")
        s.exit(1)
    except Exception as e:
        print(e)
        s.exit(1)


def resolve_url_to_ip(url):
    try:
        ellaged_url = urlsplit(url)
        result = ellaged_url.netloc or ellaged_url.path  # Récupère le domaine proprement
        return socket.gethostbyname(result)

    except socket.gaierror:
        print(f"le domaine n'a pas pu etre resolu {url}")
        s.exit(1)
    except Exception as e:
        print(e)
        s.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Traceroute app Superhelper - vous aide a voir par ou passe vos demandes internet.")
    parser.add_argument("-t", "--target", type=str, required=True, help="l'adresse a contacter")
    parser.add_argument("-o", "--output-file", type=str, help="Fichier de sortie.")
    parser.add_argument("-p", "--progressive", action="store_true", help="progressive (affiche comme tracert).")
    parser.add_argument("-s", "--set", type=str, required=True, choices=["ip", "url"], help="ip ou url.")
    args = parser.parse_args()

    try:
        destination = args.target
        if args.set == "ip":
            if not is_valid_ip(destination):
                NoValideIpFoundError()
                s.exit(1)
        elif args.set == "url":
            result = resolve_url_to_ip(destination)
            if not result:
                NoValideIpFoundError()
                s.exit(1)
            print(f"url ip trouver: {result}")
            destination = result

        print("liste des ip :")
        traceroute(destination, progressive=args.progressive, output_file=args.output_file)

    except UnsupportedOSError as e:
        print(e)
        s.exit(1)
    except Exception as e:
        print(e)
        s.exit(1)

if __name__ == "__main__":
    main()
