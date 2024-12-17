import argparse
import subprocess
import platform
import sys as s
from urllib.parse import urlsplit
import socket

class UnsupportedOSError(Exception):
    pass

def get_os_cmd(ip=None, dst=None, tracert=False, ping=False):
    user_os = platform.system().lower()
    if ping:
        return ["ping", ip] if user_os == "windows" else ["ping", ip]
    elif tracert:
        if user_os == "windows":
            return ["tracert", dst]
        elif user_os == "linux": 
            return ["traceroute", dst]
        else:
            raise UnsupportedOSError()
    else:
        raise ValueError("rien n'a ete fourni")

def is_valid_ip(ip):
    try:
        cmd = get_os_cmd(ip=ip, ping=True)
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    except Exception as e:
        print(e)
        return False
    except subprocess.CalledProcessError:
        print("sub process echec")
        s.exit(1)

def traceroute(destination, progressive=False, output_file=None):
    try:
        result = get_os_cmd(dst=destination, tracert=True)
        if progressive:
            with subprocess.Popen(result, stdout=subprocess.PIPE, text=True) as process:
                for i, line in enumerate(process.stdout, start=1):
                    print(f"{i} - {line.strip()}")
                    if output_file:
                        with open(output_file, "a") as f:
                            f.write(line)
        else:
            final_result = subprocess.run(result, stdout=subprocess.PIPE, text=True)
            if final_result.returncode == 0:
                print(final_result.stdout)
                if output_file:
                    with open(output_file, "w") as f:
                        f.write(final_result.stdout)
            else:
                print(f"Traceroute: {final_result.stderr}")
    except UnsupportedOSError as e:
        print(e)
        s.exit(1)
    except subprocess.CalledProcessError:
        print("sub process echec")
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
        print(f"domaine {url} non resolu.")
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
                print("ip pas valide.")
                s.exit(1)
        elif args.set == "url":
            result = resolve_url_to_ip(destination)
            if not result:
                print(f"url:{destination} pas valide.")
                s.exit(1)
            print(f"url ip trouver: {result}")
            destination = result

        print(f"tentative de contacte {destination}")
        traceroute(destination, progressive=args.progressive, output_file=args.output_file)

    except UnsupportedOSError as e:
        print(e)
        s.exit(1)
    except Exception as e:
        print(e)
        s.exit(1)


if __name__ == "__main__":
    main()
