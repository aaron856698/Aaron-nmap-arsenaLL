import subprocess
import os
from colorama import init, Fore, Style

init(autoreset=True)


def limpiar_pantalla():
    os.system('clear' if os.name == 'posix' else 'cls')


def mostrar_banner():
    print(Fore.WHITE + """
        .--.                      ███╗   ██╗███╗   ███╗ █████╗ ██████╗
       |o_o |                    ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
       |:_/ |                    ██╔██╗ ██║██╔████╔██║███████║██████╔╝
      //   \ \                   ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝
     (|     | )                  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║
    /'\_   _/`\                  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
    \___)=(___/
""")
    print(Fore.LIGHTCYAN_EX + Style.BRIGHT +
          "🐧 NMAP AUTOPATIZADO - ESCANEO AUTOMÁTICO")
    print(Fore.YELLOW + "🛠️ Echo por: Aaron David - 🇦🇷 Argentino")


def mostrar_menu():
    print("\n🔍 Opciones de escaneo:")
    print("1  - Escaneo de puertos abiertos")
    print("2  - Detección de servicios y versiones")
    print("3  - Detección de sistema operativo")
    print("4  - Escaneo completo (puertos + OS + servicios)")
    print("5  - Buscar vulnerabilidades")
    print("6  - Listar todas las IPs con sistema operativo detectado")
    print("7  - Salir")
    print("8  - Ingresar IP manualmente y buscar vulnerabilidades")
    print("9  - Escaneo silencioso (stealth scan)")
    print("10 - Escaneo UDP")
    print("11 - Escaneo rápido (100 puertos comunes)")
    print("12 - Traceroute")
    print("13 - Scripts NSE básicos")
    print("14 - Detección agresiva de versiones")
    print("15 - Detección de firewall y filtrado")
    print("16 - Descubrir IPs activas en red")
    print("17 - Escaneo de puertos específicos")
    print("18 - Guardar resultados en archivo")
    print("19 - Detección de MAC")
    print("20 - Escaneo de exploits")


def ejecutar_nmap(comando):
    print(Fore.CYAN + f"\n📡 Ejecutando: {comando}\n")
    resultado = subprocess.run(
        comando, shell=True, capture_output=True, text=True)
    print(Fore.GREEN + resultado.stdout)


def cargar_ips():
    ruta = 'direcciones_ip.txt'
    if os.path.exists(ruta):
        with open(ruta, 'r') as archivo:
            return [ip.strip() for ip in archivo if ip.strip()]
    else:
        return []


def main():
    limpiar_pantalla()
    mostrar_banner()

    while True:
        mostrar_menu()
        opcion = input("👉 Elegí una opción (1-20): ")

        if opcion == '1':
            ejecutar_nmap("nmap -p-")
        elif opcion == '2':
            ejecutar_nmap("nmap -sV")
        elif opcion == '3':
            ejecutar_nmap("nmap -O")
        elif opcion == '4':
            ejecutar_nmap("nmap -A -p-")
        elif opcion == '5':
            ejecutar_nmap("nmap --script vuln")
        elif opcion == '6':
            lista_ips = cargar_ips()
            if not lista_ips:
                print(
                    Fore.RED + "⚠️ No se encontró el archivo direcciones_ip.txt o está vacío.")
            else:
                for ip in lista_ips:
                    print(Fore.MAGENTA + f"\n🔍 IP: {ip}")
                    ejecutar_nmap(f"nmap -O {ip}")
        elif opcion == '7':
            print(Fore.YELLOW + "👋 Saliendo del escáner. ¡Hasta luego!")
            break
        elif opcion == '8':
            ip_manual = input(
                "📝 Ingresá la IP que querés analizar por vulnerabilidades: ")
            ejecutar_nmap(f"nmap --script vuln {ip_manual}")
        elif opcion == '9':
            ejecutar_nmap("sudo nmap -sS -p-")
        elif opcion == '10':
            ejecutar_nmap("nmap -sU")
        elif opcion == '11':
            ejecutar_nmap("nmap -F")
        elif opcion == '12':
            ejecutar_nmap("nmap --traceroute")
        elif opcion == '13':
            ejecutar_nmap("nmap -sC")
        elif opcion == '14':
            ejecutar_nmap("nmap -sV --version-all")
        elif opcion == '15':
            ejecutar_nmap("nmap -sA")
        elif opcion == '16':
            rango = input("📍 Ingresá el rango de red (ej: 192.168.1.0/24): ")
            ejecutar_nmap(f"nmap -sn {rango}")
        elif opcion == '17':
            puertos = input(
                "🔢 Ingresá los puertos separados por coma (ej: 21,22,80,443): ")
            ejecutar_nmap(f"nmap -p {puertos}")
        elif opcion == '18':
            ip_archivo = input("📍 Ingresá la IP para guardar resultados: ")
            ejecutar_nmap(f"nmap -oN resultado_{ip_archivo}.txt {ip_archivo}")
        elif opcion == '19':
            ejecutar_nmap("sudo nmap -sn")
        elif opcion == '20':
            ejecutar_nmap("nmap --script exploit")
        else:
            print(Fore.RED + "❌ Opción inválida. Elegí un número del 1 al 20.")


if __name__ == "__main__":
    main()
