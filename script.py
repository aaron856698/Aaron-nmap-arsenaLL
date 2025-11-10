#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import re
import platform
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)


def verificar_nmap():
    """Verifica si nmap está instalado en el sistema"""
    try:
        resultado = subprocess.run(
            ['nmap', '-V'], capture_output=True, text=True)
        return resultado.returncode == 0
    except FileNotFoundError:
        return False


def validar_ip_o_rango(objetivo):
    """Valida que sea IP o rango tipo CIDR (ej: 192.168.1.1 o 192.168.1.0/24)"""
    if not objetivo or not objetivo.strip():
        return False
    objetivo = objetivo.strip()
    # IP simple o CIDR
    patron = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    if not re.match(patron, objetivo):
        return False
    # validar octetos
    ip_base = objetivo.split('/')[0]
    octetos = ip_base.split('.')
    try:
        return all(0 <= int(o) <= 255 for o in octetos)
    except ValueError:
        return False


def limpiar_pantalla():
    os.system('clear' if os.name == 'posix' else 'cls')


def mostrar_banner():
    """Muestra un banner más compacto con información del programa"""
    # Intentar usar el banner pequeño primero, si no existe usar el grande
    archivos_banner = ['imagenBaner/ascii-art-small.txt',
                       'imagenBaner/ascii-art.txt']
    banner_encontrado = False

    for archivo_banner in archivos_banner:
        try:
            with open(archivo_banner, 'r') as archivo:
                lineas_banner = archivo.readlines()
            banner_encontrado = True
            break
        except FileNotFoundError:
            continue

    # Imprimir título y separador
    print(Fore.BLUE + "═" * 60)
    print(Fore.LIGHTCYAN_EX + Style.BRIGHT +
          "            🐧 NMAP AUTOMATIZADO - ESCANEO AUTOMÁTICO")

    # Imprimir banner si se encontró
    if banner_encontrado:
        for linea in lineas_banner:
            print(Fore.WHITE + linea.rstrip())

    # Imprimir información del autor y separador final
    print(Fore.YELLOW + "            🛠️ Hecho por: Aaron David G - 🇦🇷 Argentino")
    print(Fore.BLUE + "═" * 60)


def mostrar_menu():
    print("\n🔍 Opciones de escaneo:")
    print("1  - Escaneo de puertos abiertos")
    print("2  - Detección de servicios y versiones")
    print("3  - Detección de sistema operativo")
    print("4  - Escaneo completo (puertos + OS + servicios)")
    print("5  - Buscar vulnerabilidades (scripts vuln)")
    print("6  - Listar todas las IPs con sistema operativo detectado (archivo)")
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
    print("19 - Detección de hosts activos (ping scan)")
    print("20 - Escaneo con scripts de exploits (SOLO lista, no ejecuta exploits)")
    print("21 - Escaneo profundo de una IP (modo laboratorio, sin explotación)")
    print("22 - Descubrir dispositivos activos en red local")
    print("23 - MODO LAB: pasos seguros para pruebas (no ejecutar exploits)")


def ejecutar_nmap(comando, timeout=3600):
    """Ejecuta un comando nmap con manejo de errores y devuelve stdout"""
    # En Windows no usamos sudo; si el comando trae 'sudo ' lo quitamos
    if platform.system() == 'Windows':
        comando = comando.replace('sudo ', '')

    print(Fore.CYAN + f"\n📡 Ejecutando: {comando}\n")
    try:
        resultado = subprocess.run(
            comando, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(Fore.RED + "❌ Error: ejecución del comando excedió el tiempo límite.")
        return ""
    except Exception as e:
        print(Fore.RED + f"❌ Error al ejecutar el comando: {e}")
        return ""

    # Mostrar stderr si hay código de retorno != 0
    if resultado.returncode != 0:
        if resultado.stderr:
            print(Fore.RED + resultado.stderr)
        else:
            print(
                Fore.RED + f"❌ El comando finalizó con código {resultado.returncode}.")
    # Mostrar stdout si lo hay
    if resultado.stdout:
        print(Fore.GREEN + resultado.stdout)

    return resultado.stdout or ""


def analizar_salida_nmap(salida):
    """Parseo ligero: contar líneas con 'open' y buscar marcas de vulnerabilidad"""
    puertos_abiertos = []
    vulnerabilidades = []
    for linea in salida.splitlines():
        low = linea.lower()
        # buscar líneas de tipo '22/tcp open ssh'
        if "open" in low and "/" in linea:
            partes = linea.split()
            if partes:
                puertos_abiertos.append(partes[0])
        # detecciones obvias
        if "vulnerable" in low or "cve" in linea.upper():
            vulnerabilidades.append(linea.strip())

    return puertos_abiertos, vulnerabilidades


def mostrar_resumen(objetivo, puertos_abiertos, vulnerabilidades):
    """Muestra un resumen legible del escaneo en consola."""
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(Fore.BLUE + "\n" + "-" * 60)
    print(Fore.LIGHTWHITE_EX + Style.BRIGHT +
          f"📊 Resumen final del escaneo — {ahora}")
    print(Fore.LIGHTWHITE_EX + f"🔎 Objetivo: {objetivo}")
    print(Fore.YELLOW +
          f"🔓 Puertos abiertos detectados: {len(puertos_abiertos)}")
    if puertos_abiertos:
        # join con comas pero limitar si hay muchísimos
        lista_mostrar = puertos_abiertos[:50]
        print(Fore.WHITE + "📍 Lista: " + ", ".join(lista_mostrar))
        if len(puertos_abiertos) > 50:
            print(Fore.WHITE + f"   ...(+{len(puertos_abiertos)-50} más)")
    else:
        print(Fore.WHITE + "📍 Lista: (ninguno)")

    print(Fore.RED + f"🚨 Vulnerabilidades detectadas: {len(vulnerabilidades)}")
    if vulnerabilidades:
        for vuln in vulnerabilidades:
            # mostrar las primeras 10 con truncado si son muy largas
            print(Fore.WHITE + "   - " +
                  (vuln if len(vuln) <= 200 else vuln[:197] + "..."))
        if len(vulnerabilidades) > 10:
            print(Fore.WHITE + f"   ...(+{len(vulnerabilidades)-10} más)")
    else:
        print(Fore.WHITE + "   - (ninguna detectada)")

    print(Fore.BLUE + "-" * 60 + "\n")


def cargar_ips():
    ruta = 'direcciones_ip.txt'
    if os.path.exists(ruta):
        with open(ruta, 'r') as archivo:
            return [ip.strip() for ip in archivo if ip.strip()]
    else:
        return []


def pedir_objetivo(prompt_message="Ingresá IP o rango (ej: 192.168.1.1 o 192.168.1.0/24): "):
    objetivo = input(prompt_message).strip()
    if not objetivo:
        print(Fore.RED + "⚠️ Objetivo vacío. Operación cancelada.")
        return None
    return objetivo


def main():
    if not verificar_nmap():
        print(Fore.RED + "❌ Error: nmap no está instalado en el sistema.")
        print(Fore.YELLOW + "Instalá nmap y volvé a ejecutar el script.")
        return

    limpiar_pantalla()
    mostrar_banner()

    while True:
        mostrar_menu()
        opcion = input("👉 Elegí una opción (1-23): ").strip()

        # Para cada opción que ejecuta nmap, llamamos a ejecutar_nmap(), luego analizamos
        # y mostramos resumen con mostrar_resumen(objetivo, puertos, vulns)

        if opcion == '1':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -p- {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '2':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -sV {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '3':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -O {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '4':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -A -p- {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '5':
            objetivo = pedir_objetivo(
                "📝 Ingresá la IP/rango para buscar vulnerabilidades: ")
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap --script vuln {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '6':
            lista_ips = cargar_ips()
            if not lista_ips:
                print(
                    Fore.RED + "⚠️ No se encontró el archivo direcciones_ip.txt o está vacío.")
            else:
                for ip in lista_ips:
                    if validar_ip_o_rango(ip):
                        salida = ejecutar_nmap(f"nmap -O {ip}")
                        pa, vulns = analizar_salida_nmap(salida)
                        mostrar_resumen(ip, pa, vulns)

        elif opcion == '7':
            print(Fore.YELLOW + "👋 Saliendo del escáner. ¡Hasta luego!")
            break

        elif opcion == '8':
            ip_manual = pedir_objetivo(
                "📝 Ingresá la IP que querés analizar por vulnerabilidades: ")
            if ip_manual and validar_ip_o_rango(ip_manual):
                salida = ejecutar_nmap(f"nmap --script vuln {ip_manual}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(ip_manual, pa, vulns)
            else:
                print(
                    Fore.RED + "❌ IP inválida. Usa el formato correcto (ej: 192.168.1.1)")

        elif opcion == '9':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -sS -p- {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '10':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -sU {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '11':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -F {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '12':
            objetivo = pedir_objetivo(
                "📍 Ingresá la IP/rango para traceroute: ")
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap --traceroute {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '13':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -sC {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '14':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -sV --version-all {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '15':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -sA {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '16':
            rango = pedir_objetivo(
                "📍 Ingresá el rango de red (ej: 192.168.1.0/24): ")
            if rango and validar_ip_o_rango(rango):
                salida = ejecutar_nmap(f"nmap -sn {rango}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(rango, pa, vulns)

        elif opcion == '17':
            objetivo = pedir_objetivo()
            if objetivo and validar_ip_o_rango(objetivo):
                puertos = input(
                    "🔢 Ingresá los puertos separados por coma (ej: 21,22,80,443): ").strip()
                if puertos:
                    salida = ejecutar_nmap(f"nmap -p {puertos} {objetivo}")
                    pa, vulns = analizar_salida_nmap(salida)
                    mostrar_resumen(objetivo, pa, vulns)
                else:
                    print(
                        Fore.RED + "⚠️ No se ingresaron puertos. Operación cancelada.")

        elif opcion == '18':
            objetivo = pedir_objetivo(
                "📍 Ingresá la IP para guardar resultados: ")
            if objetivo and validar_ip_o_rango(objetivo):
                safe_name = objetivo.replace('/', '_').replace(':', '_')
                salida = ejecutar_nmap(
                    f"nmap -oN resultado_{safe_name}.txt {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)
                print(Fore.YELLOW +
                      f"✅ Resultados guardados en resultado_{safe_name}.txt")
            else:
                print(Fore.RED + "❌ IP inválida.")

        elif opcion == '19':
            objetivo = pedir_objetivo("📍 Ingresá IP o rango para ping scan: ")
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -sn {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '20':
            objetivo = pedir_objetivo(
                "📍 Ingresá la IP para analizar con scripts (NO ejecuta exploits): ")
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(
                    f"nmap --script \"default,vuln\" {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '21':
            objetivo = pedir_objetivo(
                "🧠 Ingresá la IP para escaneo profundo (modo laboratorio): ")
            if objetivo and validar_ip_o_rango(objetivo):
                salida = ejecutar_nmap(f"nmap -p- -sV -sC -A -Pn {objetivo}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(objetivo, pa, vulns)

        elif opcion == '22':
            rango_red = pedir_objetivo(
                "🌐 Ingresá el rango de red (ej: 192.168.0.0/24): ")
            if rango_red and validar_ip_o_rango(rango_red):
                salida = ejecutar_nmap(f"nmap -sn {rango_red}")
                pa, vulns = analizar_salida_nmap(salida)
                mostrar_resumen(rango_red, pa, vulns)

        elif opcion == '23':
            # Rechazo la ejecución de exploits; mostramos pasos seguros para laboratorio.
            print(Fore.YELLOW + "⚠️ MODO LAB (información segura):")
            print(
                Fore.WHITE + "- No ejecutar exploits contra sistemas de terceros sin permiso.")
            print(Fore.WHITE + "- Para pruebas en laboratorio, crea máquinas virtuales aisladas (ej: VirtualBox, Vagrant).")
            print(Fore.WHITE + "- Pasos sugeridos:")
            print(
                Fore.WHITE + "  1) Montá una VM víctima con software vulnerable intencionalmente.")
            print(
                Fore.WHITE + "  2) Desde tu VM atacante, ejecutá nmap para recolectar información.")
            print(
                Fore.WHITE + "  3) Analizá resultados y documentá (sin automatizar exploits).")
            print(
                Fore.WHITE + "  4) Aprendé a aplicar parches y mitigaciones en la VM víctima.")

        else:
            print(Fore.RED + "❌ Opción inválida. Elegí un número del 1 al 23.")


if __name__ == "__main__":
    main()
