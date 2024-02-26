import socket

import F1_informationGathering
import F2_threatModeling
import F3_vulnerabilityAnalysis
import F4_exploitation
import menu


def main():
    # while True:
        # ip = input("Introduce la IP para el pentesting: ")
        # if es_ip_valida(ip):1
        #     break
        # else:
        #     print("IP no válida. Por favor, intenta de nuevo.")
    opcion = menu.menu()
    
    if opcion == '1':
        # dominio = input("Introduce el dominio para buscar información: ")
        F1_informationGathering.ejecutar_theharvester('www.zoonsuite.com')
    elif opcion == '2':
        F2_threatModeling.run()
    elif opcion == '3':
        F3_vulnerabilityAnalysis.run()
    elif opcion == '4':
        F4_exploitation.run()
    elif opcion == '5':
        print("Pentesting cancelado.")

def es_ip_valida(ip):
    partes = ip.split(".")
    if len(partes) != 4:
        return False
    for parte in partes:
        if not parte.isdigit():
            return False
        i = int(parte)
        if i < 0 or i > 255:
            return False
    return True

if __name__ == "__main__":
    main()