import subprocess

import shodan


# Función para recolectar información con theHarvester
def ejecutar_theharvester():
    try:
        dominio = input("Introduce el dominio para buscar información (ejemplo.com): ")
        # Pregunta al usuario qué buscador quiere usar
        buscador = input("Por favor, introduce el buscador que quieres usar (bing,yahoo,brave,github-code.): ")

        # Pregunta al usuario cuántos resultados quiere buscar
        while True:
            limite = input("Por favor, introduce el número de resultados que quieres buscar: ")
            if limite.isdigit():
                break
            else:
                print("Por favor, introduce un número válido.")

        # En Kali Linux, puedes ejecutar theHarvester directamente
        comando = f"theHarvester -d {dominio} -l {limite} -b {buscador}"
        
        # Ejecutar el comando
        resultado = subprocess.check_output(comando, shell=True, text=True)
        # Imprimir el resultado y restablecer el color de la consola
        print('\n' + resultado + '\033[0m')
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar theHarvester: ", e)
        return str(e)
            
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

# Función para solicitar una entrada numérica al usuarios
def solicitar_entrada_numerica(mensaje, opciones_validas):
    while True:
        respuesta = input(mensaje)
        if respuesta.isdigit() and int(respuesta) in opciones_validas:
            return int(respuesta)
        else:
            print(f"\nPor favor, introduce un número válido. Opciones válidas: {opciones_validas}\n")


# Función principal
def main():
    ejecutar_theharvester()