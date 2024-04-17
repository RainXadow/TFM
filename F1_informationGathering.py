import subprocess


# Función para recolectar información con theHarvester
def ejecutar_theharvester():
    try:
        dominio = input("Introduce el dominio para buscar información (ejemplo.com): ")
        buscador = input("Por favor, introduce el buscador que quieres usar (bing, yahoo, brave, github-code): ")

        # Pregunta al usuario cuántos resultados quiere buscar
        while True:
            limite = input("Por favor, introduce el número de resultados que quieres buscar: ")
            if limite.isdigit():
                break
            else:
                print("Por favor, introduce un número válido.")

        # Construir el comando para ejecutar theHarvester
        comando = f"theHarvester -d {dominio} -l {limite} -b {buscador}"
        
        # Ejecutar el comando y capturar la salida
        resultado = subprocess.run(comando, shell=True, text=True, capture_output=True)

        # Guardar el resultado en un archivo y mostrarlo en la consola
        nombre_archivo = f"TheHarvesterResults.txt"
        with open(nombre_archivo, 'w') as archivo:
            archivo.write(resultado.stdout)

        # Imprimir el resultado en la consola
        print('\n' + resultado.stdout + '\033[0m')

    except subprocess.CalledProcessError as e:
        print("Error al ejecutar theHarvester: ", e)
        return str(e)

# Función principal
def main():
    ejecutar_theharvester()