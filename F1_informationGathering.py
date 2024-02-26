import subprocess


# Función para recolectar información con theHarvester
def ejecutar_theharvester(dominio):
    try:
        # Asegúrate de usar la ruta correcta a theHarvester.py
        comando = f"python3 theHarvester/theHarvester.py -d {dominio} -l {100} -b google"
        
        # Ejecutar el comando
        resultado = subprocess.check_output(comando, shell=True, text=True)
        
        return resultado
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar theHarvester: ", e)
        return str(e)