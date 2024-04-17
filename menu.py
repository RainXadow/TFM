def menu():
    while True:
        print("\nMenú de opciones:")
        print("1. Fase 1: Information Gathering")
        print("2. Fase 2: Threat Modeling")
        print("3. Fase 3, 4 y 5: Vulnerability Analysis, Explotation y Post-Explotation")
        print("4. Fase 6: Documentation")
        print("5. Cancelar")

        opcion = input("Selecciona una opción: ")

        if opcion in ['1', '2', '3', '4', '5']:
            return opcion
        else:
            print("Opción no válida. Por favor, intenta de nuevo.")