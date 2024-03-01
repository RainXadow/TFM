import F1_informationGathering
import F2_threatModeling
import F3_vulnerabilityAnalysis
import F4_exploitation
import menu


def main():
    while True:
        opcion = menu.menu()
        
        if opcion == '1':
            F1_informationGathering.main()
        elif opcion == '2':
            F2_threatModeling
        elif opcion == '3':
            F3_vulnerabilityAnalysis
        elif opcion == '4':
            F4_exploitation
        elif opcion == '5':
            print("Pentesting cancelado.")
            exit()
            
if __name__ == "__main__":
    main()