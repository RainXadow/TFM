import F1_informationGathering
import F2_threatModeling
import F6_Documentation
import F345_vulnerabilityAnalysis_Explotation_PostExplotation
import menu


def main():
    while True:
        opcion = menu.menu()
        
        if opcion == '1':
            F1_informationGathering.main()
        elif opcion == '2':
            F2_threatModeling.main()
        elif opcion == '3':
            F345_vulnerabilityAnalysis_Explotation_PostExplotation.main()
        elif opcion == '4':
            F6_Documentation.main()
        elif opcion == '5':
            print("Pentesting cancelado.")
            exit()
            
if __name__ == "__main__":
    main()