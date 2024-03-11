import nmap

# Inicializar el scanner de nmap
nm = nmap.PortScanner()

# Función para descubrir hosts activos en la red
def host_discovery(range_ip):
    nm.scan(hosts=range_ip, arguments='-sn')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print(f'{host} : {status}')
    return nm.all_hosts()

# Función para escanear puertos de una lista de hosts
def port_scanning(hosts):
    for host in hosts:
        nm.scan(host, '1-1024')
        print(f'Host : {host}')
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocol : {proto}')

            lport = nm[host][proto].keys()
            for port in lport:
                print(f'port : {port}\tstate : {nm[host][proto][port]["state"]}')

def os_detection(hosts):
    for host in hosts:
        try:
            nm.scan(host, arguments='-O')
            print(f'\nHost : {host}')
            if nm[host].has_tcp(22):  # Check if port 22 is open
                if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
                    osmatch = nm[host]['osmatch'][0]
                    print(f'Name : {osmatch["name"]}')
                    print(f'Accuracy : {osmatch["accuracy"]}')
                    print(f'Line : {osmatch["line"]}')
                    for osclass in osmatch['osclass']:
                        print(f'OSClass.type : {osclass["type"]}')
                        print(f'OSClass.vendor : {osclass["vendor"]}')
                        print(f'OSClass.osfamily : {osclass["osfamily"]}')
                        print(f'OSClass.osgen : {osclass["osgen"]}')
                        print(f'OSClass.accuracy : {osclass["accuracy"]}')
                else:
                    print('No OS detection available')
            else:
                print('Port 22 closed, OS detection may not be accurate')
        except Exception as e:
            print(f'Error: {e}')
            
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

def solicitar_direccion_ip():
    while True:
        ip = input("Introduce la dirección IP (ej. 192.168.1.1): ")
        if es_ip_valida(ip):
            return ip
        else:
            print("Dirección IP inválida, por favor intente nuevamente.")

def solicitar_mascara():
    while True:
        mascara = input("Introduce la máscara de red (ej. 24): ")
        if mascara.isdigit() and 0 <= int(mascara) <= 32:
            return mascara
        else:
            print("Máscara de red inválida, por favor intente nuevamente.")

# Función principal que encapsula todas las demás funciones
def main():
    ip = solicitar_direccion_ip()
    mascara = solicitar_mascara()
    rango_ip = f"{ip}/{mascara}"
    print(f"Escaneando el rango de IP: {rango_ip}")

    hosts_activos = host_discovery(rango_ip)
    port_scanning(hosts_activos)
    os_detection(hosts_activos)
