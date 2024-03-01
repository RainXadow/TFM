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

# Función para detectar el sistema operativo de una lista de hosts
def os_detection(hosts):
    for host in hosts:
        try:
            nm.scan(host, arguments='-O')
            print(f'Host : {host}')
            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    print(f'OSClass.type : {osclass["type"]}')
                    print(f'OSClass.vendor : {osclass["vendor"]}')
                    print(f'OSClass.osfamily : {osclass["osfamily"]}')
                    print(f'OSClass.osgen : {osclass["osgen"]}')
                    print(f'OSClass.accuracy : {osclass["accuracy"]}')
            else:
                print('No OS detection available')
        except Exception as e:
            print(f'Error: {e}')

# Ejemplo de uso
hosts_active = host_discovery('192.168.1.0/24')
port_scanning(hosts_active)
os_detection(hosts_active)
