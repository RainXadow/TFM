import json

import nmap

# Inicializar el scanner de nmap
nm = nmap.PortScanner()

#! Implementar algun escaneo mas

def host_discovery(range_ip):
    nm.scan(hosts=range_ip, arguments='-sn')
    return {x: nm[x]['status']['state'] for x in nm.all_hosts()}

def port_scanning(hosts):
    scan_results = {}
    for host in hosts:
        nm.scan(host, '1-1024')
        ports_info = {}
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            ports_info[proto] = {port: nm[host][proto][port]['state'] for port in lport}
        scan_results[host] = ports_info
    return scan_results

def os_detection(hosts):
    os_results = {}
    for host in hosts:
        try:
            nm.scan(host, arguments='-O')
            os_results[host] = nm[host]['osmatch'][0] if 'osmatch' in nm[host] and nm[host]['osmatch'] else {}
        except Exception as e:
            os_results[host] = {'error': str(e)}
    return os_results

def es_ip_valida(ip):
    partes = ip.split(".")
    return len(partes) == 4 and all(parte.isdigit() and 0 <= int(parte) <= 255 for parte in partes)

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

def guardar_datos_en_json(datos, archivo):
    with open(archivo, 'w') as file:
        json.dump(datos, file, indent=4)

def main():
    ip = solicitar_direccion_ip()
    mascara = solicitar_mascara()
    rango_ip = f"{ip}/{mascara}"

    hosts_activos = host_discovery(rango_ip)
    ports_info = port_scanning(hosts_activos.keys())
    os_info = os_detection(hosts_activos.keys())

    datos_completos = {
        'hosts': hosts_activos,
        'ports': ports_info,
        'os': os_info
    }

    guardar_datos_en_json(datos_completos, 'scan_results.json')