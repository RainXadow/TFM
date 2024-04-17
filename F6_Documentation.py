import json

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def load_data(json_file, txt_file):
    with open(json_file, 'r') as file:
        scan_data = json.load(file)
    with open(txt_file, 'r') as file:
        exploit_output = file.read()
    return scan_data, exploit_output

def create_pdf(report_data, filename='informe_pentesting.pdf'):
    scan_data, exploit_output = report_data
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    # Título del documento
    y_position = height - 60  # Espaciado adicional antes del título
    c.drawString(50, y_position, "INFORME DE PENTESTING")
    y_position -= 40  # Espaciado adicional después del título

    # Información de los hosts y puertos abiertos
    c.drawString(50, y_position, "HOSTS Y PUERTOS ABIERTOS:")
    y_position -= 30  # Espaciado adicional después del título
    for host, details in scan_data['hosts'].items():
        c.drawString(70, y_position, f"Host: {host}, Estado: {details}")
        y_position -= 20
        if host in scan_data['ports']:
            for protocol, ports in scan_data['ports'][host].items():
                for port, status in ports.items():
                    c.drawString(90, y_position, f"Puerto: {port}, Protocolo: {protocol}, Estado: {status}")
                    y_position -= 20

    y_position -= 10  # Espaciado adicional antes del título
    # Información del sistema operativo
    c.drawString(50, y_position, "INFORMACIÓN DEL SISTEMA OPERATIVO:")
    y_position -= 30  # Espaciado adicional después del título
    for host, details in scan_data['os'].items():
        c.drawString(70, y_position, f"Host: {host}")
        y_position -= 20
        if details:
            c.drawString(90, y_position, f"Nombre OS: {details['name']}, Precisión: {details['accuracy']}")
            y_position -= 20

    y_position -= 10  # Espaciado adicional antes del título
    # Resultados del exploit
    c.drawString(50, y_position, "RESULTADOS DEL EXPLOIT:")
    y_position -= 30  # Espaciado adicional después del título
    for line in exploit_output.split('\n'):
        c.drawString(70, y_position, line)
        y_position -= 20
        if y_position < 50:
            c.showPage()  # Nueva página si se acaba el espacio
            y_position = height - 50

    c.save()

def main():
    scan_results_file = 'scan_results.json'
    exploit_output_file = 'vsftpd_exploit_output.txt'
    report_data = load_data(scan_results_file, exploit_output_file)
    create_pdf(report_data)