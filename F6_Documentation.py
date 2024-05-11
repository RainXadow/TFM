import json

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def load_data(json_file, txt_file, the_harvester_file):
    with open(json_file, 'r') as file:
        scan_data = json.load(file)
    with open(txt_file, 'r') as file:
        exploit_output = file.read()
    with open(the_harvester_file, 'r', encoding='utf-8') as file:
        harvester_output = file.read()
    return scan_data, exploit_output, harvester_output

def create_pdf(report_data, filename='informe_pentesting.pdf'):
    scan_data, exploit_output, harvester_output = report_data
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    # Inicializar la posición vertical para los textos
    y_position = height - 70  # Espacio adicional antes del primer título

    # Título del documento
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y_position, "INFORME DE PENTESTING")
    y_position -= 50  # Espacio adicional después del título

    # Resultados de TheHarvester
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "RESULTADOS DE THEHARVESTER:")
    y_position -= 30  # Espacio adicional después del título
    c.setFont("Helvetica", 12)
    for line in harvester_output.split('\n'):
        if y_position < 50:
            c.showPage()
            y_position = height - 50
        c.drawString(50, y_position, line)
        y_position -= 14

    # Información de los hosts y puertos abiertos
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "HOSTS Y PUERTOS ABIERTOS:")
    y_position -= 20
    c.setFont("Helvetica", 12)
    for host, details in scan_data['hosts'].items():
        c.drawString(70, y_position, f"Host: {host}, Estado: {details}")
        y_position -= 14
        if host in scan_data['ports']:
            for protocol, ports in scan_data['ports'][host].items():
                for port, status in ports.items():
                    c.drawString(90, y_position, f"Puerto: {port}, Protocolo: {protocol}, Estado: {status}")
                    y_position -= 14
        if y_position < 50:
            c.showPage()
            y_position = height - 50

    # Información del sistema operativo
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "INFORMACIÓN DEL SISTEMA OPERATIVO:")
    y_position -= 20
    c.setFont("Helvetica", 12)
    for host, details in scan_data['os'].items():
        c.drawString(70, y_position, f"Host: {host}")
        y_position -= 14
        if details:
            c.drawString(90, y_position, f"Nombre OS: {details['name']}, Precisión: {details['accuracy']}")
            y_position -= 14
            for osclass in details.get('osclass', []):
                c.drawString(110, y_position, f"Tipo: {osclass['type']}, Vendedor: {osclass['vendor']},")
                y_position -= 14
                c.drawString(110, y_position, f"Familia OS: {osclass['osfamily']}, Generación: {osclass['osgen']}")
                y_position -= 14
        if y_position < 50:
            c.showPage()
            y_position = height - 50

    # Resultados del exploit
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "RESULTADOS DEL EXPLOIT:")
    y_position -= 20
    c.setFont("Helvetica", 12)
    for line in exploit_output.split('\n'):
        c.drawString(50, y_position, line)
        y_position -= 14
        if y_position < 50:
            c.showPage()
            y_position = height - 50

    c.save()

def main():
    scan_results_file = 'scan_results.json'
    exploit_output_file = 'vsftpd_exploit_output.txt'
    the_harvester_file = 'TheHarvesterResults.txt'
    report_data = load_data(scan_results_file, exploit_output_file, the_harvester_file)
    create_pdf(report_data)