#!/bin/bash

#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "Este script debe ser ejecutado con sudo " 
   exit 1
else
   pip3 install -r requirements.txt
   py2bin pyc arpspoofing.py
   chmod +x arpspoofing.pyc
   mv arpspoofing.pyc /bin/arpspoofing
   echo "Enhorabuena ya puedes correr el script simplemente poniendo sudo arpspoofing 'ip victima' 'ip gateway' 'interfaz de red' "
fi
