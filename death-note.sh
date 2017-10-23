#[DEATH NOTE]
#!/bin/sh

black=$(tput setaf 0)
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
magenta=$(tput setaf 5)
cyan=$(tput setaf 6)
white=$(tput setaf 7)

normal=$(tput sgr0)

while :
do
    clear
    printf "\t$blue _______________by error-system____________\n"
    printf "\t$blue Menu principal $0\n"
    printf "\t___________________________________________\n"
    printf "\t$red[apk]$normal   Herraientas para APK\n"
    printf "\t$red[ip]$normal    Herramientas IP      \n"    
    printf "\t$red[shell]$normal Generador de shellcodes arm | intel\n" 
    printf "\t$red[enc]$normal   Encriptacion (sha-256 md5 base64) \n"
    printf "\t$red[api]$normal   Implementacion de API REST (openssl-socket-curl-wget) \n"
    printf "\t$red[wpa]$normal   Ataques a redes wifi (iw-aircrack-tcdump)\n"
    printf "\t$red[22]$normal    Buscar exploit en seachdatbase --https://www.exploit-db.com/search/ \n"
    printf "\t$red[25]$normal    crunch | Aircrack-ng -->Handshake_PCAP \n"
    printf "\t$red[shut]$normal  Apagado automatico de PC \n"
    printf "\t$red[exi]$normal   Exit/Stop\n"
    printf "\t====================================\n"
    
    echo -n "Entrar opcion [en rojo]:"
    read opc
    case $opc in
 
 
 #herramientas para malware de apk android***********************************************************************************   
    apk)
        path=${PWD}"/apk/"
        path2=${PWD}"/app/dex2jar-2.0/"
        
        printf "\t$red[1]$normal Decompilar APK con DEX2JAR\n" 
        printf "\t$red[2]$normal Compilar APK con DEX2JAR\n"
        printf "\t$red[3]$normal Decompilar APK con APKTOOL\n"
        printf "\t$red[4]$normal Compilar APK con APKTOOL\n"
        
        echo -n "Entrar opcion [1-4]:"
        read opc2
        case $opc2 in
         1)
           printf "\n jar2dex APK-->" ;
           read  nom_f
           unzip -o -d $path$nom_f $path$nom_f.apk
                     
           $path2"d2j-dex2jar.sh" -f $path$nom_f/classes.dex -o $path$nom_f.jar
           read ;;
    
         2)
           printf "\nIngrese el nombre y la ruta del archivo APK-->"
           read nom_f        
		   $path2"d2j-jar2dex.sh" -o $path$nom_f/classes.dex $path$nom_f/$nom_f.jar 
           
           #./$dexd2j-dex-recompute-checksum.sh -f -o $nom_f-n2.apk $nom_f-n.dex
           #zipalign -v 4 $path$nom_f.apk $path$nom_f-n.apk 
           read;;
         3)
           printf "\nIngrese el nombre y la ruta del archivo APK-->"
           read nom_f
           apktool -f d -o $path$nom_f $path$nom_f.apk
           printf "Listo\n pulsar enter :)"
          read ;;
         4) 
          printf "\nIngrese el nombre y la ruta del archivo APK-->"
          read nom_f
          apktool b $path$nom_f
          zipalign -v 4 $path$nom_f.apk $path$nom_f-n.apk 
          printf "Listo\n pulsar enter :)"
          read;;
        esac;;
 
 # datos de red y anonimato*************************************************************************************************     
      ip) 
          printf "\t$red[5]$normal  Ver ip publica\n"
          printf "\t$red[6]$normal  Ver ip publica mas geolocalizacion\n"
          printf "\t$red[7]$normal  Ver ip Local +  gw + broadcast\n"
          printf "\t$red[8]$normal  Ver ip local\n"
          printf "\t$red[11]$normal Ver IP con TOR \n"
          printf "\t$red[12]$normal Ver IP-geo traves de TOR \n"
          
          echo -n "Entrar opcion [1-4]:"
          read opc2
          case $opc2 in
          
          5) 
           printf 'La ip publica es: '
           curl http://ifconfig.me
           read;;
          
          6) 
           curl ip-api.com
           #http://www.google.com/maps/place/-34.6033,-58.3816/@-34.6033,-58.3816,16z
           read;;   
          7)
            printf "Ingrese la interface etho o wlan0 -->" 
            read iface
            ifconfig $iface | grep "inet"
            read;;
          8)
           printf "Ingrese la interface etho o wlan0 -->" 
           read iface
           ip addr show $iface | grep inet | awk '{ print $2; }' | sed 's/\/.*$//' 
           read;;
           
          11)
            printf 'La ip publica a traves de tor es: '
            proxychains curl -S http://ifconfig.me
            read;;
    
           12)
             printf 'La geolocalizacion a traves de tor es: '
             proxychains curl http://ip-api.com
             #http://www.google.com/maps/place/-34.6033,-58.3816/@-34.6033,-58.3816,16z
             read;;
         esac;;

#generacion de shellcode C ASM ************************************************************************************************        
     shell)
          
          printf "\t$red[13]$normal Desactivar ASLR y NX\n"
          printf "\t$red[14]$normal Activar ASLR y NX\n"     
          printf "\t$red[15]$normal Compilar en C\n"
          printf "\t$red[16]$normal Compilar en Asm\n"
          printf "\t$red[17]$normal Generar Shellcode\n"
          printf "\t$red[18]$normal Generar Shellcode para ARM\n"    
          echo -n "Entrar opcion [1-4]:"
          read opc2
          case $opc2 in
          3)
          printf "Desactivar ASLR y NX"
          printf 0 > /proc/sys/kernel/randomize_va_space
          printf "Listo pulsar enter :) \n"
          read;;
          14)  
          printf "Activar ASLR y NX"
          printf 2 > /proc/sys/kernel/randomize_va_space
          printf "Listo pulsar enter :) \n"
          read;;
          15)
          printf "\nIngrese el archivo en C -->"
          path=${PWD}"/code/"
          read nom_f
          echo -e gcc -fno-stack-protector -o $path$nom_f $path$nom_f.c
          gcc -fno-stack-protector -o $path$nom_f $path$nom_f.c
          $path$nom_f
          printf "Listo pulsar enter :) \n"
          read;;
          
          16)
          as -o $path$nom_f.o $path$nom_f.s 
          gcc -o $path$nom_f $path$nom_f.o
          read;;
          
          17) 
          for i in $(objdump -d /$path$nom_f | grep '^ ' | sed 's/ //g' | awk -F"[\t]" {'print $2'});
            do echo -n ${i:14:2}${i:12:2}${i:10:2}${i:8:2}${i:6:2}${i:4:2}${i:2:2}${i:0:2};done|sed 's/.\{2\}/\\x&/g'   
            printf "Listo pulsar enter :) \n"
          read;;
          
          18)       
          for i in $(objdump -d /$path$nom_f | grep '^ ' | sed 's/ //g' | awk -F"[\t]" {'print $2'});
            do echo -n ${i:6:2}${i:4:2}${i:2:2}${i:0:2};done|sed 's/.\{2\}/\\x&/g'   
            printf "Listo pulsar enter :) \n"
          read;;    
         esac;;
         

 #encriptacion sha-256 md5 base-64****************************************************************************************   
     enc) 
          printf "\t$red[256]$normal    Generador de hash sha256-->\n"
          printf "\t$red[512]$normal    Generador de hash sha512 -->\n"
          printf "\t$red[md5]$normal    Generador de hash md5 -->\n"
          printf "\t$red[b64e]$normal   Generador de hash base 64 encode-->\n"
          printf "\t$red[b64d]$normal   Generador de hash base 64 decode -->\n"
          printf "\t$red[aese]$normal   Generador de hash openssl aes encode-->\n"
          printf "\t$red[aesd]$normal   Generador de hash openssl aes decode -->\n"
          
          echo -n "Entrar opcion [*]:"
          
          read opc2
          case $opc2 in
           256) 
           printf "Hash sha256 -->"
           read pass
           printf $pass | sha256sum |awk '{print toupper($0)}'|sed 's/ //g'|sed 's/-//g' 
           printf "Listo pulsar enter :) \n"
           read;;
           
           512) 
           printf "Hash sha512r -->"
           read pass
           printf $pass | sha512sum |awk '{print toupper($0)}'|sed 's/ //g'|sed 's/-//g' 
           printf "Listo pulsar enter :) \n"
           read;;
           md5)
           printf "hash MD5-->"
           read pass
           printf $pass | md5sum |awk '{print toupper($0)}'|sed 's/ //g'|sed 's/-//g' 
           printf "Listo pulsar enter :) \n"
           read;;
           
           b64e)
           printf "BaSe 64 EnCode -->"
           read pass
           printf $pass | base64 |sed 's/ //g'|sed 's/-//g' 
           printf "Listo pulsar enter :) \n"
           read;;
           
           b64d)
           printf "BaSe 64 DeCode -->"
           read pass
           printf $pass | base64 -d |sed 's/ //g'|sed 's/-//g' 
           printf "Listo pulsar enter :) \n"
           read;;
           
           aese)
           
           printf "AES encode -->"
           read pass
           printf $pass | openssl enc -aes-256-cbc -a  
           printf "Listo pulsar enter :) \n"
           read;;
           
           aesd)
           printf "AES decode -->"
           read pass
           echo $pass | openssl enc -aes-256-cbc -a -d
           printf "Listo pulsar enter :) \n"
           read;;
           
           
           
           
          esac;;
#bash socket experimental inestable**********************************************************************************                    
  #dig ss whois nbtstat socat tor-resolve nmap smbclient -L ip  printf "%x\n" $ echo $((16#FF))    
      api) 
          printf "\t$blue Bash Socket experimental inestable\n"
          printf "\t$red[owm]$normal   API OpenWeatherMap clima\n"
          printf "\t$red[geo]$normal   API Geolocalizacion de google\n"
          printf "\t$red[sock]$normal  Bash Socket para pruebas\n"
          printf "\t$red[modbus]$normal  modbus-tcp experimental\n"
          echo -n "Entrar opcion [*]:"
          
          read opc2
          case $opc2 in
          owm)
              head="GET /data/2.5/weather?lat=-37.8814&lon=-67.8277&APPID=4074c704aa16735532f97a8b18a0020e&units=metric&lang=es HTTP/1.0\r\n"
              dato1="Host: api.openweathermap.org\r\n"
              dato2="Content-Type: application/json\r\n"
              dato3="Connection: close\r\n\r\n"
              echo -e $head$dato1$dato2$dato3                          
              
              exec 3<>/dev/tcp/api.openweathermap.org/80
              echo -e $head$dato1$dato2$dato3 >&3
              cat <&3
              exec 3>&-
              read;;
              
          geo) 
              head="POST /geolocation/v1/geolocate?key=AIzaSyAe4Z2ng-doKeagGz7tpr3DWjWAL5qXR08 HTTP/1.1\r\n"
              datos1="Host: www.googleapis.com\r\n"
              datos2="Content-Type: application/json\r\n"
              payload="{\"macAddress\": \"D0:FC:CC:A5:7B:F9 \", \"signalStrength\": -43,\"age\": 0,\"channel\": 11,\"signalToNoiseRatio\": 0}\n"
              datos3="Content-Length: "${#payload}"\r\n\r\n"
              datos4="Connection: close\r\n"
       
              echo -e $head$datos1$datos2$datos4$datos3$payload | openssl s_client -connect www.googleapis.com:443 -ign_eof
              read;;
          sock)
              printf "Ingrese el host remoto rhost -->" 
              read rhost
              printf "Ingrse el remote port rport -->" 
              read rport
                           
              head="GET / HTTP/1.0\r\n"
              dato1="Host: "$rhost"\r\n"
              dato2="Connection: close\r\n\r\n"
              echo -e $head$dato1$dato2
              
              exec 3<>/dev/tcp/$rhost/$rport
              echo -e $head$dato1$dato2 >&3
              cat <&3
              exec 3>&-
              read;;   
              
           modbus)
                 # printf "Ingrese el host remoto rhost -->" 
                 #read rhost
                 rhost=217.128.188.179
                 rport=502
                 echo -e $rhost:$rport
                 payload="\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00\x00\x05"
                 
                 payload2="0x000000000006010300000005"
                 #echo $((payload2))
                 #printf "%d\n" $payload2   #decimal
                 printf "%#010x\n" 8
                 printf "0x%08x\n" 8         
                 printf "%#08x\n" 8
                                              
                exec 3<>/dev/tcp/$rhost/$rport
                echo -e $payload >&3
                #cat <&3
                read -r msg_in <&3
                #echo -n $msg_in  # >&3
                #printf "%u\n" $msg_in
                echo 0x$(printf "%s" "$msg_in" |od -t x8 -An ) #| tr -dc '[:alnum:]')
                #printf a
                exec 3>&-
                read;; 
          esac;; 
             
#ataques wep/wpa/wpa2*****************************************************************************************************************************     
          wpa)
                printf "\t$blue Bash Socket experimental inestable\n"
                printf "\t$red[infw]$normal   Informacion de redes wifi\n"
                printf "\t$red[mon_man]$normal Pasar de modo monitor a modo managed\n"
                printf "\t$red[man_mon]$normal Pasar de modo managed a monitor\n"
                printf "\t$red[modbus]$normal  modbus-tcp experimental\n"
                echo -n "Entrar opcion [*]:"
          
                read opc2
          case $opc2 in
          
           mon_man)
                   printf "Ingrese la interfaz PHY(phy0)-->"
                   read phy
                   printf "Ingrese la interfaz monitor (mon0)-->"
                   read mon
                   printf "Ingrese la interfaz managed(wlan0)-->"
                   read man
                   
                                
                  iw dev $mon del
                  iw phy $phy interface add $man type managed
                  iw dev
                  iwconfig $man
                  read;;
                  
          man_mon)
                   canal1=2412
                   canal2=2417
                   canal3=2422
                   canal4=2427
                   canal5=2432
                   canal6=2437
                   canal7=2442
                   canal8=2447
                   canal9=2452
                   canal10=2457
                   canal11=2462
                   canal12=2467
                   canal13=2472
               
                   printf "Ingrese la interfaz PHY(phy0)"
                   read phy
                   printf "Ingrese la interfaz monitor (mon0)"
                   read mon
                   printf "Ingrese la interfaz managed(wlan0)"
                   read man
                   printf "Ingrese nombre del archivo PCAP"
                   read dump
                   
                  iw phy $phy interface add $mon type monitor
                  iw dev $man del
                  ifconfig $mon up
                  iw dev $mon set freq 2437         
                  iwconfig $mon
                  tcpdump -i $mon -n -w $dump.pcap
                  read;;
                
          infw)
                #Interface iface
                wlan_x=$(iw dev |grep Interface  | awk -F"[\t]" {'print $2'}|sed -u -e 's/Interface //')
                #interfaz phy
                phy_x=$(iw dev |grep phy  | awk -F"[\t]" {'print $1'}|sed 's/#//')
                               
                
                echo -e "Interfaces wlan disponibles: "$blue $wlan_x $normal "\n"
                echo -e "Interfaces phy disponibles:  "$blue $phy_x $normal "\n"
                
                
                               
                #echo -e "Ingrese la interfaz phy y el nombre ej wlan0mon"--->"
                #read phy
                #read wlan 
                                
                #iw phy $phy interface add $wlan type monitor
                                
                read;; 
                
                
          wifi)
              printf "Ingrese la interface iface -->" 
              read iface
              #printf "Ingrse el remote port rport -->" 
              #read canales
              #iw <interface> link | grep SSID | awk '{print '$2'}' | sed -u -e 's/SSID: //'
              
              #interfaces wifi 
              #iw dev |grep Interface  | awk -F"[\t]" {'print $2'}|sed -u -e 's/Interface //'
 
               
               canal1=2412
               canal2=2417
               canal3=2422
               canal4=2427
               canal5=2432
               canal6=2437
               canal7=2442
               canal8=2447
               canal9=2452
               canal10=2457
               canal11=2462
               canal12=2467
               canal13=2472
               
                
               iw dev
               iw phy phy0 info
               iw phy phy0 interface add wlan0mon type monitor
               iw dev wlan0 del
               
               ifwconfig wlan0mon up
               
               iw dev mon0 set freq 2437         
               ifconfig mon0
               tcpdump -i mon0 -n -w file.pcap
               
               
               iw dev mon0 del
               iw phy phy0 interface add wlan0 managed
               iw dev
               iwconfig wlan0
               
               rfkill list
               rfkill unblock 0
               read;;
            esac;;
            
#*******************************************************************************************************************************            
    9)
      gcc -dumpmachine      
      
      
    
    
      read;;
      
    10)
       printf 'La INformacion del procesador es:-->'
       cat /proc/cpuinfo
       read;;
   
    
    22)
        printf "Ingrese plataforma windows linux arm android -->" 
        read plat
        printf "Ingrese programa ej pdf -->" 
        read prg
       
        searchsploit $prg $plat -w -t
        read;;
    
    
       
    
           
       
    25)  
     
      min=8
      max=10
      charset=${PWD}"/charset/charset.lst"
      patron=mixalpha-numeric-symbol14
      
      patron_min=lalpha
      patron_num=numeric
      
      aircrack=aircrack-ng
      #crunch $min $max $charset $ataque
      
      path=${PWD}"/hs/"
      
     printf "Ingrse el BSID -->"
     read bsid;
     printf "Ingrse el handshake pcap -->"
     read pcap;
     
     #printf "Ingrese regla de caracteres para crunch 8 8 0123465789"
    #read regla;
    #printf "Ingrese longitud inicial -->"
    #read len_i;
    #printf "Ingrese longitud final -->"
    #read len_f;
    
     #crunch 8 10 123456789 | aircrack-ng -b D4:6E:0E:54:F8:E6 -w- E-54-F8-E6.cap
     crunch $min $max -f $charset $patron_min -d 2@ | aircrack-ng -b $bsid -w- $path$pcap.cap
     read;;
     
    40)
       airmon-ng start wlan0
       airodump-ng mon0
       airplay-ng -0 5 -a mac_ap -c mac_cli wlan0
       airdecap-ng
       airolib-ng
       airotun-ng
       airbase-ng
       
       read;;
#***************************************************************************************************    
    shut)
        printf "Apagado automatico Ingrese la cantidad de minutos -->" 
        read min
        shutdown -h +$min
        read;;
              
    exi) exit 0 ;;
    
    *) printf "ohhhh!!! Selecciona unba opcion del menu :)";
       printf "Presiona una tecla...";
       read;;
    
    esac
done
