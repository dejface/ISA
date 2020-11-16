# ISA 2020: Odpovědní arch pro cvičení č. 3

## (1.) Resolving DNS dotazů

Jaké jsou autoritativní DNS servery pro doménu *vutbr.cz*?\
  \ rhino.cis.vutbr.cz
  \ pipit.cis.vutbr.cz
  \
*Display filter* pro zobrazení pouze DNS provozu: dns

Počet zachycených paketů souvisejících s vyhledáním NS pro doménu *vutbr.cz*: 2

Provedený DNS dotaz (vyberte správnou variantu): **rekurzivní**

Podle čeho jste zjistili zakroužkovaný typ DNS dotazu v zachyceném paketu? \

  Pri požiadavke sa vytvorila jedna priama požiadavka (otázka) a dostali sme na ňu od serveru priamu odpoveď (2x nameserver)
  Taktiež sa v pakete od serveru vyskytuje príznak (FLAG) "Recursion desired", ktorý označuje, že požiadavka sa bude vykonávať rekurzívne

Cílová IP adresa paketu s DNS dotazem: 192.168.10.1

Jakému zařízení náleží zapsaná IP adresa?

  IP adresa patrí lokálnemu DNS serveru respektíve je to adresa môjho routeru ku ktorému som pripojený v domácej sieti


## (2.) Zabezpečení a resolving pomocí DNS over HTTPS

Dokážete zjistit ze zachyceného DNS provozu, jaké domény jste předtím navštívili? Proč?   
  
  Nie, komunikácia je viacmenej šifrovaná. Z navštívených stránok (celkovo 5) sa v komunikácii objavil iba youtube.com.
  Vďaka tomu, že sme v prehliadači povolili DNS over HTTPS sme dokázali zašifrovať mená serverov, na ktoré sa pripájame.
  
*Display filter* pro zobrazení pouze TLS provozu: tls

Jeden řádek z položky *Answers* z libovolné DoH odpovědi:  
  
  Odpoveď v pakete číslo 330
  snippets.cdn.mozilla.net: type CNAME, class IN, cname d228z91au11ukj.cloudfront.net
  
IP adresa, na kterou směřovaly pakety s DoH dotazem: 185.43.135.1

Doménové jméno patřící k doplněné IP adrese: odvr.nic.cz


## (3.) Zabezpečení a resolving pomocí DNS over TLS

*Display filter* pro zobrazení pouze provozu využívající TCP port 853: tcp.port == 853

*Display filter* pro zobrazení pouze provozu využívající TCP nebo UDP port 53: tcp.port == 53 or udp.port == 53

Služba běžící nad portem 53: DNS

Počet zachycených paketů se zdrojovým nebo cílovým portem 53: 0


## (4.) Blokování reklam a další



Jaký rozdíl jste zpozorovali na webu *idnes.cz* při jeho načtení s aktivním nástrojem *pi-hole*?

Reklamné bannery na stránke idnes.cz sa nezobrazovali, respektíve zobrazovali sa len zašednuté plochy.