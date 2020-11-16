# ISA 2020: Odpovědní arch pro cvičení č. 1

## Zjišťování konfigurace

### (1.) Rozhraní enp0s3

*MAC adresa*: 08:00:27:88:81:41

*IPv4 adresa*: 10.0.2.15

*Délka prefixu*: 24

*Adresa síťe*: 10.0.2.0/24

*Broadcastová adresa*: 10.0.2.255

### (2.) Výchozí brána

*MAC adresa*: 52:54:00:12:35:02

*IPv4 adresa*: 10.0.2.2

### (4.) DNS servery

*Soubor*: /etc/resolv.conf

*DNS servery*: nameserver 192.168.10.1

### (5.) Ping na výchozí bránu

*Soubor*: /etc/hosts

*Úprava*: pridaná IPv4 adresa východiskovej brány a jej hostname
          10.0.2.2  gw

### (6.) TCP spojení

*Záznam + popis*: 
State      Recv-Q Send-Q      Local Address:Port     Peer Address:Port                
ESTAB      0      0           10.0.2.15:40066       216.58.201.78:https   

State ESTAB - stav spojenia otvorený (nastalo spojenie)
Recv-Q - počet bytov, ktoré neboli skopírované klientom
Send-Q - počet bytov, ktoré neboli uznané serverom
Local Address:Port - adresa a port klienta
Peer Address:Port - adresa a port servera

### (8.) NetworkManager události

*Příkaz*: sudo journalctl -u NetworkManager

### (9.) Chybová hláška sudo

*Příkaz*: sudo journalctl -t sudo

*Chybová hláška*: user : command not allowed ; TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/wireshark


## Wireshark

### (1.) Capture filter

*Capture filter*: port 80 or 8080

### (2.) Zachycená HTTP komunikace

Komu patří nalezené IPv4 adresy a MAC adresy?

IPv4 adresy patria mojej VM a na druhej strane host adrese http://cphoto.fit.vutbr.cz. Nájdené MAC adresy patria rozhraniu enp0s3 a východzej bráne.

Vypisovali jste již některé z nich?

Ano, vypisoval som svoju IPv4 adresu rizhrania enp0s3 10.0.2.15, jeho MAC adresu 08:00:27:88:81:41 a MAC adresu východiskovej brány 52:54:00:12:35:02

Proč tomu tak je?

Pretože MAC adresy sa zaznamenávajú len susedné navzájom, kdežto IP adresy od zdroju až do cieľa.

#### Požadavek HTTP

Cílová MAC adresa

  - *Adresa*: 52:54:00:12:35:02
  - *Role zařízení*: MAC adresa východzej brány

Cílová IP adresa

  - *Adresa*: 147.229.177.179
  - *Role zařízení*: server

Zdrojová MAC adresa

  - *Adresa*: 08:00:27:88:81:41
  - *Role zařízení*: MAC adresa rozhrania enp0s3

Zdrojová IP adresa

  - *Adresa*: 10.0.2.15
  - *Role zařízení*: klient


#### Odpověď HTTP

Cílová MAC adresa

  - *Adresa*: 08:00:27:88:81:41
  - *Role zařízení*: MAC adresa rozhrania enp0s3

Cílová IP adresa

  - *Adresa*: 10.0.2.15
  - *Role zařízení*: klient

Zdrojová MAC adresa

  - *Adresa*: 52:54:00:12:35:02
  - *Role zařízení*: MAC adresa východzej brány

Zdrojová IP adresa

  - *Adresa*: 147.229.177.179
  - *Role zařízení*: server

### (3.) Zachycená ARP komunikace

*Display filter*: arp or icmp

### (6.) Follow TCP stream

Jaký je formát zobrazených dat funkcí *Follow TCP stream*, slovně popište
význam funkce *Follow TCP stream*:

Follow TCP stream zobrazuje komunikáciu medzi serverom a klientom. Pokiaľ je komunikácia nešifrovaná, dajú sa vďaka tejto funkcii vyčítať z paketu napr. citlivé údaje (heslá, PIN kódy, atď). Dáta (payload paketu) sú oproti normálnemu paketu zobrazované vo viacmenej čitateľnejšom formáte.