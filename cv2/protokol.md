# ISA 2020: Odpovědní arch pro cvičení č. 2

## Vzdálený terminál - SSH, Secure Shell

### (2.) Bezpečné připojení na vzdálený počítač bez autentizačních klíčů

*Verze OpenSSH*: OpenSSH_7.4

*Vybraná podporovaná šifra*: chacha20-poly1305@openssh.com

*Co lze zjistit o obsahu komunikace?*: Komunikácia medzi klientom a serverom je po celý čas zašifrovaná pomocou určitej šifry, obsah je šifrovaný.

### (3.) Vytvoření veřejného a privátního klíče

*Jak se liší práva mezi souborem s privátním a veřejným klíčem?*: 
    
    V súbore s privátnym kľúčom sú citlivé dáta a preto môžu byť dostupné na čítanie a zápis iba uživateľovi(ten kto kľúč vytvoril).
    V súbore s verejným kľúčom dáta nie sú citlivé a sú naopak dostupné ostatným, takže si ich môže prečítať hocikto, zapisovať môže opäť len user(vlasntík).

### (4.) Distribuce klíčů

*Jaká hesla bylo nutné zadat při kopírovaní klíčů?*: heslo uživateľa na druhom stroji (user4lab/root4lab)

*Jaká hesla bylo nutné zadat při opětovném přihlášení?*: 
    tentokrát bolo nutné zadať kľúč, ktorý sme predtým nastavili pre uživateľa user 
    a pre roota to bolo rovnaké heslo ako predtým, keďže tam sme kľúč nezadávali (fitvutisa/root4lab)

### (6.) Pohodlné opakované použití klíče

*Museli jste znovu zadávat heslo?*: Nie, heslo bolo uložené a automaticky sme sa prihlásili k druhému stroju

## Zabezpečení transportní vrstvy - TLS, Transport Layer Security

### (1.) Nezabezpečený přenos dat

*Je možné přečíst obsah komunikace?*: Áno obsah komunikácie sa dá prečítať kedže je komunikácia nezabezpečená.

### (2.) Přenos dat zabezpečený TLS

*Je možné přečíst obsah komunikace?*: Nie, obsah komunikácie je zašifrovaný. Jediné čo sa dá z komunikácie prečítať je TLS hlavička.
