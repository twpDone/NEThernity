# NEThernity

Warning this was developped for demonstration purposes and according to local laws.
Don't run it on networks you don't own without explicit permition (written).
Crafting packets require privileges.
You can crash your network in case of bugs, or unbwanted behaviour.

LaBrea Inspired - ARP Unallocated DHCP anwering
Ping Answering (nmap first check)
Using Tar Pit tricks, timeouts and old TCP tricks to slow down scanners.
Keep browsers, requests, wget and stuff like that open as long as possible.

Scapy Automaton Based

Begin -> WAIT ----------------|---- ON ARP whos-has ----> ARPMAP ->-|
         /|\                  |                                     |-- on timeout->-spoof unallocated---|   
          |-<-reply-<-on ICMP-|                                     |-- on is-at reply ->----------------|
          |-<-reply-<-on PING-|                                                                          |
          |-<-tarpit-<-on SYN-|                                                                          |
          |----------------------------------------------------------------------------------------------|
          
          
