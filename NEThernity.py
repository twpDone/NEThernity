#!/usr/bin/python
from scapy.all import *

##
# Replies Stuff.
# Act like a tarpit: no FIN no RST.
# Dont forget to `iptables -P OUTPUT DROP`
#

class NEThernity(Automaton):         
    @ATMT.state(initial=1)                                                           
    def BEGIN(self):                                                                 
        self.notwaitingfor=[]                                                        
        raise self.WAIT()                                                            
    @ATMT.state()                                                               
    def WAIT(self):                                                                  
        pass                                                                         
    @ATMT.state()                                                                    
    def ARPMAP(self,pkt):                                                            
        self.waitingfor=pkt                                                          
    @ATMT.timeout(ARPMAP, 0.1)                                                       
    def timeout_arp(self):                                                           
        p=ARP(op=2,pdst=self.waitingfor["ARP"].psrc,psrc=self.waitingfor["ARP"].pdst)
        print("Now Spoofing unallocated {}".format(self.waitingfor["ARP"].pdst))
        send(p,verbose=0)                                                 
        raise self.WAIT()                                                 
    @ATMT.receive_condition(ARPMAP)                                       
    def arpisat(self,pkt):                                                                                                                 
        if pkt.haslayer(ARP):                                                                                                              
            if pkt.op==2 and pkt["ARP"].psrc==self.waitingfor["ARP"].pdst:                                                                    
                self.notwaitingfor.append(self.waitingfor["ARP"].pdst)                                                                        
                print("WHITELIST ARP :",pkt["ARP"].psrc)                                                                                      
                raise self.WAIT()      
    @ATMT.receive_condition(WAIT)                                                    
    def receive(self,pkt):                                                           
        ACK=16 # Stack Abuse                                                    
        SYNACK=18 # Tarpit Abuse                                          
        if pkt.haslayer(TCP) and pkt['TCP'].flags==2 :                    
            if pkt.window == 1024 and pkt.id%2==0:                        
                p=IP(src=pkt['IP'].dst,dst=pkt['IP'].src)/TCP(sport=pkt['TCP'].dport,dport=pkt['TCP'].sport,ack=pkt["TCP"].seq+1,flags=ACK)
            else:                                                                                                                          
                p=IP(src=pkt['IP'].dst,dst=pkt['IP'].src)/TCP(sport=pkt['TCP'].dport,dport=pkt['TCP'].sport,ack=pkt["TCP"].seq+1,flags=SYNACK)
            # abusing TARPIT                                                                                                                  
            print(p.summary())                                                                                                                
            send(p,verbose=0)                                                                                                                 
        if pkt.haslayer(ICMP):                                                                                                                
            if pkt["ICMP"].type==8:                                                                                                           
                p=IP(src=pkt['IP'].dst,dst=pkt['IP'].src)/ICMP(type=0,id=pkt["ICMP"].id,seq=pkt["ICMP"].seq)/Raw(pkt["Raw"])                  
                #print(p.summary)                                                                                                             
                send(p,verbose=0)                                                                                                             
        if pkt.haslayer(ARP):                                                                                                                 
            if pkt["ARP"].op==1:                                                                                                              
                if pkt["ARP"].pdst not in self.notwaitingfor:                                                                                 
                    raise self.ARPMAP(pkt)                                                                                                    


NEThernity().run()
