# delay packet gadget issues

- First issue is that we can't do it normally because xdp programs are not sleepable
    - so we need to look into bpf_timers

- Second when looking into bpf timers, we need to sort of store all the packets in a map temporarily and then after some time, reinject the packets
    - which means that we need to store all the packets in a queue or something, so first of all we need to uniquely identify these packets and then we need to see the feasibilty of how many packets can be stored in the map and will the rest be dropped 
    - alternate architechure ? need to explore but later

- third issue, so we cant store the skb in the map directly ? so we have to make a copy of each packet that comes in , and then drop the packet
    - since it is only DNS packets with max size of 512 bytes, we can dare to follow with this architeture