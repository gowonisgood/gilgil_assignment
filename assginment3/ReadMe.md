## gilgil_assingment3
## 과제

ARP 감염 패킷을 생성하여 Victim의 ARP 테이블을 변조하는 과제.
Attacker가 Ethernet 및 ARP 헤더를 조작해 ARP infection packet을 생성하고 전송.

Sender(Victim)와 Target(Gateway)의 Mac 정보를 자동으로 수집하고 조합 처리 가능해야 함.
Attacker의 Mac 주소는 인터페이스 이름을 통해 자동으로 획득해야 함.

감염 여부는 Victim의 ARP 테이블 변조 확인 또는 Wireshark로 ping 패킷 수신 여부를 통해 검증함.
테스트는 반드시 물리적으로 분리된 장비에서 수행해야 하며 VM 환경일 경우 bridge 모드 등을 활용함.

패킷 전송은 pcap_sendpacket, 수신은 pcap_open_live 설정값을 적절히 조정해 구현함.


## 실행
```c
syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]
sample : send-arp wlan0 192.168.10.2 192.168.10.1
```

## example

```shell
sudo ./pcap-test eth0
00:0c:29:aa:ce:11 -> 00:50:56:ff:76:3a, 192.168.205.131:56452 -> 110.11.116.252:80, -
============================
00:50:56:ff:76:3a -> 00:0c:29:aa:ce:11, 110.11.116.252:80 -> 192.168.205.131:56452, 0|0
============================
00:0c:29:aa:ce:11 -> 00:50:56:ff:76:3a, 192.168.205.131:56452 -> 110.11.116.252:80, -
============================
00:0c:29:aa:ce:11 -> 00:50:56:ff:76:3a, 192.168.205.131:56452 -> 110.11.116.252:80, 47|45|54|20|2f|20|48|54|54|50|2f|31|2e|31|d|a|48|6f|73|74
============================
```


## 과제 동영상
https://youtu.be/3GlrsAKyeLY?si=biB98XliOFdIB0Gt

