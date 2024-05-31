# SNORT
```
snort -Q -c /etc/snort/snort.conf -A full -i ens37 -l /var/log/snort/
```
[-i ens37]: Interface yang dipakai (`ip addr` untuk melihat interfaace).

[-l /var/log/snort]: Folder log snort.

[-c]: File config snort.

[-A full]: Snort alert mode.


### Snort Rules :
> File Location : /etc/snort/rules/local.rules 


TLDR;
Ketiga rules dibawah merupakan alert pada saat server menerima request TCP, UDP, dan ICMP dengan threshold 30 request dengan rentang waktu 10 detik maka dinyatakan flooding.

```
#SYN Flood
alert tcp any any -> $HOME_NET any (flags: S; msg:"SYN DDoS Attempt!"; threshold: type both, track by_dst, count 30, seconds 10; sid:110001;rev:1;)
#UDP Flood
alert udp any any -> $HOME_NET any (msg:"UDP DDoS Attempt!"; threshold: type both, track by_dst, count 30, seconds 10; sid:110002;rev:1;)
#ICMP Flood
alert icmp any any -> $HOME_NET any (msg:"ICMP DDoS Attempt!"; threshold: type both, track by_dst, count 30, seconds 10; sid:110003;rev:1;)
```

### Snort Config : 
> File Location : /etc/snort/snort.conf;

>>```
>>...
>>ipvar HOME_NET 192.168.18.0/24
>>...
>>```
>atau 
>>```
>>...
>>ipvar HOME_NET 192.168.18.0/24,192.168.126.0/24
>>...
>>```


# OSSEC

- [decoder.xml (/var/ossec/etc/network_decoder.xml)](ossec-ddos/decoder.xml) 
- [rules.xml (/var/ossec/rules/local_rules.xml)](ossec-ddos/rules.xml)
- [iptables-rules](ossec-ddos/rules-iptables.v4)
- [Confi (/var/ossec/etc/ossec.conf)](ossec-ddos/ossec.conf), atau [Config(With Active Response )](ossec-ddos/ossec_active_response.conf)


### iplog
```
iplog --detect-syn-flood=true --detect-ping-flood=true --detect-syn-scan=true -l /var/log/iplog
```
>Note: Tambah --restart atau -R jika iplog sudah dijalankan sebelumnya

### IP Tables (Optional)
```
iptables-restore < rules-iptables.v4
```

### Run OSSEC
```
./var/ossec/bin/ossec-control restart
```
