# Wireshark Terminal

`wireshark-terminal` is similar to the Wireshark we know and use, the difference is that `wireshark-terminal` runs in the terminal in a simple and compact way.
Remember that the wireshark-terminal program can only be run as sudo. If it's used on mobile, the phone needs to be root as well.

For the program to work run `sudo ./wireshark-terminal`.

Configurations before using the `wireshark-terminal` program:

On Linux (Debian/Ubuntu):
```
sudo apt-get update && sudo apt-get install libpcap-dev
```

On macOS (using Homebrew):
```
brew install libpcap
```

Compiler:
```
gcc wireshark-terminal.c -o wireshark-terminal -lpcap
```

If you get a compilation error, run the command below:
```
gcc wireshark-terminal.c -o wireshark-terminal -lpcap -D_GNU_SOURCE
```

Note: The `wireshark-terminal` program needs to be run as the `root` or `sudo` user.

```
sudo ./wireshark-terminal
```

Result of outgoing traffic:

```
No.   Time       Source                                  Destination                             Protocol Length Info
Capturando pacotes na interface 'eth0'. Pressione Ctrl+C para sair.
1     0.087535   N/A                                     N/A                                     ARP      60     Who has 169.254.196.19? Tell 192.168.1.150
2     0.475484   26:2f:d0:71:28:20                       01:80:c2:00:00:13                       Non-IP   60     N/A
3     0.475485   26:2f:d0:71:28:20                       01:80:c2:00:00:0e                       Non-IP   60     N/A
4     0.563930   N/A                                     N/A                                     ARP      60     Who has 169.254.196.19? Tell 192.168.1.150
5     0.878399   60:83:e7:5f:9a:f9                       ff:ff:ff:ff:ff:ff                       Non-IP   60     N/A
6     1.034234   60:83:e7:41:e5:fe                       ff:ff:ff:ff:ff:ff                       Non-IP   60     N/A
7     1.375848   N/A                                     N/A                                     ARP      60     Who has 192.168.1.20? Tell 192.168.1.100
8     1.375848   N/A                                     N/A                                     ARP      60     Who has 192.168.1.242? Tell 192.168.1.100
9     1.385256   192.168.1.70                            8.8.8.8                                 UDP      72     Port 36507 -> 53
10    1.385274   192.168.1.70                            8.8.8.8                                 UDP      72     Port 36507 -> 53
11    1.420434   8.8.8.8                                 192.168.1.70                            UDP      120    Port 53 -> 36507
12    1.420636   8.8.8.8                                 192.168.1.70                            UDP      156    Port 53 -> 36507
13    1.420780   192.168.1.70                            104.26.10.35                            TCP      74     Port 50134 -> 443
14    1.450985   104.26.10.35                            192.168.1.70                            TCP      74     Port 443 -> 50134
15    1.451017   192.168.1.70                            104.26.10.35                            TCP      66     Port 50134 -> 443
16    1.451334   192.168.1.70                            104.26.10.35                            TCP      583    Port 50134 -> 443
17    1.482157   104.26.10.35                            192.168.1.70                            TCP      66     Port 443 -> 50134
18    1.484424   104.26.10.35                            192.168.1.70                            TCP      1514   Port 443 -> 50134
19    1.484445   192.168.1.70                            104.26.10.35                            TCP      66     Port 50134 -> 443
20    1.484560   104.26.10.35                            192.168.1.70                            TCP      1458   Port 443 -> 50134
```
