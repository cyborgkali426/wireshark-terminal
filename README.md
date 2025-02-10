# wireshark-terminal

`wireshark-terminal` is similar to the Wireshark we know and use, the difference is that `wireshark-terminal` runs in the terminal in a simple and compact way.
Remember that the wireshark-terminal program can only be run as sudo. If it's used on mobile, the phone needs to be root as well.

For the program to work run `sudo ./wireshark-terminal`.

Configurations before using the `wireshark-terminal` program:

```
sudo apt-get update && sudo apt-get install libpcap-dev
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
