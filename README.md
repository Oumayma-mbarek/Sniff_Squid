# SniffSquid 
Sniff Squid is the long lost cousin of wireshark, he is just younger and dumber 

Its main goal is to sniff packets and display them layer by layer 

## Implemented Protocols 
note: SniffSquid does not implement all protocols (for now), here is a list of the implemented protocols that it is able to parse. Some protocols are not fully implemented (they do not display all possible options)

- Link layer : 
  - Ethernet
- Network layer: 
  - IPV4 
  - IPV6
  - ARP
- Transport layer: 
  - TCP
  - UDP 
- Application layer:
  - HTTP
  - FTP
  - SMTP
  - TELNET
  - POP3
  - IMAP
  - BOOTP
  - DHCP
  - DNS
  
## Using SniffSquid
### Building
SniffSquid is compiled using [PowerMake](https://github.com/mactul/powermake) which is a compiler that allows automating the process. 
This tool is developed by Macéo TULOUP. It generated a Makefile on its own by detecting all .c files, .h and so on

It can be easily installed via pip : 
``` bash 
pip3 install -U powermake
```
Once PowerMake is installed run makefile.py using python : 
``` bash
python3 makefile.py 
```
> **Note:** The generated program will be located at ```./build/Linux/x64/release/bin/sniff_squid```.
the -r option can be used to force recompiling, the -v option to see the commands run and the -d option to compile the program in debug mode:
``` bash
python3 makefile.py -rvd
```
> The generated program will be located at ```./build/Linux/x64/debug/bin/sniff_squid```.
Other options are available, the complete list can be found using:
```bash
python3 makefile.py -h
```

### Running  
the binary is located in ``` ./build/Linux/x64/release/bin/sniff_squid```.

The program supports both offline and live captures. 

For live captures the interface should be specified using the ``` -i <interface>``` option 
example: ```sudo ./build/Linux/x64/release/bin/sniff_squid -i wlan0 ```

For offline captures, the name of a valid file should be specified after the ``` -o <file> ``` option: 
example: ```sudo ./build/Linux/x64/release/bin/sniff_squid -o offline_captures/http.cap ```

The offline mode reads .cap, .pcap or .pcapng files.

Filters can be added using the ``` -f <filter>``` option.

Another supported option is the ``` -v [1-3] ``` which specified a verbosity level between 1 and 3, 3 being the most verbose, 2 displays a single line for each protocol and 1 displays the whole packet in a single line 

Eventually ``` -h ``` option displays help 


## Project logic

### Thidr-party libraries 
- **libpcap** For receiving packets on different interfaces and reading from and saving to a file, released under the BSD license, 
- **dash** For parsing command-line arguments. This is a library implemented by Valentin FOULON, released under the MIT licence

### Architecture 
- Source files are in the src folder
- Include files are in the include folder
- Testing files for offline captures are in the offline_caputres folder
- main.c reads the command line and handles arguments and then calls sniff_squid.c
- sniff_squid.c is responsible for parsing packets 
- dash folder contains the dash library mentioned above 
- the build folder contains the generated binary 
- src/text.c is used for parsing all text protocols : HTTP/FTP/SMTP/POP3 and IMAP and it prints the output like in wireshark (16 bytes of hexa and their equivalent next to them, unknown caracters are printed as a dot)
  
## IMPORTANT 
- This project could be imporved in several ways; adding more protocols, enhancing security, handling all options of each protocol ... 
- It is by far not done, but it allows the parsing of many protocols already 
- This program is prone to error since the security was not a main concern here so there is a possiblity of error on invalid captures or overloaded fields of certain protocol headers 
