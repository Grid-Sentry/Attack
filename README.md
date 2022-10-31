# HOW TO SETUP:

1. Clone the git repo: https://github.com/keith-gray-powereng/goose
2. Copy the `goose` directory from the repo into that directory where the exploit is located.
3. Paste this code in `goose.py` file inside the `goose` directory from step 2

```python
from struct import pack

from scapy.packet import Packet
from scapy.fields import XShortField, XByteField, ConditionalField
from scapy.all import bind_layers

class GOOSEPDU(Packet):
    name = "GOOSEPDU"
    fields_desc = [
        XByteField("ID",0x61),
        XByteField("DefLen",0x81),
         # NOTE: Length comes from this byte's Least Significant Nibble. Not sure what MSN is for.
        ConditionalField(XByteField("PDU1ByteLen",0x00),lambda pkt:pkt.DefLen^0x80 == 1), 
        ConditionalField(XShortField("PDU2BytesLen",0x0000),lambda pkt:pkt.DefLen^0x80 == 2)
    ]

bind_layers(GOOSE, GOOSEPDU)
```
4. Run the exploit.


# 1. Masquerade Exploit:

```bash
slsuser@slsuser-vm:/opt/analysis_scripts$ python3 goose_exploit.py -h
usage: python3 goose_exploit.py [options]

GOOSE MiTM Masquerade Exploit.

options:
  -h, --help
        show this help message and exit
  --pcapfile PCAPFILE
        Name of the PCAP file to process.
  --livecapture
        Start the live capture. (default: False)
  --output OUTPUT
        Name of the ouput file (should be with .pcap extension)
        Example: 
        ----------
            python3 goose_exploit.py --livecapture --output <filename>
```

# 2. Replay Attack

```bash
slsuser@slsuser-vm:/opt/analysis_scripts$ python3 goose_replay.py -h
usage: python3 goose_replay.py [options]

GOOSE Replay Attack.

options:
  -h, --help
        show this help message and exit
  --pcapfile PCAPFILE
        Name of the PCAP file to process.
  --livecapture
        Start the live capture. (default: False)
  --output OUTPUT
        Name of the ouput file (should be with .pcap extension)
        Example: 
        ----------
            python3 goose_replay.py --livecapture --output <filename>

```
# REFERENCES:

https://idahogray.github.io/blog/generating-goose-messages.html

https://github.com/cutaway-security/goosestalker
