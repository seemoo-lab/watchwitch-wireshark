# Implemented Protocols

## Magnet 
This is the entrypoint for our dissector via Bluetooth. It operates on a fixed BTL2CAP channel of 0x003a.\
The protocol is responsible for advertising device capabilities and dynamically negotiating channels for services.\
For every service there are two L2CAP channels created, one for each direction.\
Implemented at release is the plumbing to call the NRLP, CLink and BT.TS dissector.\
During development version 0x10 and 0x11 were observed.

## Network Relay Link (NRLP)
Plumbing protocol for encryption/negotiation/data/reassembly (IKEv2, 6LOWPAN, ESP, etc.).\
It carries a SEQ/ACK counter which also appear on other protocols going over Bluetooth, likely for the purpose of reassembly and reordering.\
Since the underlying L2CAP dissector does not have extra support for reassemblying data over multiple segments, it was necessary to reimplement the logic for this in the NRLP dissector.

## BT.TS
Placeholder/Stub dissector due to few/no documentation.\
Also was very low in volume on our given dataset.

## CLink
Placeholder/Stub dissector due to few/no documentation.\
This protocol has already been partially documented by pyatv which you can read about [here](https://pyatv.dev/documentation/protocols/#companion-link).\
It was deemed low priority for us and also needs tools to dump the keys which we don't have and requires support for decrypting ChaCha20-Poly1305 aswell.\
Because this is not encapsulated in the same style as the IPSec VPN tunnel carrying Alloy, it makes the patches made not reusable for this case.

## ESP (patches)
The preferred encryption standard used by the watch IPSec ESP tunnel is ChaCha20-Poly1305-IIV.\
Although Wireshark has support for IPSec ESP payloads, this specific encryption standard is not supported.\
A patch to Wireshark for our specific usecase is available under [patches/](patches/)

## SHOES
Network Proxy for internet sharing between watch and phone.\
A connection can be initialized via Hostname, IPv4, IPv6 and Bonjour.\
It will typically contain a few TLVs and beyond the given shoes_length, a TLS handshake segment.

## Network Service Connectors (NWSC)
Used on a newly created TCP connection to the Alloy ports, the first two messages exchanged are NWSC Request and Response.\
This protocol relies on heuristics so that it can be differentiated from Alloy data which is being used on the exact same TCP ports.\
The service name, UUID, ed25519 signature/public key are exchanged and if the connection is valid/accepted then the Alloy dissector will get called to the requesting port.

## Alloy
On successful NWSC establishment, Alloy will get called. It build on top of TCP and can be spread out over multiple packets which means that we require reassembly.\
Reassembly is trivial for protocols built upon TCP and Wireshark offers the ``dissect_tcp_pdus`` function for this case.\
The hard part for Alloy was figuring out how to make the function ignore the first two messages (NWSC) since they have a different header structure.\
We solved this by using a heuristic approach to determine if a packet is of type NWSC, Alloy Control or Alloy Data. This is represented in our helper function ``pdu_length`` which needs to figure out what header structure is being used so that it can get the length field correctly. Since the first two messages will have already been parsed by the NWSC dissector, it will not be attempted to be parsed by Alloy.\
There are two different types of Alloy being used with a different set of commands depending on which port is being talked on (61314 or 61315).\
Alloy Control (on ids-control-channel) will initialize channels with a UUID, channel account, service and name. The initialization also carries a source port field which however is not useful for our case since they seem to not match to the ports that are actually used in the communication.\
Alloy Data carries a significant amount of information in the form of bplists, Protobuf, Dicts and more.\
To parse the payloads for many of the data encapsulation formats, the following tool may be very useful: [bytewitch](https://rec0de.net/open/bytewitch/).\
During development CC version 5 and Protocol version 15 were observed.