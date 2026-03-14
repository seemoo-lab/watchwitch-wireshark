# <img src="doc/img/logo.png" alt="WatchWitch logo" height=42 width=42 valign=bottom /> WatchWitch Wireshark Dissectors

This repository is a collection of various dissectors, scripts, and patches to assist in understanding the proprietary protocols of the Apple Watch used via Bluetooth and WiFi while utilizing the existing Wireshark ecosystem.	

<p align="center">
  <img src="doc/img/alloy_bluetooth.png"/>
</p>

## Structure
``doc/`` contains various documentation about this project\
``lua/`` contains the dissectors written in Lua\
``patches/`` contains ESP patches for older Wireshark versions\
``scripts/`` contains extra tools to dump data from a capture

## Requirements
No extra dependencies are necessary for the Lua dissectors since Wireshark ships with a Lua interpreter. (tshark alone does not, you may need to install Lua manually in this case)\
Wireshark >=v4.6 is needed for ESP decryption support. Source patches for Wireshrk v4.2 to v4.5 are available.

## Installation
- Move the lua plugins into:\
  ``~/.local/lib/wireshark/plugins/`` (Linux/MacOS)\
  ``%APPDATA%/Wireshark/plugins/`` (Windows)\
  and reload with Ctrl + Shift + L

## Aquiring Bluetooth captures 
Follow the instructions in [doc/capture.md](doc/capture.md) for setting up PacketLogger and capturing Bluetooth data.

## Supported Protocols
- Magnet 
- NRLP
- SHOES
- NWSC
- Alloy Control/Data

Additionally there are stub dissectors for the following protocols
- BT.TS
- CLink

More information about each protocol can be found under [doc/protocols.md](doc/protocols.md).

## Limitations
- Some commands are not or only partially implemented due to missing documentation.
- If the pairing/initialization part of the capture is missing then it is necessary to manually assign dissectors to the L2CAP channels/TCP ports.
- Some frames contain multiple payloads which can cause the tree view to become quite long due to reassembly.
- If the ESP packets are not dissected due to missing keys or an issue, some other heuristic dissectors that are shipped with Wireshark may try to mistakenly dissect the encrypted data. This could cause random crashes and is an issue with Wireshark itself! It is recommended to turn off unrelated protocols under ``Analyze -> Enabled Protocols``.

## References
- Nils Rollshausen, **WatchWitch: Investigating Apple Watch Interoperability and Security**, unpublished thesis, Master’s thesis, _Technical University of Darmstadt_, 2023.
- PyATV, **PyATV Documentation: Companion Link**, URL: https://pyatv.dev/documentation/protocols/#companion-link (visited on 08/29/2024)

## Authors
- **Nojus** ([@pabloaul](https://github.com/pabloaul))
- **Sebastian** ([@sebinbash](https://github.com/sebinbash))
