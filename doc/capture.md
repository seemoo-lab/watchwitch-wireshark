# How to obtain a Bluetooth Capture

## Prerequisites
- iPhone
- Apple Watch
- Mac

## Steps

1. Download and install the [Bluetooth Development Profile](https://developer.apple.com/bug-reporting/profiles-and-logs/?name=bluetooth) on your iPhone

2. Install [Xcode](https://developer.apple.com/xcode/) (11 or greater) on your Mac

3. Download the [Additional Tools for Xcode](https://developer.apple.com/download/more/?=xcode) and open the Hardware Folder

4. Copy *packetLogger* to your Application folder

5. Connect the iPhone to your Mac via a cable

6. Open packetLogger and start a new capture: ``File -> New iOS Trace``

6. Set Device Filter to iPhone

7. Make sure to capture the initial pairing process of the Apple Watch which contains the L2CAP channel ID assignments. Alternatively you can manually decode NRLP packets in Wireshark by selecting the L2CAP packets and right clicking ``Decode As...``.

8. After you're done, save your capture as a `.pklg` capture: ``File -> Save As...``

## Capturing with ESP Keys

To be able to decrypt ESP payloads, we need to extract key material from the iPhone using [Frida](https://frida.re). This requires a jailbroken iPhone with Frida installed.

Run the supplied script before connecting the watch and the phone:

```bash
frida -U terminusd -l scripts/dumpEspKeys.js
```

This will produce the following output, which you can use to set up ESP SAs in wireshark:

```
ESP encryption mode is ChaCha20Poly1305IIV
SPI 0x06595ff4 Encryption Key 0xee6d5c0c7ccb8971e4f339ca3f08bd0557898752315b1fe3daf5307ff40ad02768894559
SPI 0x03273281 Encryption Key 0x7c5f67eb2d04cf36c02e87a9ca3a53e885233434aaf8696ecf1c484be88f27bdb076de5c
```