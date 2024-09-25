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

