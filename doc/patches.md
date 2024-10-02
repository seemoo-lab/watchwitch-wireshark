# Running patched Wireshark for ESP decryption

Due to the Wireshark IPSec/ESP dissector missing support for ChaCha20-Poly1305-IIV, it is needed to manually patch this in.
This is required to see data beyond the ESP encryption.

## Installation
### NixOS
1. Enter [../patches/](patches/) directory

2. Run `nix-shell` (nixpkgs within was pinned to nixos-24.05)

3. You are now in a shell with the patched Wireshark after compilation finished. Run `wireshark` to start.

### Other OS
1. Acquire Wireshark Source [v4.2.6](https://gitlab.com/wireshark/wireshark/-/archive/v4.2.6/wireshark-v4.2.6.tar.gz) (newer versions likely will work too until they touch the IPSec/ESP code)

2. Extract and move patch to root of the source code

3. Apply patch: `git apply chacha20.patch`. For wireshark v4.4.0 to v4.5.0, use `chacha20-v450.patch`

4. Follow Wireshark build instructions for your respective environment

## Usage
Add your keys in the ESP SAs menu, reachable by:
``Edit -> Preferences -> Protocols -> ESP -> ESP SAs (Edit)``
or
``Right click frame that contains ESP Data -> Protocol Preferences -> Encapsulating Security Payload -> ESP SAs``

The patch will add the option for ChaCha20 encryption and the option to set "Any" in the Protocol (because there usually is no IP Header)

For the case of dissecting Apple Watch data, it is recommended to turn off "Check sequence numbers of ESP frames"

### ESP SA
- Protocol should be set to `Any`
- Src/Dest IP can remain empty
- Encryption should be set to `ChaCha20 with Poly1305 IIV [RFC8750]`
- SPI and Encryption Key should be filled out like usual
- Encryption Key should be 36 bytes (32B key followed by 4B salt)
- Authentication should be set to `NULL`
