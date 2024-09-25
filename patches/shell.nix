let
   pkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/2527da1ef492c495d5391f3bcf9c1dd9f4514e32.tar.gz") {}; # pinned to nixos-24.05
   wireshark-dev = pkgs.wireshark.overrideAttrs(oldAttrs: {
      patches = [ ./chacha20.patch ];
   });
in 
   pkgs.mkShell {
      buildInputs = [ wireshark-dev ];
   }
