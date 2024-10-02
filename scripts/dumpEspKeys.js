// hook NetworkExtension to dump ESP keys negotiated with the Apple Watch
// usage: frida -U terminusd -l dumpEspKeys.js

console.log("reloaded")

function readHex(pointer, length) {
  let res = ""
  for(var i = 0; i < length; i++) {
    const hexByte = pointer.add(i).readU8().toString(16)
    res += (hexByte.length == 1 ? "0" + hexByte : hexByte)
  }
  return res
}

try {
  Interceptor.attach(ObjC.classes.NEIKEv2ChildSA["- setResponderSendEncryptionKey:"].implementation, {
    onEnter(args) {
      this.self = new ObjC.Object(args[0])
    },
    onLeave(retval) {
      const proposal = this.self.chosenProposal()
      const localSPI = proposal.spi().toString().toLowerCase()
      
      const remoteSPI = proposal.remoteSPI().toString().toLowerCase()

      const outgoingEncryptionKey = readHex(this.self.outgoingEncryptionKey().bytes(), this.self.outgoingEncryptionKey().length())
      const incomingEncryptionKey = readHex(this.self.incomingEncryptionKey().bytes(), this.self.incomingEncryptionKey().length())

      console.log(`ESP encryption mode is ${proposal.encryptionProtocol()}`)
      console.log(`SPI 0x${localSPI} Encryption Key 0x${outgoingEncryptionKey}`)
      console.log(`SPI 0x${remoteSPI} Encryption Key 0x${incomingEncryptionKey}`)

      if(this.self.outgoingIntegrityKey() != null || this.self.incomingIntegrityKey() != null) {
        console.log("WARNING: exptected integrity keys to be null but found:")
        console.log(`Outgoing Encryption Key ${outgoingEncryptionKey}`)
        console.log(`Incoming Encryption Key ${incomingEncryptionKey}`)
      }

    }
  })
} catch (error) {
  console.log("ERROR! Couldn't hook NEIKEv2ChildSA setResponderSendEncryptionKey method!")
}