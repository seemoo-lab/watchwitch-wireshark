clink_proto = Proto("clink", "Apple CLink")

-- most information borrowed from https://pyatv.dev/documentation/protocols/#companion-link and their github
local clink_types = {
  [0x00]="Unknown",
  [0x01]="NoOp",
  [0x03]="PS_Start",
  [0x04]="PS_Next",
  [0x05]="PV_Start",
  [0x06]="PV_Next",
  [0x07]="U_OPACK",
  [0x08]="E_OPACK",
  [0x09]="P_OPACK",
  [0x0a]="PA_Req",
  [0x0b]="PA_Rsp",
  [0x10]="SessionStartRequest",
  [0x11]="SessionStartResponse",
  [0x12]="SessionData",
  [0x20]="FamilyIdentityRequest",
  [0x21]="FamilyIdentityResponse",
  [0x22]="FamilyIdentityUpdate"
}

-------- ADD KNOWN FIELDS HERE --------
local f = clink_proto.fields 
  f.echo = ProtoField.bool("clink.echo", "Echo", 8, {"yes","no"}, 0x01, "Echo message")
  f.echo_count = ProtoField.uint8("clink.echo_count", "Echo Count", base.DEC)
  f.seq = ProtoField.new("Sequence Number", "clink.seq", ftypes.UINT8, nil, base.DEC, 0x7e)
  f.ack = ProtoField.new("Acknowledgement Number", "clink.ack", ftypes.UINT8, nil, base.DEC, 0x3f)
  f.type = ProtoField.uint8("clink.type", "Payload Type", base.HEX, clink_type)
  f.length = ProtoField.uint8("clink.length", "Payload Size", base.DEC)
  f.data = ProtoField.bytes("clink.data", "Payload", base.NONE)

function clink_proto.dissector(buffer, pinfo, tree)
  if buffer:len() == 0 then return end

  pinfo.cols.protocol = clink_proto.name
  local subtree = tree:add(clink_proto, buffer(), "Apple Companion Link")
  local offset = 0 -- what byte we are currently looking at

  -- first byte
  if bit.band(buffer(offset, 1):uint(), 0x1) == 0x1 then -- handle echo bit (bit 0x1)
    pinfo.cols.info:set("Echo Count sent")

    subtree:add(f.echo, buffer(offset,1)) -- byte1[_______X]
    offset = offset + 1

    subtree:add(f.echo_count, buffer(offset, 1))
    offset = offset + 1
    
    return offset -- stop dissector here. it's "that weird short packet"
  end

  subtree:add(f.seq, buffer(offset, 1)) -- byte1[_XXXXXX_]
  offset = offset + 1

  subtree:add(f.ack, buffer(offset, 1)) -- byte2[__XXXXXX]
  offset = offset + 1

  -- except for the first two or three messages, the rest will be encrypted
  -- therefore the functionality of this dissector is mostly a stub
  subtree:add(f.data, buffer(offset))
  offset = offset + buffer(offset):len()

  return offset
end