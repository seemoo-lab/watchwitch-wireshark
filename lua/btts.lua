btts_proto = Proto("btts", "Apple BT.TS")

local btts_types = { -- those are some command values i have seen during usage, accuracy absolutely not guranteed
  [0x01]="phone to watch, hello",
  [0x02]="watch to phone, hello",
  [0x10]="watch to phone, unknown",
  [0x11]="phone to watch, unknown",
  [0x12]="watch to phone, unknown",
  [0x13]="phone to watch, unknown",
  [0x14]="watch to phone, unknown",
  [0x20]="phone to watch, unknown",
  [0x21]="watch to phone, unknown",
  [0x22]="watch to phone, unknown"
}

-------- ADD KNOWN FIELDS HERE --------
local f = btts_proto.fields 
  f.echo = ProtoField.bool("btts.echo", "Echo", 8, {"yes","no"}, 0x01, "Echo message")
  f.echo_count = ProtoField.uint8("btts.echo_count", "Echo Count", base.DEC)
  f.seq = ProtoField.new("Sequence Number", "btts.seq", ftypes.UINT8, nil, base.DEC, 0x7e)
  f.ack = ProtoField.new("Acknowledgement Number", "btts.ack", ftypes.UINT8, nil, base.DEC, 0x3f)
  f.type = ProtoField.uint8("btts.type", "Payload Type", base.HEX, btts_type)
  f.length = ProtoField.uint16("btts.length", "Payload Size", base.DEC)
  f.data = ProtoField.bytes("btts.data", "Payload", base.NONE)

function btts_proto.dissector(buffer, pinfo, tree)
  if buffer:len() == 0 then return end

  pinfo.cols.protocol = btts_proto.name
  local subtree = tree:add(btts_proto, buffer(), "Apple BT.TS")
  local offset = 0 -- what byte we are currently looking at

  -- first NRLP byte
  if bit.band(buffer(offset, 1):uint(), 0x1) == 0x1 then -- handle echo bit (bit 0x1)
    pinfo.cols.info:set("Echo Count sent")

    subtree:add(f.echo, buffer(offset, 1)) -- byte1[_______X]
    offset = offset + 1

    subtree:add(f.echo_count, buffer(offset, 1))
    offset = offset + 1

    return offset -- stop dissector here. it's "that weird short packet"
  end

  subtree:add(f.seq, buffer(offset, 1)) -- byte1[_XXXXXX_]
  offset = offset + 1

  subtree:add(f.ack, buffer(offset, 1)) -- byte2[__XXXXXX]
  offset = offset + 1

  -- missing any info about this protocol
  -- functionality of this dissector is mostly a stub
  subtree:add(f.data, buffer(offset))
  offset = offset + buffer(offset):len()

  return offset
end