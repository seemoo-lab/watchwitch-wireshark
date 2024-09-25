shoes_proto = Proto("shoes", "Apple SHOES Proxy")

local shoes_request_types = {
  [0x01]="Hostname", [0x04]="Hostname",
  [0x02]="IPv6",     [0x05]="IPv6",
  [0x03]="IPv4",     [0x06]="IPv4",
  [0x07]="Bonjour",  [0x08]="Bonjour"
}

local shoes_tlv_types = {
  [0x01]="Traffic Class",
  [0x02]="Flags",
  [0x03]="Bundle ID",
  [0x04]="Network Info",
  [0x05]="Multipath"
}

-------- ADD KNOWN FIELDS HERE --------
local f = shoes_proto.fields 
  f.null = ProtoField.uint8("shoes.null", "Null", base.HEX)
  f.len = ProtoField.uint16("shoes.len", "Length", base.DEC)
  f.type = ProtoField.uint8("shoes.type", "Type", base.HEX, shoes_request_types)
  f.port = ProtoField.uint16("shoes.port", "Port", base.DEC)

  f.destlen = ProtoField.uint8("shoes.destlen", "Hostname Length", base.DEC)
  f.host = ProtoField.string("shoes.hostname", "Hostname", base.NONE)
  f.ipv4 = ProtoField.ipv4("shoes.ipv4", "IPv4")
  f.ipv6 = ProtoField.ipv6("shoes.ipv6", "IPv6")
  f.bonjour = ProtoField.string("shoes.bonjour", "Bonjour Service", base.NONE)
  f.data = ProtoField.bytes("shoes.data", "Data", base.NONE)

  f.tlv_type = ProtoField.uint8("shoes.tlv.type", "Type", base.HEX, shoes_tlv_types)
  f.tlv_len = ProtoField.uint16("shoes.tlv.len", "Length", base.DEC)
  f.tlv_val = ProtoField.bytes("shoes.tlv.val", "Value", base.NONE)

-- returns true if shoes
function check_shoes(buffer, pinfo, tree)
  local length = buffer:len()
  local shoes_length = buffer(0,2):uint()
  -- valid length
  if length <= 4 or shoes_length + 2 >= length then return true end
  -- valid opcode
  if shoes_request_types[buffer(2,1):uint()] == nil then
    return true
  end
  return false
end

function shoes_proto.dissector(buffer, pinfo, tree)
  local offset = 0

  offset = dissect_shoes(buffer, pinfo, tree, offset)
  Dissector.get("tls"):call(buffer(offset):tvb(), pinfo, tree)
end

function parse_tlvs(buffer, pinfo, tree, offset)
  local buflen = buffer:len()
  while offset < buflen do

    local type = buffer(offset, 1):uint()
    offset = offset + 1

    local length = buffer(offset, 2):uint()
    offset = offset + 2

    local value = buffer(offset, length)
    offset = offset + length
    
    local tlv_type = shoes_tlv_types[type] or "unknown"
    local subtree = tree:add(shoes_proto, buffer(offset - length - 3, length + 3), "TLV: "..tlv_type..": "..value:string( ))
    subtree:add(f.tlv_type, buffer(offset - length - 3, 1))
    subtree:add(f.tlv_len, buffer(offset - length - 2, 2))
    subtree:add(f.tlv_val, buffer(offset - length, length))
  end
  
  return offset
end
      
function dissect_shoes(buffer, pinfo, tree, offset)
  local initial_offset = offset
  local length = buffer:len()
  if check_shoes(buffer, pinfo, tree) then return 0 end
  pinfo.cols.protocol = shoes_proto.name
  pinfo.cols.info:set("SHOES Request ")
  
  local shoes_length = buffer(offset, 2):uint()
  local subtree = tree:add(shoes_proto, buffer(offset, shoes_length + 2), "SHOES Proxy") -- +2 due to length field
  subtree:add(f.len, buffer(offset, 2))
  offset = offset + 2

  subtree:add(f.type, buffer(offset, 1))
  local type = buffer(offset, 1):uint()
  offset = offset + 1

  subtree:add(f.port, buffer(offset, 2))
  local port = buffer(offset, 2)
  offset = offset + 2

  -- parse request types
  if type == 0x01 or type == 0x04 then
    pinfo.cols.info:append("[Hostname]")

    subtree:add(f.destlen, buffer(offset, 1))
    local destlen = buffer(offset, 1):uint()
    offset = offset + 1

    subtree:add(f.host, buffer(offset, destlen))
    offset = offset + destlen

  elseif type == 0x02 or type == 0x05 then
    pinfo.cols.info:append("[IPv6]")
    
    subtree:add(f.ipv6, buffer(offset, 16))
    offset = offset + 16

  elseif type == 0x03 or type == 0x06 then
    pinfo.cols.info:append("[IPv4]")

    subtree:add(f.ipv4, buffer(offset, 4))
    offset = offset + 4
  
  elseif type == 0x07 or type == 0x08 then
    pinfo.cols.info:append("[Bonjour]")
    
    local destlen = buffer(offset, 1):uint()
    subtree:add(f.destlen, buffer(offset, 1))
    offset = offset + 1
    
    subtree:add(f.host, buffer(offset, destlen))
    offset = offset + destlen
  
  end

  if (shoes_length + 2) > offset then
    -- parse TLVs
    offset = parse_tlvs(buffer(initial_offset, shoes_length + 2), pinfo, subtree, offset)
  end

  return offset
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(62742, shoes_proto)

