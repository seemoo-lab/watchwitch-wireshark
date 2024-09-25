magnet_proto = Proto("magnet", "Apple Magnet")

local magnet_cmds = {
  [0x01]="Advertise Remote Services",
  [0x02]="Response Remote Services ",
  [0x03]="Service Channel Created",
  [0x04]="Service Channel Accepted",
  [0x05]="Service Added",
  [0x06]="Service Removed",
  [0x07]="Service Removal Acknowledged",
  [0x08]="Error Response",
  [0x09]="Version Info",
  [0x70]="Request Time Data", -- not in paper; "TimeSyncCorrection"
  [0x71]="Time Data type 1",
  [0x72]="Time Data type 2",
  [0x90]="DID info",
  [0x91]="CL data"
}

local magnet_version = 0x0b -- hack: assume new magnet for parsing with 2 byte length field

-------- ADD KNOWN FIELDS HERE --------
local f = magnet_proto.fields 
-- magnet base
  f.cmd = ProtoField.uint8("magnet.op","Magnet Opcode", base.HEX, magnet_cmds)
  f.len = ProtoField.uint16("magnet.len", "MagnetL Data Length", base.DEC)
  f.len_old = ProtoField.uint8("magnet.len_old", "MagnetS Data Length", base.DEC)
-- cmd 0x01/05: remote services
  f.service_amount = ProtoField.uint8("magnet.service_amount", "Service Count", base.DEC)
  f.service_len = ProtoField.uint8("magnet.service_len", base.DEC)
  f.sid = ProtoField.uint16("magnet.sid", "Service ID", base.DEC)
  f.service_flags = ProtoField.uint8("magnet.service_flags", "Service Flags", base.HEX)
  f.service_name_len = ProtoField.uint8("magnet.service_name_len", "Service Name Length", base.DEC)
  f.service_name = ProtoField.string("magnet.service_name", "Service Name", base.ASCII)
  f.service_option = ProtoField.uint8("magnet.service_option", "Service Option", base.HEX)
-- cmd 0x02: remote services response
  f.service_count = ProtoField.uint8("magnet.service_count", "Service Count", base.DEC)
-- cmd 0x03/04: service channel creation/acceptance
  f.cid = ProtoField.uint16("magnet.cid","Channel ID", base.HEX)
-- cmd 0x09: get version
  f.ver = ProtoField.uint8("magnet.ver", "Magnet Version", base.DEC)
  f.ver_flags = ProtoField.uint32("magnet.ver_flags", "Magnet Version Flags", base.HEX)
-- cmd 0x71: time data
  f.timestamp = ProtoField.absolute_time("magnet.timestamp", "Unix Timestamp", base.UTC)
-- unknown data
  f.data = ProtoField.bytes("magnet.data", "Unknown Data", base.NONE)

local known_services = { -- mapping service name to what dissector to call. 1: NRLP, 2: CLink, 3: BT.TS
  ["com.apple.terminusLink"] = 1,
  ["com.apple.terminusLink.urgent"] = 1,
  ["CLink"] = 2,
  ["CLinkHP"] = 2,
  ["com.apple.BT.TS"] = 3
}

local magnet_service_mapping = {} -- contains service ID to service name mapping

function call_dissector(cid, type) -- call specific dissector to given BTL2CAP channel ID
  if type == 0x00 then
    return
  elseif type == 0x01 then
    DissectorTable.get("btl2cap.cid"):add(cid, Dissector.get("nrlp"))
  elseif type == 0x02 then
    DissectorTable.get("btl2cap.cid"):add(cid, Dissector.get("clink"))
  elseif type == 0x03 then
    DissectorTable.get("btl2cap.cid"):add(cid, Dissector.get("btts"))
  end
end

function magnet_proto.dissector(buffer, pinfo, tree)
  local length = buffer:len()
  if length == 0 then return end 
  pinfo.cols.protocol = magnet_proto.name

  local subtree = tree:add(magnet_proto, buffer(), "Apple MAGNET")
  local offset = 0 -- what byte we are currently looking at

  subtree:add(f.cmd, buffer(offset, 1))
  local cmd = buffer(offset, 1):uint()
  if cmd == 0x09 then magnet_version = 0x00 end -- version requests happen with the old magnet length field size
  pinfo.cols.info:set(magnet_cmds[cmd])
  offset = offset + 1 -- move forward a byte
  
  if magnet_version <= 0x08 then 
    subtree:add(f.len_old, buffer(offset, 1))
    offset = offset + 1
  else
    subtree:add_le(f.len, buffer(offset, 2))
    offset = offset + 2
  end


  if cmd == 0x01 then ------ PARSE SE RVICES
    subtree:add(f.service_amount, buffer(offset, 1))
    local service_amount = buffer(offset, 1):uint()
    offset = offset + 1

    for i = 0, service_amount - 1, 1
    do
      local service_len = buffer(offset, 1):uint()
      local subtree_service = subtree:add(magnet_proto, buffer(offset, service_len + 1))
      --subtree_service:add(f.service_len, buffer(offset,1)) -- too verbose
      offset = offset + 1
      
      subtree_service:add_le(f.sid, buffer(offset, 2))
      local service_id = buffer(offset, 2):le_uint()
      offset = offset + 2
      
      subtree_service:add(f.service_flags, buffer(offset, 1))
      offset = offset + 1

      --subtree_service:add(f.service_name_len, buffer(offset+3,1)) -- too verbose
      local service_name_len = buffer(offset, 1):uint()
      offset = offset + 1
      
      subtree_service:add(f.service_name, buffer(offset, service_name_len))
      local service_name = buffer(offset, service_name_len):string()  
      offset = offset + service_name_len

      subtree_service:add(f.service_option, buffer(offset, 1))
      offset = offset + 1

      subtree_service:set_text("Service: "..service_name.." ("..service_id..")")
      magnet_service_mapping[service_id] = service_name -- add service ID mapping to table
    end

  elseif cmd == 0x02 then -- PARSE SERVICES RESPONSE
    subtree:add(f.service_count, buffer(offset, 1))
    local service_count = buffer(offset, 1):uint()
    offset = offset + 1

    for i = 0, service_count - 1, 1
    do
      local sid = buffer(offset, 2):le_uint()
      local service_name = magnet_service_mapping[sid] or "unknown!" -- look up service name in table
      local marker = subtree:add(magnet_proto, buffer(offset, 2), "Service Name: "..service_name.." ("..sid..")")
      offset = offset + 2
    end

  elseif cmd == 0x03 then -- PARSE SERVICE CHANNEL CREATION
    subtree:add_le(f.cid, buffer(offset, 2))
    local cid = buffer(offset, 2):le_uint()
    offset = offset + 2
    
    --subtree:add_le(f.sid, buffer(offset, 2)) -- redundant due to marker
    local sid = buffer(offset, 2):le_uint()
    local service_name = magnet_service_mapping[sid] or "unknown!"
    local marker = subtree:add(magnet_proto, buffer(offset, 2), "Service Name: "..service_name.." ("..sid..")")
    offset = offset + 2

    -- register dissector for channel if service is known and implemented
    call_dissector(cid, known_services[service_name] or 0)

  elseif cmd == 0x04 then -- PARSE SERVICE CHANNEL ACCEPTANCE   
    subtree:add(f.data, buffer(offset, 1))
    offset = offset + 1

    --subtree:add_le(f.sid, buffer(offset, 2)) -- redundant due to marker
    local sid = buffer(offset, 2):le_uint()
    local service_name = magnet_service_mapping[sid] or "unknown!"
    local marker = subtree:add(magnet_proto, buffer(offset, 2), "Service Name: "..service_name.." ("..sid..")")
    offset = offset + 2

    local cid = buffer(offset, 2):le_uint()
    subtree:add_le(f.cid, buffer(offset, 2))
    offset = offset + 2
    
    -- register dissector for channel if service is known and implemented
    call_dissector(cid, known_services[service_name] or 0)

  elseif cmd == 0x05 then -- PARSE SERVICE ADDED
    subtree:add_le(f.sid, buffer(offset, 2))
    local service_id = buffer(offset, 2):le_uint()
    offset = offset + 2

    subtree:add(f.data, buffer(offset, 1)) -- unknown byte
    offset = offset + 1

    --subtree:add(f.service_name_len, buffer(offset,1)) -- too verbose
    local service_name_len = buffer(offset, 1):uint()
    offset = offset + 1

    subtree:add(f.service_name, buffer(offset, service_name_len))
    local service_name = buffer(offset, service_name_len):string()
    offset = offset + service_name_len

    subtree:add(f.service_option, buffer(offset, 1))
    offset = offset + 1
    
    magnet_service_mapping[service_id] = service_name

  elseif cmd == 0x06 then -- PARSE SERVICE REMOVED
    subtree:add_le(f.sid, buffer(offset, 2))
    offset = offset + 2

  elseif cmd == 0x07 then -- PARSE SERVICE REMOVED ACCEPTANCE
    subtree:add_le(f.sid, buffer(offset, 2))
    offset = offset + 2

    subtree:add(f.data, buffer(offset))
    offset = offset + buffer(offset):len()

  elseif cmd == 0x08 then -- PARSE ERROR RESPONSE (structure unknown)
    subtree:add(f.data, buffer(offset))
    offset = offset + buffer(offset):len()

  elseif cmd == 0x09 then -- PARSE VERSION
    subtree:add(f.ver, buffer(offset, 1))
    magnet_version = buffer(offset, 1):uint()
    offset = offset + 1

    subtree:add(f.ver_flags, buffer(offset, 4))
    offset = offset + 4

  elseif cmd == 0x70 then -- TIME REQUEST (nothing to parse)

  elseif cmd == 0x71 then -- PARSE TIME RESPONSE TYPE 1
    local ts = buffer(offset, 8):le_uint64()
    local secs = ts:tonumber() / 1e9
    local nsecs= ts:tonumber() % 1e9
    subtree:add(f.timestamp, buffer(offset, 8), NSTime.new(secs, nsecs))
    offset = offset + 8

    subtree:add(f.data, buffer(offset)) -- todo: figure out rest of date structure
    offset = offset + buffer(offset):len()

  elseif cmd == 0x72 then -- PARSE TIME RESPONSE TYPE 2 (structure unknown)
    subtree:add_le(f.data, buffer(offset))
    offset = offset + buffer(offset):len()

  elseif cmd == 0x90 then -- PARSE DIDINFO (structure unknown)
    subtree:add_le(f.data, buffer(offset))
    offset = offset + buffer(offset):len()

  elseif cmd == 0x91 then -- PARSE CLDATA (structure unknown)
    subtree:add_le(f.data, buffer(offset))
    offset = offset + buffer(offset):len()

  else -- handle everything else
    subtree:add_le(f.data, buffer(offset))
    offset = offset + buffer(offset):len()

  end

  return offset
end

local channel_id = DissectorTable.get("btl2cap.cid")
channel_id:add(0x3a, magnet_proto) -- magnet is fixed channel on 0x3a