nwsc_proto = Proto("nwsc", "Apple Network Service Connectors")

local nwsc_flag_responses = {
  [0x0000]="Invalid",
  [0x4000]="Rejected",
  [0x8000]="Accepted"
}

-------- ADD KNOWN FIELDS HERE --------
local f = nwsc_proto.fields
  f.len =      ProtoField.uint16("nwsc.len", "Length", base.DEC)
  f.port =     ProtoField.uint16("nwsc.port", "Port", base.DEC)
  f.flag =     ProtoField.uint16("nwsc.flag", "NWSC Response Flag", base.HEX, nwsc_flag_responses)
  f.seq =      ProtoField.bytes ("nwsc.sequence", "Sequence Number", base.NONE) -- figure.9 protocols.pdf
  f.uuid =     ProtoField.bytes ("nwsc.uuid", "UUID", base.NONE)
  f.snamelen = ProtoField.uint8 ("nwsc.service_len", "Service Name Length", base.DEC)
  f.sname =    ProtoField.string("nwsc.service_name", "Service Name", base.ASCII)
  f.sig =      ProtoField.bytes ("nwsc.signature", "Public Signature (ed25519)", base.NONE)
  f.pub_key =  ProtoField.bytes ("nwsc.public_key", "Public Key (ed25519)", base.NONE)


-- possible ways to check for nwsc:
  -- does nwsc length field fit to entire buffer-2 (never observed nwsc being split)
  -- is tcp seq number 0 or 1? (the only valid connections i've seen were when this was the case, this may be the most reliable indicator!)
  -- response: is a valid flag set? (see nwsc_flag_responses)
  -- response: is buffer 44? (fixed length response)
  -- request: is port field valid? (61314 or 61315)
  -- request: is buffer between 81 and 348? (nwsc req no uuid vs nwsc req with max string length)

-- returns 0 for invalid, 1 for response, 2 for request
function check_nwsc(buffer, pinfo, tree)
  local blen = buffer:len()
  if blen < 44 or blen > 348 then return 0 end -- absolute size check
  local len_field = buffer(0,2):uint()
  local sec_field = buffer(2,2):uint()

  if len_field+2 == blen then -- exact size check (data is within one packet)
    if blen == 44 then -- response fixed size
      if nwsc_flag_responses[sec_field] ~= nil then -- check for valid response flag
        return 1 -- this is a response
      end
    elseif blen >= 81 then -- request min-max size
      if sec_field == 61314 or sec_field == 61315 then -- does port look plausible
        return 2 -- this is a request
      end
    end
  end
  return 0 -- probably not nwsc
end

function nwsc_proto.dissector(buffer, pinfo, tree)
  if buffer():len() == 0 then return 0 end
  local offset = 0

  local nwsc_type = check_nwsc(buffer, pinfo, tree)
  if nwsc_type == 0 then return 0 end

  pinfo.cols.protocol = nwsc_proto.name
  pinfo.cols.info:set("NWSC ")

  -- length
  local nwsc_length = buffer(offset, 2):uint()
  local subtree = tree:add(nwsc_proto, buffer(offset, nwsc_length + 2), "NWSC Message")
  subtree:add(f.len, buffer(offset, 2))
  offset = offset + 2

  if nwsc_type == 1 then -- NWSC response
    pinfo.cols.info:append("Response ")

    subtree:add(f.flag, buffer(offset, 2))
    if nwsc_flag_responses[buffer(offset, 2):uint()] == "Accepted" then -- call alloy on this connection
      local alloyport = pinfo.dst_port
      DissectorTable.get("tcp.port"):add(alloyport, Dissector.get("alloy")) -- hack: this is likely not the intended way but it works
    end
    offset = offset + 2

    subtree:add(f.seq, buffer(offset, 8))
    offset = offset + 8

    subtree:add(f.pub_key, buffer(offset, 32))
    offset = offset + 32

  else -- NWSC request
    pinfo.cols.info:append("Request ")
    
    subtree:add(f.port, buffer(offset, 2))
    offset = offset + 2

    subtree:add(f.seq, buffer(offset, 8))
    offset = offset + 8

    local sname_length = 0
    if buffer(offset, 4):uint() ~= 0 then
      subtree:add(f.uuid, buffer(offset, 16))
      offset = offset + 16

      sname_length = buffer(offset, 1):uint()
      subtree:add(f.snamelen, buffer(offset, 1))
      offset = offset + 1

    else
      pinfo.cols.info:append("(No UUID) ")
      subtree:add(f.uuid, buffer(offset, 4))
      offset = offset + 4

    end
    if sname_length > 0 then
      subtree:add(f.sname, buffer(offset, sname_length))
      offset = offset + sname_length

    end
    subtree:add(f.sig, buffer(offset, 64))
    offset = offset + 64

  end

  return offset
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(61314, nwsc_proto)
tcp_port:add(61315, nwsc_proto)
