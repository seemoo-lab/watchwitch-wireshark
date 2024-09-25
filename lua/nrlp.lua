nrlp_proto = Proto("nrlp", "Network Relay Link Protocol")

local nrlp_type = {
  [0x02]="UncompressedIP?",
  [0x03]="Encapsulated6LoWPAN",
  [0x04]="IKEv2",
  [0x05]="Echo service",
  [0x64]="ESP_ClassD",
  [0x65]="ESP_ClassD_ECT0",
  [0x66]="TCP",
  [0x67]="TCP_ECT0",
  [0x68]="ESP_ClassC",
  [0x69]="ESP_ClassC_ECT0"
}

-------- ADD KNOWN FIELDS HERE --------
local f = nrlp_proto.fields 
  f.echo = ProtoField.bool("nrlp.echo", "Echo", 8, {"yes","no"}, 0x01, "Echo message")
  f.echo_count = ProtoField.uint8("nrlp.echo_count", "Echo Count", base.DEC)
  f.seq = ProtoField.new("Sequence Number", "nrlp.seq", ftypes.UINT8, nil, base.DEC, 0x7e)
  f.ack = ProtoField.new("Acknowledgement Number", "nrlp.ack", ftypes.UINT8, nil, base.DEC, 0x3f)
  f.type = ProtoField.uint8("nrlp.type", "Payload Type", base.HEX, nrlp_type)
  f.length = ProtoField.uint16("nrlp.length", "Payload Size", base.DEC)
  f.data = ProtoField.bytes("nrlp.data", "Payload", base.NONE)
  f.checksum = ProtoField.uint16("nrlp.checksum", "Checksum", base.HEX)
  f.fragment = ProtoField.bytes("nrlp.fragment", "Fragment", base.NONE)
  f.reassembled = ProtoField.bool("nrlp.reassembled", "Reassembled segment")
  f.reassembled_in = ProtoField.uint16("nrlp.reassembled_in", "Reassembled in frame", base.DEC)

local l2cap_cid = Field.new("btl2cap.cid")

local nrlp_fragments = {}

function nrlp_proto.dissector(buffer, pinfo, tree)
  local length = buffer:len()
  local offset = 0
  local reassembled = false

  while offset < length do
    local result = dissect_nrlp(buffer, pinfo, tree, offset, reassembled)
    if result > 0 then
      -- sucessfully dissected packet
      offset = offset + result
    elseif result == 0 then
      -- dissection failed, packet is not for us
      -- for manual reassembly, record packet
      if pinfo.can_desegment ~= 1 then
        new_tvb = reassemble_nrlp(buffer, pinfo, tree, 0, 0)
        if new_tvb ~= nil then
          result = dissect_nrlp(new_tvb, pinfo, tree, 0, true)
          if result > 0 then
            -- dissection of reassembled packet was sucessful
            offset = result
            buffer = new_tvb
            length = new_tvb:len()
            reassembled = true
          else
            -- dissection of reassembled packet failed: reject packet
            return 0
          end
        else
          -- no reassembly: reject packet
          return 0
        end
      else
        -- default behaviour: reject packet
        return 0
      end
    else
      -- result is negative, this is a fragmented packet
      if pinfo.can_desegment == 1 then
        -- reassembly is supported by underlying layer
        pinfo.desegment_offset = offset
        -- get absolte number of missing bytes
        result = -result
        -- tell wireshark how many more bytes we need
        pinfo.desegment_len = result
        -- return the consumed bytes
        return offset
      else
        -- reassembly is not supported by underlying layer, use reassemble_nrlp
        reassemble_nrlp(buffer, pinfo, tree, offset, result)
        return offset
      end
    end
  end

  return offset
end

-- dissects the first SEQ/ACK bytes of the NRLP packet
function dissect_seq_ack(buffer, pinfo, subtree, offset)
  subtree:add(f.seq, buffer(offset, 1))
  subtree:add(f.ack, buffer(offset + 1, 1))
end

-- dissects NRLP packet given the tvb, pktinfo, tree and offset
-- returns the length of the dissected NRLP packet, or the number
-- of missing bytes as a negative number if the packet only contains
-- a fragment or 0 if the packet could not be dissected
function dissect_nrlp(buffer, pinfo, tree, offset, reassembled)
  local length = buffer:len()
  if length == 2 and offset == 0 then
    -- QoS/Echo packet
    pinfo.cols.protocol:set("NRLP ECHO")
    local subtree = tree:add(nrlp_proto, buffer(), "Apple NRLP")
    pinfo.cols.info:set("NRLP Echo")
    subtree:add(f.echo, buffer(offset,1))
    subtree:add(f.echo_count, buffer(offset + 1, 1))
    return 2
  elseif length <= 4 then
    -- too small
    return 0
  else
    -- valid length
    -- check for TERMINUS packet
    if buffer(offset + 2):len() >= 8 and buffer(offset + 2, 8):string() == "TERMINUS" then
      pinfo.cols.protocol = nrlp_proto.name
      pinfo.cols.info:set("NRLP TERMINUS")
      local subtree = tree:add(nrlp_proto, buffer(), "Apple NRLP")
      return length
    end

    local nrlp_length = 0
    local seq_ack_length = 0
    if offset == 0 and reassembled == false then
      nrlp_length = buffer(offset + 3, 2):uint()
      seq_ack_length = 2
    else
      nrlp_length = buffer(offset + 1, 2):uint()
    end
    -- check if length field matches L2CAP frame length
    if nrlp_length + 5 + seq_ack_length <= (length - offset) then
      -- discard invalid packets
      local type = buffer(offset + seq_ack_length, 1):uint()
      if nrlp_type[type] == nil then
        return 0
      end
      -- valid packet, add subtree
      -- one or multiple packets in this frame
      pinfo.cols.protocol = nrlp_proto.name
      local subtree = tree:add(nrlp_proto, buffer(0, nrlp_length), "Apple NRLP")
      -- first & second NRLP byte (seq, ack) - only dissect if this is the first packet in L2CAP frame
      if seq_ack_length > 0 then
        dissect_seq_ack(buffer, pinfo, subtree, offset)
      else
      end
      -- third NRLP byte (payload type)
      subtree:add(f.type, buffer(offset + seq_ack_length, 1))
      -- NRLP payload length
      subtree:add(f.length, buffer(offset + seq_ack_length + 1, 2))
      -- NRLP data
      subtree:add(f.data, buffer(offset + seq_ack_length + 3, nrlp_length))
      -- call dissectors for payload type
      dissect_nrlp_payload(buffer, pinfo, tree, type, offset + seq_ack_length + 3, nrlp_length)
      -- NRLP checksum
      local checksum = buffer(offset + seq_ack_length + 3 + nrlp_length, 2):uint()
      local calculated_checksum = calculate_nrlp_checksum(buffer(offset + seq_ack_length, nrlp_length + 3):tvb(), checksum)
      subtree:add(f.checksum, buffer(offset + seq_ack_length + 3 + nrlp_length, 2))
      if checksum ~= calculated_checksum then
        subtree:add(string.format("WARNING: checksum does not match (Calculated: 0x%04x)", calculated_checksum))
      end
      -- Is fragmented?
      if reassembled == true then
        subtree:add(f.reassembled, true)
      end
      return nrlp_length + 5 + seq_ack_length -- alternatively: length
    -- first fragment - heuristic: nrlp_length is bigger than remaining buffer and smaller than 4096
    elseif nrlp_length + 7 > length - offset and nrlp_length < 4096 then
      -- discard packets with invalid type
      local type = buffer(offset + seq_ack_length, 1):uint()
      if nrlp_type[type] == nil then
        return 0
      end
      -- packet stretches over multiple frames
      -- 5 bytes (3 bytes NRLP header, 2 bytes checksum)
      local missing_bytes = nrlp_length - buffer(offset):len() + 5
      return -missing_bytes
      -- continued fragment
    else
      -- discard - these get picked up by the main function as possible cont. segments
      return 0
    end
  end
end


function dissect_nrlp_payload(buffer, pinfo, tree, type, offset, length)
  if type == 0x02 then
    pinfo.cols.info:set("NRLP -> UncompressedIP Payload")
    Dissector.get("ip"):call(buffer(offset, length):tvb(), pinfo, tree)
  elseif type == 0x03 then -- PARSE 6LOWPAN
    pinfo.cols.info:set("NRLP -> 6LOWPAN Payload")
    Dissector.get("6lowpan"):call(buffer(offset, length):tvb(), pinfo, tree)
  elseif type == 0x04 then -- PARSE IKEv2
    pinfo.cols.info:set("NRLP -> IKEv2 Payload")
    Dissector.get("isakmp"):call(buffer(offset, length):tvb(), pinfo, tree)
  elseif type == 0x05 then -- PARSE ECHO
    pinfo.cols.info:set("NRLP -> Echo Service")
    subtree:add(f.data, buffer(offset, length))
  elseif type == 0x64 or type == 0x65 or type == 0x68 or type == 0x69 then -- PARSE ESP
    pinfo.cols.info:set("NRLP -> ESP Payload")
    Dissector.get("esp"):call(buffer(offset, length):tvb(), pinfo, tree)
  elseif type == 0x66 or type == 0x67 then -- PARSE TCP
    pinfo.cols.info:set("NRLP -> TCP Payload")
    Dissector.get("tcp"):call(buffer(offset, length):tvb(), pinfo, tree)
  end
end

function calculate_nrlp_checksum(buffer)
  local length = buffer:len()
  local type = buffer(0, 1):uint()
  if type >= 0x64 then
    -- only calculate over type and length bytes
    local type = buffer(0, 1):uint()
    local length0 = buffer(1, 1):uint()
    local length1 = buffer(2, 1):uint()
    local b0 = bit.bxor(length0, bit.rshift(type, 4))
    local b1 = bit.bxor(length1, bit.band(bit.lshift(type, 4), 0xff))
    return (bit.lshift(b0, 8) + b1)
  else
    -- internet checksum (RFC1071)
    local bytes = buffer:bytes()
    local sum = 0

    -- pad to even length
    if length % 2 ~= 0 then
      bytes:append(ByteArray.new("00"))
    end

    for i = 0, (length / 2) - 1 do
      sum = sum + bytes(i * 2, 2):uint()
    end

    local shifted = bit.rshift(sum, 16)
    while shifted > 0 do
      sum = bit.band(sum, 0xffff) + shifted
      shifted = bit.rshift(sum, 16)
    end

    sum = bit.bnot(sum)
    sum = bit.band(sum, 0xffff) -- truncate to 16 bits
    return sum
  end
end

function reassemble_nrlp(buffer, pinfo, tree, offset, result)
  local cid = l2cap_cid().value
  if nrlp_fragments[cid] == nil then
    nrlp_fragments[cid] = {}
  end
  local frame = pinfo.number
  if nrlp_fragments[cid][frame] == nil then
    nrlp_fragments[cid][frame] = {}
  end
  --local subtree = tree:add(nrlp_proto, buffer(offset), "Apple NRLP")
  --subtree:add(f.fragment, buffer(offset))
  -- handle SEQ-ACK bytes
  if offset == 0 then
    offset = offset + 2
  end
  nrlp_fragments[cid][frame]["fragment"] = buffer(offset):bytes()
  nrlp_fragments[cid][frame]["offset"] = offset
  nrlp_fragments[cid][frame]["remaining"] = result

  -- search for start fragment (only for continuing fragments)
  local idx = frame
  local start_fragment = nrlp_fragments[cid][idx]
  --local between_fragments = {}
  --while start_fragment["remaining"] ~= 0 do
  if result == 0 then
    -- this is a continuing segment
    while idx >= 0 do
      idx = idx - 1
      if nrlp_fragments[cid][idx] ~= nil then
	break
      end
    end
    if idx > 0 then
      start_fragment = nrlp_fragments[cid][idx]
      nrlp_fragments[cid][idx]["reassembled"] = frame
    end
  else
    -- this is a first segment
    pinfo.cols.protocol = nrlp_proto.name
    pinfo.cols.info:append("[NRLP Fragment]")
    local subtree = tree:add(nrlp_proto, buffer(offset), "Apple NRLP")
    subtree:add(f.fragment, buffer(offset))
    if nrlp_fragments[cid][frame]["reassembled"] ~= nil then
      subtree:add(f.reassembled_in, nrlp_fragments[cid][frame]["reassembled"])
    end
  end
  --end

  -- reassembled byte array
  -- if NRLP message starts at beginning of L2CAP payload, remove SEQ-ACK headers
  if idx < frame then
    local reassembled_bytes = ByteArray.new()
    reassembled_bytes = reassembled_bytes..start_fragment["fragment"]..buffer(offset):bytes()
    local reassembled_tvb = reassembled_bytes:tvb("Reassembled NRLP")
    return reassembled_tvb
  end
end
