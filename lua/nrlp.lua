nrlp_proto = Proto("nrlp", "Network Relay Link Protocol")

local MTU = 8192 -- max nrlp payload size (not accurate! only used for plausibility checks)

local nrlp_types = {
  [0x00]="Pad0 (no op)",
  [0x01]="PadN (no op)",
  [0x02]="UncompressedIP",
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

local f = nrlp_proto.fields
  f.echo = ProtoField.bool("nrlp.echo", "Echo", 8, {"yes","no"}, 0x01, "Echo message")
  f.echo_count = ProtoField.uint8("nrlp.echo_count", "Echo Count", base.DEC)
  f.seq = ProtoField.new("Sequence Number", "nrlp.seq", ftypes.UINT8, nil, base.DEC, 0x7e)
  f.ack = ProtoField.new("Acknowledgement Number", "nrlp.ack", ftypes.UINT8, nil, base.DEC, 0x3f)
  f.type = ProtoField.uint8("nrlp.type", "Payload Type", base.HEX, nrlp_types)
  f.length = ProtoField.uint16("nrlp.length", "Payload Size", base.DEC)
  f.data = ProtoField.bytes("nrlp.data", "Payload", base.NONE)
  f.checksum = ProtoField.uint16("nrlp.checksum", "Checksum", base.HEX)

local reassembled_message = {} -- [pinfo.number]
local started_at_offset = {} -- [pinfo.number]
local split_headers = {} -- [pinfo.number]

-- this all needs to be indexed by cid because else the state carries over to other channels and breaks stuff
local remaining_bytes = {} -- [cid]: when nil -> no fragment transfer in progress
local prev_seq = {} -- [cid]: seq from last frame for continuity check
local seq_continuity_broken_at = {} -- [cid]: at what frame the continuity gets broken

local split_header_bytes = {} -- [cid]: split header bytes from previous frame

local started_at_seq = {} -- [cid]: at what seq the fragmented message begins
local seq_fragments = {} -- [cid][seq]: up to 64 fragments
local seq = {} -- [cid]: current seq

l2cap_cid = Field.new("btl2cap.cid") -- multiple instances of nrlp will share the state, so we need to differentiate them by cid

function nrlp_proto.dissector(buffer, pinfo, tree)
  ---- PREPARATIONS ----
  if buffer():len() == 0 then return end 
  pinfo.cols.protocol = nrlp_proto.name
  local subtree = tree:add(nrlp_proto, buffer(), "NRLP (Frame) ")
  local offset = 0
  cid = l2cap_cid()() -- non-local scope required, not sure why

  if seq_fragments[cid] == nil then
    seq_fragments[cid] = {}
  end
  ---- SEQACK ----
  seq[cid] = bit.rshift(bit.band(buffer(0, 1):uint(), 0x7e), 1)
  if seqack(buffer, pinfo, subtree) == -1 then return end -- exit early if Echo Count
  if not is_seq_continuous(pinfo, seq[cid]) then 
    subtree:append_text("[sequence was not continuous past "..seq_continuity_broken_at[cid].."]")  
    return -- stop further dissection if the seq is not continuous
  end 
  offset = offset + 2
  ---- NRLP HELLO ----
  if buffer(offset):len() >= 8 and buffer(offset, 8):string() == "TERMINUS" then
    pinfo.cols.info:set("NRLP Hello")
    offset = offset + 8 -- skip terminus string
    subtree:add(f.data, buffer(offset))
    return 8 + buffer(offset):len()
  end
  ---- SPLIT HEADER + FRAGMENTATION ----
  if pinfo.visited then
    if split_headers[pinfo.number] ~= nil then -- found a stored header for this edgecase!
      buffer = split_headers[pinfo.number]:tvb("fixed header (from memory)") -- split_headers contains the entire frame 
    end

    offset = offset + present(buffer(offset), pinfo, subtree)
  else
    if split_header_bytes[cid] ~= nil then -- found split header, injecting this in current buffer
      local reconstructed = buffer(0, offset):bytes()..split_header_bytes[cid]..buffer(offset):bytes() -- prepend the missing header
      split_headers[pinfo.number] = reconstructed -- cache the frame with fixed header
      buffer = reconstructed:tvb("fixed header (in place)") -- replace buffer
      split_header_bytes[cid] = nil -- reset state
    end

    offset = offset + prepare(buffer(offset), pinfo, subtree)
  end
  ---- NRLP DATA ----
  while offset < buffer():len() and buffer(offset):len() > 3 do -- the second statement is needed for when the frame boundary lies within the header :(
    offset = offset + nrlp(buffer(offset), pinfo, subtree, pinfo.visited)
  end
  ---- SPLIT HEADER ----
  if buffer(offset):len() == 1 or buffer(offset):len() == 2 or buffer(offset):len() == 3 then -- save the split header so we can prepend it in the next frame
    split_header_bytes[cid] = buffer(offset, buffer(offset):len()):bytes()
  end
end

function prepare(buffer, pinfo, tree)
  local offset = 0

  if remaining_bytes[cid] == nil then -- no need to reassemble
    return 0
  end

  if remaining_bytes[cid] <= buffer():len() then -- this is the last fragment
    started_at_offset[pinfo.number] = remaining_bytes[cid]

    add_fragment(buffer(offset, remaining_bytes[cid]), seq[cid])

    reassemble(buffer, pinfo, tree, started_at_seq[cid], seq[cid])

    offset = offset + started_at_offset[pinfo.number]
    remaining_bytes[cid] = nil
    return offset
  end

  -- this is a middle fragment
  add_fragment(buffer(), seq[cid])
  started_at_offset[pinfo.number] = remaining_bytes[cid] -- to skip the frame in the second phase
  remaining_bytes[cid] = remaining_bytes[cid] - buffer():len() -- move remaining bytes forward for the next frame
  return started_at_offset[pinfo.number] -- just so we skip the while loop afterwards
end

function present(buffer, pinfo, tree)
  local offset = 0

  if reassembled_message[pinfo.number] ~= nil then
    local message = reassembled_message[pinfo.number]:tvb("reassembled message")
    nrlp(message, pinfo, tree, true)
  end

  ---- Skip ahead past fragmented data ----
  if started_at_offset[pinfo.number] ~= nil then -- skipping fragments
    offset = started_at_offset[pinfo.number]
    tree:append_text("["..offset.." bytes from fragment] ")
    assert(split_headers[pinfo.number] == nil, "bytes were skipped forward despite there being a header at the beginning!") -- if we prepend a header then there must be a header at the beginning
  end

  return offset
end

function seqack(buffer, pinfo, tree) -- parsing first two bytes of every nrlp frame
  if bit.band(buffer(0, 1):uint(), 0x1) == 0x1 then -- byte1[_______X]
    pinfo.cols.info:set("NRLP Echo Count sent")
    tree:add(f.echo, buffer(0, 1)) 
    tree:add(f.echo_count, buffer(1, 1))
    return -1
  end
  tree:add(f.seq, buffer(0, 1)) -- byte1[_XXXXXX_]
  tree:add(f.ack, buffer(1, 1)) -- byte2[__XXXXXX]
  return 2
end

function is_seq_continuous(pinfo, current_seq)
  assert(current_seq >= 0 and current_seq <= 63, "invalid seq number. got: "..(current_seq or "nil"))

  if prev_seq[cid] == nil then -- init seq counter
    prev_seq[cid] = current_seq
    return true
  end

  if seq_continuity_broken_at[cid] ~= nil then -- there is a break in the packet, avoid dissecting past the break
    return pinfo.number < seq_continuity_broken_at[cid]
  end

  if pinfo.visited == true then -- there was no break in the entire capture
    return true
  end

  if (prev_seq[cid] + 1) % 64 == current_seq then -- good
    prev_seq[cid] = current_seq
    return true
  end

  seq_continuity_broken_at[cid] = pinfo.number -- bad
  return false
end

function nrlp(buffer, pinfo, tree, stateless) -- nrlp with header and checksum
  assert(buffer():len() >= 3, "nrlp was called with no/partial header present")

  local ptree = tree:add(nrlp_proto, buffer(), "NRLP (Payload) ")

  local type = buffer(0, 1):uint()
  ptree:add(f.type, buffer(0, 1))

  assert(nrlp_types[type] ~= nil, "an unknown nrlp type was used: "..(type or "nil"))

  local length = buffer(1, 2):uint()
  ptree:add(f.length, buffer(1, 2))

  assert(length < MTU, "the payload length is longer than seems plausible: "..(length or "nil"))

  if length + 2 > buffer(3):len() then -- this is the start of a fragmented message
    ptree:append_text(" needs reassembly")
    if not stateless then
      remaining_bytes[cid] = length + 2 - buffer(3):len() -- setting remaining bytes to skip ahead
      seq_fragments[cid][seq[cid]] = buffer():bytes() -- add the beginning of the fragment
      started_at_seq[cid] = seq[cid] -- set the beginning mark so we know from what seq to start assemblying from
    end
    return 3 + length + 2 -- end early to avoid out of range when parsing fragmented data 
  end

  return 3 + nrlp_data(buffer(3), pinfo, ptree, type, length, stateless) -- header + (data + checksum)
end

function nrlp_data(buffer, pinfo, tree, payload_type, payload_length, stateless) -- only nrlp content + checksum
  assert(payload_length <= buffer():len(), "payload length is larger than the buffer! payload: "..payload_length.." buffer: "..buffer():len())

  tree:add(f.data, buffer(0, payload_length))

  plumbing(buffer(0, payload_length), pinfo, tree, payload_type)

  tree:add(f.checksum, buffer(payload_length, 2)) -- todo: checksum calculation

  remaining_bytes[cid] = nil -- we parsed the full message, so we have no remaining bytes left

  return payload_length + 2
end

function reassemble(buffer, pinfo, tree, started_at, ending_at)
  local i = started_at
  defragmented = ByteArray.new()

  while i%64 ~= (ending_at + 1) % 64 do -- ending_at+1 so that we include the frame that we are currently at 
    defragmented:append(seq_fragments[cid][i%64])
    seq_fragments[cid][i%64] = nil
    i = i + 1
  end

  reassembled_message[pinfo.number] = defragmented
end

function add_fragment(buffer, i)
  seq_fragments[cid][i] = buffer():bytes()
end

function plumbing(buffer, pinfo, tree, type) -- calls dissector by type on given buffer
  assert(nrlp_types[type] ~= nil, "plumbing was called with unknown nrlp type: "..type)
  pinfo.cols.info:set("NRLP -> "..nrlp_types[type])
  if type == 0x02 then
    Dissector.get("ip"):call(buffer():tvb(), pinfo, tree)
  elseif type == 0x03 then
    Dissector.get("6lowpan"):call(buffer():tvb(), pinfo, tree)
  elseif type == 0x04 then
    Dissector.get("isakmp"):call(buffer():tvb(), pinfo, tree)
  elseif type == 0x05 then
    tree:add(f.data, buffer())
  elseif type == 0x64 or type == 0x65 or type == 0x68 or type == 0x69 then
    Dissector.get("esp"):call(buffer():tvb(), pinfo, tree)
  elseif type == 0x66 or type == 0x67 then
    Dissector.get("tcp"):call(buffer():tvb(), pinfo, tree)
  end
end