alloy_proto = Proto("alloy", "Apple Alloy")

local alloy_control_types = {
  [0x01]="Hello",
  [0x02]="SetupChannel",
  [0x03]="CloseChannel",
  [0x04]="CompressionRequest",
  [0x05]="CompressionResponse",
  [0x06]="SetupEncryptedChannel",
  [0x07]="FairplayHostSessionInfo",
  [0x08]="FairplayDeviceInfo",
  [0x09]="FairplayDeviceSessionInfo",
  [0x0a]="OTRNegotiationMessage",
  [0x0b]="EncryptControlChannel",
  [0x0c]="SuspendOTRNegotiationMessage",
  [0x0d]="SetupDirectChannel",
  [0x0e]="DirectMessageInfo"
}

local alloy_hello_tlv_types = {
  [0x00]="Min. compatible Protocol Version",
  [0x01]="Max. compatible Protocol Version",
  [0x02]="Instance ID",
  [0x03]="Capability Flags",
  [0x04]="Min. compatible Service Version",
  [0x05]="Device ID"
}

local alloy_data_types = {
  [0x00]="Data",
  [0x01]="Ack",
  [0x02]="KeepAlive",
  [0x03]="Protobuf",
  [0x04]="Handshake",
  [0x05]="Encrypted",
  [0x06]="Dictionary",
  [0x07]="AppAck",
  [0x08]="SessionInvitation",
  [0x09]="SessionAccept",
  [0x0a]="SessionDecline",
  [0x0b]="SessionCancel",
  [0x0c]="Session",
  [0x0d]="SessionEnd",
  [0x0e]="SMSText",
  [0x0f]="SMSTextDownload",
  [0x10]="SMSOutgoing",
  [0x11]="SMSDownloadOutgoing",
  [0x12]="SMSDeliveryReceipt",
  [0x13]="SMSReadReceipt",
  [0x14]="SMSFailure",
  [0x15]="Fragmented",
  [0x16]="ResourceTransfer",
  [0x17]="OTREncrypted",
  [0x18]="OTR",
  [0x19]="ProxyOutgoingNice",
  [0x1a]="ProxyIncomingNice",
  [0x1b]="TextMessage",
  [0x1c]="DeliveryReceipt",
  [0x1d]="ReadReceipt",
  [0x1e]="Attachment",
  [0x1f]="PlayedReceipt",
  [0x20]="SavedReceipt",
  [0x21]="ReflectedDeliveryReceipt",
  [0x22]="GenericCommand",
  [0x23]="GenericGroupMsgCommand",
  [0x24]="LocationShareOfferCommand",
  [0x25]="ExpiredAck",
  [0x26]="Error",
  [0x27]="ServiceMap",
  [0x28]="unknown?", -- missing
  [0x29]="SessionReinitiate",
  [0x2a]="SyndicationAction",
  [0x2b]="Retract",
  [0x2c]="Edit",
  [0x2d]="RecoverSync",
  [0x2e]="MarkAsUnread",
  [0x2f]="DeliveredQuietly",
  [0x30]="NotifyRecipient",
  [0x31]="RecoverJunk",
  [0x32]="SMSFilteringSettings"
}

local alloy_servicemap_tlv_types = {
  [0x01]="Reason",
  [0x02]="Stream ID",
  [0x03]="Topic"
}

-------- ADD KNOWN FIELDS HERE --------
local f = alloy_proto.fields
  f.cmd =  ProtoField.uint8 ("alloy.type", "Type", base.HEX)
  f.len =  ProtoField.uint16("alloy.len", "Length", base.DEC)
  f.len2 = ProtoField.uint32("alloy.len2", "Length", base.DEC)
  f.seq =  ProtoField.uint32("alloy.seq", "Sequence Number", base.DEC)
  f.data = ProtoField.bytes ("alloy.data", "Payload", base.NONE)
  f.unk =  ProtoField.bytes ("alloy.unknown", "Unknown Data", base.NONE)
-- Alloy control fields
  f.ccver =         ProtoField.string("alloy.ccver", "CC Version", base.ASCII)
  f.prodname =      ProtoField.string("alloy.prodname", "Product Name", base.ASCII)
  f.prodver =       ProtoField.string("alloy.prodver", "Product Version", base.ASCII)
  f.build =         ProtoField.string("alloy.build", "Build", base.ASCII)
  f.model =         ProtoField.string("alloy.model", "Model", base.ASCII)
  f.protover =      ProtoField.uint32("alloy.protover", "Protocol Version", base.DEC)
  f.channel_proto = ProtoField.uint8 ("alloy.channel_proto", "Channel Protocol", base.HEX)
  f.src_port =      ProtoField.uint16("alloy.source_port", "Source Port", base.DEC)
  f.dest_port =     ProtoField.uint16("alloy.dest_port", "Destination Port", base.DEC)
  f.sender_uuid =   ProtoField.string("alloy.sender_uuid", "Sender UUID", base.ASCII)
  f.rcvr_uuid =     ProtoField.string("alloy.receiver_uuid", "Receiver UUID", base.ASCII)
  f.account =       ProtoField.string("alloy.account", "Channel Account", base.ASCII)
  f.service =       ProtoField.string("alloy.service", "Channel Service", base.ASCII)
  f.name =          ProtoField.string("alloy.channel_name", "Channel Name", base.ASCII)
  f.ssrc =          ProtoField.uint32("alloy.ssrc", "Encrypted Channel SSRC", base.HEX)
  f.key =           ProtoField.bytes ("alloy.key", "Encrypted Channel Key", base.NONE)
  f.start_seq =     ProtoField.uint16("alloy.start_seq", "Encrypted Channel Start Sequence", base.DEC)
-- Alloy option TLVs
  f.tlv_type =             ProtoField.uint8 ("alloy.options.type", "Type", base.HEX, alloy_hello_tlv_types)
  f.tlv_len =              ProtoField.uint16("alloy.options.len", "Length", base.DEC)
  f.tlv_min_ver =          ProtoField.uint64("alloy.options.min_ver", "Min. compatible Protocol Version", base.DEC)
  f.tlv_max_ver =          ProtoField.uint64("alloy.options.max_ver", "Max. compatible Protocol Version", base.DEC)
  f.tlv_inst_id =          ProtoField.bytes ("alloy.options.instance_id", "Instance ID: ", base.NONE)
  f.tlv_cap_flags =        ProtoField.bytes ("alloy.options.capability_flags", "Capability Flags", base.NONE)
  f.tlv_cap_tinker =       ProtoField.bool  ("alloy.options.capability_flags.tinker", "Tinker", 16, nil, 0x400)
  f.tlv_cap_ipsec =        ProtoField.bool  ("alloy.options.capability_flags.ipsec", "Supports IPSec Link", 16, nil, 0x100)
  f.tlv_cap_checksum =     ProtoField.bool  ("alloy.options.capability_flags.checksum", "Checksum enabled", 16, nil, 0x80) 
  f.tlv_cap_dyn_services = ProtoField.bool  ("alloy.options.capability_flags.dynamic_services", "Dynamic Services", 16, nil, 0x8)
  f.tlv_cap_resume_trans = ProtoField.bool  ("alloy.options.capability_flags.resume_transfers", "Resume Resource Transfers", 16, nil, 0x4)
  f.tlv_cap_shared_otr =   ProtoField.bool  ("alloy.options.capability_flags.shared_otr", "Use shared OTR session", 16, nil, 0x2)
  f.tlv_cap_new_service =  ProtoField.bool  ("alloy.options.capability_flags.new_service", "New service supported", 16, nil, 0x1)
  f.tlv_srv_min_ver =      ProtoField.uint16("alloy.options.service_min_ver", "Min. compatible Service Version", base.DEC)
  f.tlv_dev_id =           ProtoField.bytes ("alloy.options.device_id", "Device ID: ", base.NONE)
  f.tlv_reason =           ProtoField.uint8 ("alloy.options.reason", "Reason", base.DEC)
  f.tlv_stream_id =        ProtoField.uint16("alloy.options.stream", "Stream ID", base.DEC)
  f.tlv_topic =            ProtoField.string("alloy.options.topic", "Topic", base.ASCII)
-- Alloy data fields
  f.frag_num =      ProtoField.uint32("alloy.fragment_number", "Fragment Number", base.DEC)
  f.frag_idx =      ProtoField.uint32("alloy.fragment_index", "Fragment Index", base.DEC)
  f.frag_ctr =      ProtoField.uint32("alloy.fragment_count", "Fragment Count", base.DEC)
  f.stream =        ProtoField.uint16("alloy.stream", "Stream", base.DEC)
  f.flags =         ProtoField.bytes ("alloy.flags", "Flags", base.BIN)
  f.flags_top =     ProtoField.bool  ("alloy.flags.top", "hasTopic", 8, nil, 0x10)
  f.flags_exp =     ProtoField.bool  ("alloy.flags.exp", "hasExpiryDate", 8, nil, 0x08)
  f.flags_app =     ProtoField.bool  ("alloy.flags.app", "wantsAppAck", 8, nil, 0x04)
  f.flags_cpr =     ProtoField.bool  ("alloy.flags.cpr", "compressed", 8, nil, 0x02)
  f.flags_epr =     ProtoField.bool  ("alloy.flags.epr", "expectsPeerResponse", 8, nil, 0x01)
  f.response_id =   ProtoField.string("alloy.response_id", "Response ID", base.ASCII)
  f.topic =         ProtoField.string("alloy.topic", "Topic", base.ASCII)
  f.msg_uuid =      ProtoField.string("alloy.msg_uuid", "Message UUID", base.ASCII)
  f.expiry_date =   ProtoField.uint32("alloy.expiry_date", "Expiry Date Timestamp", base.HEX)
  f.protobuf_type = ProtoField.uint16("alloy.protobuf_type", "Protobuf Type", base.HEX)
  f.is_response =   ProtoField.uint16("alloy.is_response", "Protobuf is Response", base.HEX)
  f.frame_ref =     ProtoField.framenum("alloy.reassembled_in", "Reassembled in Frame", base.NONE)

local alloy_fragments = {}

function parse_hello_tlvs(buffer, pinfo, tree, offset)
  local buflen = buffer:len()

  while offset + 3 < buflen do
    local type = buffer(offset, 1):uint()
    offset = offset + 1

    local length = buffer(offset, 2):uint()
    offset = offset + 2

    local value = buffer(offset, length)
    offset = offset + length

    local tlv_type = alloy_hello_tlv_types[type] or "unknown"
    local subtree = tree:add(alloy_proto, buffer(offset - length - 3, length + 3), "TLV: "..tlv_type)
    
    subtree:add(f.tlv_type, buffer(offset - length - 3, 1))
    --subtree:add(f.tlv_len, buffer(offset - length - 2, 2))
    if type == 0x00 then
      subtree:add(f.tlv_min_ver, buffer(offset - length, length))
      local min_ver = buffer(offset - length, length):uint()
      subtree:append_text(": "..min_ver)
    elseif type == 0x01 then
      subtree:add(f.tlv_max_ver, buffer(offset - length, length))
      local max_ver = buffer(offset - length, length):uint()
      subtree:append_text(": "..max_ver)
    elseif type == 0x02 then
      subtree:add(f.tlv_inst_id, buffer(offset - length, length))
      local inst_id = buffer(offset - length, length)
      subtree:append_text(": "..inst_id)
    elseif type == 0x03 then
      subtree:add(f.tlv_cap_flags, buffer(offset - length, length))
      subtree:add(f.tlv_cap_tinker, buffer(offset - length, length))
      subtree:add(f.tlv_cap_ipsec, buffer(offset - length, length))
      subtree:add(f.tlv_cap_checksum, buffer(offset - length, length))
      subtree:add(f.tlv_cap_dyn_services, buffer(offset - length, length))
      subtree:add(f.tlv_cap_resume_trans, buffer(offset - length, length))
      subtree:add(f.tlv_cap_shared_otr, buffer(offset - length, length))
      subtree:add(f.tlv_cap_new_service, buffer(offset - length, length))
      local cap_flags = buffer(offset - length, length)
      subtree:append_text(": "..cap_flags)
    elseif type == 0x04 then
      subtree:add(f.tlv_srv_min_ver, buffer(offset - length, length))
      local srv_min_ver = buffer(offset - length, length):uint()
      subtree:append_text(": "..srv_min_ver)
    elseif type == 0x05 then
      subtree:add(f.tlv_dev_id, buffer(offset - length, length))
      local device_id = buffer(offset - length, length)
      subtree:append_text(": "..device_id)
    end
  end
  return offset
end
-- todo/hack: tlv parsing could be generalized here
function parse_servicemap_tlvs(buffer, pinfo, tree, offset)
  local buflen = buffer:len()

  while offset + 3 < buflen do
    local type = buffer(offset, 1):uint()
    offset = offset + 1

    local length = buffer(offset, 2):uint()
    offset = offset + 2

    local value = buffer(offset, length)
    offset = offset + length

    local tlv_type = alloy_servicemap_tlv_types[type] or "unknown"
    local subtree = tree:add(alloy_proto, buffer(offset - length - 3, length + 3), "TLV: "..tlv_type)
    
    subtree:add(f.tlv_type, buffer(offset - length - 3, 1))
    --subtree:add(f.tlv_len, buffer(offset - length - 2, 2))
    if type == 0x01 then
      subtree:add(f.tlv_reason, buffer(offset - length, length))
      local reason = buffer(offset - length, length):uint()
      subtree:append_text(": "..reason)
    elseif type == 0x02 then
      subtree:add(f.tlv_stream_id, buffer(offset - length, length))
      local stream_id = buffer(offset - length, length)
      subtree:append_text(": "..stream_id)
    elseif type == 0x03 then
      subtree:add(f.tlv_topic, buffer(offset - length, length))
      local topic = buffer(offset - length, length):string()
      subtree:append_text(": "..topic)
      tree:append_text("with topic: "..topic)

    end
  end
  return offset
end

local function dissect_alloy_data(buffer, pinfo, tree)
  local offset = 0

  tree:add(f.cmd, buffer(offset, 1))
  local cmd = buffer(offset, 1):uint()
  offset = offset + 1

  tree:add(f.len2,buffer(offset, 4))
  local len = buffer(offset, 4):uint()
  offset = offset + 4

  pinfo.cols.info:append("[Data: " .. (alloy_data_types[cmd] or 'unknown') .. "] ")

  if cmd == 0x00 then -- Data
    tree:append_text("Data ")

    tree:add(f.seq, buffer(offset, 4))
    offset = offset + 4

    tree:add(f.stream, buffer(offset, 2))
    offset = offset + 2

    tree:add(f.flags,     buffer(offset, 1))
    tree:add(f.flags_top, buffer(offset, 1))
    tree:add(f.flags_exp, buffer(offset, 1))
    tree:add(f.flags_app, buffer(offset, 1))
    tree:add(f.flags_cpr, buffer(offset, 1))
    tree:add(f.flags_epr, buffer(offset, 1))
    local exp_bit_set = bit.band(buffer(offset, 1):uint(), 0x8) == 0x8 -- HANDLE EXP BIT
    local top_bit_set = bit.band(buffer(offset, 1):uint(), 0x10) == 0x10 -- HANDLE TOP BIT
    offset = offset + 1

    local response_id_len = buffer(offset, 4):uint()
    offset = offset + 4

    tree:add(f.response_id, buffer(offset, response_id_len))
    offset = offset + response_id_len

    local msg_uuid_len = buffer(offset, 4):uint()
    offset = offset + 4

    tree:add(f.msg_uuid, buffer(offset, msg_uuid_len))
    offset = offset + msg_uuid_len

    if top_bit_set then
      local topic_len = buffer(offset, 4):uint()
      offset = offset + 4

      tree:add(f.topic, buffer(offset, topic_len))
      local topname = buffer(offset, topic_len):string()
      offset = offset + topic_len
      
      tree:append_text("from topic: "..topname)
    end

    if exp_bit_set then
      local fake_data_size = buffer(offset):len()-4
      tree:add(f.data, buffer(offset, fake_data_size))
      offset = offset + fake_data_size
      
      tree:add(f.expiry_date, buffer(offset, 4))
      offset = offset + 4
    else
      tree:add(f.data, buffer(offset))
      offset = offset + buffer(offset):len()
    end

  elseif cmd == 0x01 then -- Ack
    tree:append_text("ACK ")

    tree:add(f.seq, buffer(offset, 4))
    offset = offset + 4

  elseif cmd == 0x03 then -- Protobuf
    tree:append_text("Protobuf ")

    tree:add(f.seq, buffer(offset, 4))
    offset = offset + 4

    tree:add(f.stream, buffer(offset, 2))
    offset = offset + 2

    tree:add(f.flags,     buffer(offset, 1))
    tree:add(f.flags_top, buffer(offset, 1))
    tree:add(f.flags_exp, buffer(offset, 1))
    tree:add(f.flags_app, buffer(offset, 1))
    tree:add(f.flags_cpr, buffer(offset, 1))
    tree:add(f.flags_epr, buffer(offset, 1))
    local exp_bit_set = bit.band(buffer(offset, 1):uint(), 0x8) == 0x8 -- HANDLE EXP BIT
    local top_bit_set = bit.band(buffer(offset, 1):uint(), 0x10) == 0x10 -- HANDLE TOP BIT
    offset = offset + 1

    local response_id_len = buffer(offset, 4):uint()
    offset = offset + 4

    tree:add(f.response_id, buffer(offset, response_id_len))
    offset = offset + response_id_len

    local msg_uuid_len = buffer(offset, 4):uint()
    offset = offset + 4

    tree:add(f.msg_uuid, buffer(offset, msg_uuid_len))
    offset = offset + msg_uuid_len

    if top_bit_set then
      local topic_len = buffer(offset, 4):uint()
      offset = offset + 4

      tree:add(f.topic, buffer(offset, topic_len))
      local topname = buffer(offset, topic_len):string()
      offset = offset + topic_len

      tree:append_text("from topic: "..topname)
    end

    tree:add(f.protobuf_type, buffer(offset, 2))
    offset = offset + 2

    tree:add(f.is_response, buffer(offset, 2))
    offset = offset + 2

    local payload_len = buffer(offset, 4):uint()
    offset = offset + 4

    tree:add(f.data, buffer(offset, payload_len))
    offset = offset + payload_len
    
    if exp_bit_set then
      tree:add(f.expiry_date, buffer(offset, 4))
      offset = offset + 4
    end

  elseif cmd == 0x04 then -- Handshake
    tree:append_text("Handshake ")

    tree:add(f.seq, buffer(offset, 4))
    offset = offset + 4

  elseif cmd == 0x06 then -- Dictionary
    tree:append_text("Dictionary ")

    tree:add(f.seq, buffer(offset, 4))
    offset = offset + 4

    tree:add(f.stream, buffer(offset, 2))
    offset = offset + 2

    tree:add(f.flags,     buffer(offset, 1))
    tree:add(f.flags_top, buffer(offset, 1))
    tree:add(f.flags_exp, buffer(offset, 1))
    tree:add(f.flags_app, buffer(offset, 1))
    tree:add(f.flags_cpr, buffer(offset, 1))
    tree:add(f.flags_epr, buffer(offset, 1))
    local exp_bit_set = bit.band(buffer(offset, 1):uint(), 0x8) == 0x8 -- HANDLE EXP BIT
    local top_bit_set = bit.band(buffer(offset, 1):uint(), 0x10) == 0x10 -- HANDLE TOP BIT
    offset = offset + 1

    local response_id_len = buffer(offset, 4):uint()
    offset = offset + 4

    tree:add(f.response_id, buffer(offset, response_id_len))
    offset = offset + response_id_len

    local msg_uuid_len = buffer(offset, 4):uint()
    offset = offset + 4

    tree:add(f.msg_uuid, buffer(offset, msg_uuid_len))
    offset = offset + msg_uuid_len

    if top_bit_set then
      local topic_len = buffer(offset, 4):uint()
      offset = offset + 4

      tree:add(f.topic, buffer(offset, topic_len))
      local topname = buffer(offset, topic_len):string()
      offset = offset + topic_len

      tree:append_text("from topic: "..topname)
    end

    if exp_bit_set then
      local fake_data_size = buffer(offset):len()-4 -- hack: there is no payload length field
      tree:add(f.data, buffer(offset, fake_data_size))
      offset = offset + fake_data_size

      tree:add(f.expiry_date, buffer(offset, 4))
      offset = offset + 4
    else
      tree:add(f.data, buffer(offset))
      offset = offset + buffer(offset):len()
    end

  elseif cmd == 0x07 then -- AppAck
    tree:append_text("AppAck ")

    tree:add(f.seq, buffer(offset, 4))
    offset = offset + 4

    tree:add(f.stream, buffer(offset, 2))
    offset = offset + 2

    local response_id_len = buffer(offset, 4):uint()
    offset = offset + 4

    tree:add(f.response_id, buffer(offset, response_id_len))
    offset = offset + response_id_len

    if buffer(offset):len() ~= 0 then -- hack: topic not always present and there is no indicator for it
      local topic_len = buffer(offset, 4):uint()
      offset = offset + 4

      tree:add(f.topic, buffer(offset, topic_len))
      offset = offset + topic_len
    end

  elseif cmd == 0x15 then -- Fragment
    tree:append_text("Fragment ")

    tree:add(f.data, buffer(offset)) -- fragment
    reassemble_alloy_fragments(buffer, pinfo, tree, offset)
    offset = offset + buffer(offset):len()
    
  elseif cmd == 0x27 then -- ServiceMap
    tree:append_text("ServiceMap ")

    offset = parse_servicemap_tlvs(buffer, pinfo, tree, offset)

  else -- unknown 
    tree:add(f.data, buffer(offset))
    offset = offset + buffer(offset):len()
  end

  return offset
end

function reassemble_alloy_fragments(buffer, pinfo, tree, offset)
  tree:add(f.frag_num, buffer(offset, 4)) -- what fragment transfer is this?
  local fragment_number = buffer(offset, 4):uint()
  offset = offset + 4 
  
  tree:add(f.frag_idx, buffer(offset, 4)) -- which fragment is this?
  local fragment_index = buffer(offset, 4):uint()
  offset = offset + 4

  tree:add(f.frag_ctr, buffer(offset, 4)) -- how many fragments are there in total?
  local fragment_count = buffer(offset, 4):uint()
  offset = offset + 4

  local fragment_source = pinfo.src_port
  if alloy_fragments[fragment_number] == nil then -- found new fragment transfer number! creating table for it
    alloy_fragments[fragment_number] = {}
  end
  if alloy_fragments[fragment_number][fragment_source] == nil then -- found unique fragment transfer (numbers are only unique for each source)
    alloy_fragments[fragment_number][fragment_source] = {}
    alloy_fragments[fragment_number][fragment_source]["total_fragment_count"] = fragment_count
  end
  if alloy_fragments[fragment_number][fragment_source][fragment_index] == nil then -- found new fragment! adding it to table
    alloy_fragments[fragment_number][fragment_source][fragment_index] = buffer(offset):bytes()
  end
  if pinfo.visited == true then -- this means that we have parsed every fragment. adding frame number...
    tree:add(f.frame_ref, alloy_fragments[fragment_number][fragment_source]["reassembled_in"])
  end
  
  tree:append_text("Transfer: [" .. fragment_index + 1 .. " / " .. fragment_count .. "] ")
  
  if fragment_count == fragment_index + 1 then -- if we are at the last fragment, attempt to put together and dissect the payload...
    local reassembled_bytes = ByteArray.new()
    for i = 0,fragment_index,1 do -- put all fragments together into a bytearray
      reassembled_bytes:append(alloy_fragments[fragment_number][fragment_source][i])
    end
    alloy_fragments[fragment_number][fragment_source]["reassembled_in"] = pinfo.number
    local fragment_tree = tree:add("Reassembled Alloy: ")
    dissect_alloy_data(reassembled_bytes:tvb("Reassembled Alloy"), pinfo, fragment_tree) -- dissect our reassembled data
    return
  end

  return
end

function dissect_alloy_control(buffer, pinfo, tree)
  local offset = 0

  tree:add(f.len, buffer(offset, 2))
  local len = buffer(offset, 2):uint()
  offset = offset + 2

  tree:add(f.cmd, buffer(offset, 1))
  local cmd = buffer(offset, 1):uint()
  offset = offset + 1

  -- dissect message type seperately
  if cmd == 0x01 then -- Hello
    pinfo.cols.info:append("[Control: Hello] ")

    local ccver_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), ccver_len, nil, "(CC Version Length)")
    offset = offset + 2

    tree:add(f.ccver, buffer(offset, ccver_len))
    local control_version = buffer(offset, ccver_len):string() 
    offset = offset + ccver_len

    local prodname_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), prodname_len, nil, "(Product Name Length)")
    offset = offset + 2

    tree:add(f.prodname, buffer(offset, prodname_len))
    local product_name = buffer(offset, prodname_len):string() 
    offset = offset + prodname_len

    local prodver_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), prodver_len, nil, "(Product Version Length)")
    offset = offset + 2

    tree:add(f.prodver, buffer(offset, prodver_len))
    local product_version = buffer(offset, prodver_len):string() 
    offset = offset + prodver_len

    local build_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), build_len, nil, "(Build Length)")
    offset = offset + 2

    tree:add(f.build, buffer(offset, build_len))
    local build = buffer(offset, build_len):string() 
    offset = offset + build_len

    local model_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), model_len, nil, "(Model Length)")
    offset = offset + 2

    tree:add(f.model, buffer(offset, model_len))
    local model = buffer(offset, model_len):string()
    offset = offset + model_len

    tree:add(f.protover, buffer(offset, 4))
    local protocol_version = buffer(offset, 4):uint()
    offset = offset + 4

    if buffer:len() > offset then
      offset = parse_hello_tlvs(buffer, pinfo, tree, offset, alloy_hello_tlv_types)
    end

    tree:append_text("Hello: ".."Alloy Control Version: "..control_version..", Protocol Version: "..protocol_version..", Device: ["..product_name.." / "..product_version.." / "..build.." / "..model.."]")

  elseif cmd == 0x02 then -- Setup Channel
    pinfo.cols.info:append("[Control: Setup] ")

    tree:add(f.channel_proto, buffer(offset, 1))
    offset = offset + 1

    tree:add(f.src_port, buffer(offset, 2))
    local source_port = buffer(offset, 2):uint()
    offset = offset + 2

    tree:add(f.dest_port, buffer(offset, 2))
    local dest_port = buffer(offset, 2):uint()
    offset = offset + 2

    local snd_uuid_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), snd_uuid_len, nil, "(Sender UUID Length)")
    offset = offset + 2

    local rcv_uuid_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), rcv_uuid_len, nil, "(Receiver UUID Length)")
    offset = offset + 2
    
    local account_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), account_len, nil, "(Account Length)")
    offset = offset + 2
    
    local service_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), service_len, nil, "(Service Length)")
    offset = offset + 2
    
    local name_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), name_len, nil, "(Name Length)")
    offset = offset + 2

    tree:add(f.sender_uuid, buffer(offset, snd_uuid_len))
    offset = offset + snd_uuid_len

    tree:add(f.rcvr_uuid, buffer(offset, rcv_uuid_len))
    offset = offset + rcv_uuid_len

    tree:add(f.account, buffer(offset, account_len))
    offset = offset + account_len

    tree:add(f.service, buffer(offset, service_len))
    offset = offset + service_len

    tree:add(f.name, buffer(offset, name_len))
    offset = offset + name_len

    local service_name = buffer(offset-name_len, name_len):string()
    tree:append_text("Opened channel: ["..service_name.."]".." to port: "..dest_port)

  elseif cmd == 0x03 then -- Close Channel
    pinfo.cols.info:append("[Control: Close] ")

    local snd_uuid_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), snd_uuid_len, nil, "(Sender UUID Length)")
    offset = offset + 2

    local rcv_uuid_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), rcv_uuid_len, nil, "(Receiver UUID Length)")
    offset = offset + 2

    local account_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), account_len, nil, "(Account Length)")
    offset = offset + 2

    local service_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), service_len, nil, "(Service Length)")
    offset = offset + 2

    local name_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), name_len, nil, "(Name Length)")
    offset = offset + 2

    tree:add(f.sender_uuid, buffer(offset, snd_uuid_len))
    offset = offset + snd_uuid_len

    tree:add(f.rcvr_uuid, buffer(offset, rcv_uuid_len))
    offset = offset + rcv_uuid_len

    tree:add(f.account, buffer(offset, account_len))
    offset = offset + account_len

    tree:add(f.service, buffer(offset, service_len))
    offset = offset + service_len

    tree:add(f.name, buffer(offset, name_len))
    offset = offset + name_len

    local service_name = buffer(offset-name_len, name_len):string()
    tree:append_text("Closed Channel: ["..service_name.."]")
  elseif cmd == 0x06 then -- Setup Encrypted Channel
    pinfo.cols.info:append("[Control: SetupEncryptedChannel] ")

    tree:add(f.channel_proto, buffer(offset, 1))
    offset = offset + 1

    tree:add(f.src_port, buffer(offset, 2))
    local source_port = buffer(offset, 2):uint()
    offset = offset + 2

    tree:add(f.dest_port, buffer(offset, 2))
    local dest_port = buffer(offset, 2):uint()
    offset = offset + 2

    local snd_uuid_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), snd_uuid_len, nil, "(Sender UUID Length)")
    offset = offset + 2

    local rcv_uuid_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), rcv_uuid_len, nil, "(Receiver UUID Length)")
    offset = offset + 2
    
    local account_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), account_len, nil, "(Account Length)")
    offset = offset + 2
    
    local service_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), service_len, nil, "(Service Length)")
    offset = offset + 2
    
    local name_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), name_len, nil, "(Name Length)")
    offset = offset + 2

    tree:add(f.ssrc, buffer(offset, 4))
    offset = offset + 4

    tree:add(f.start_seq, buffer(offset, 2))
    offset = offset + 2

    local key_len = buffer(offset, 2):uint()
    --tree:add(f.len, buffer(offset, 2), key_len, nil, "(Key Length)")
    offset = offset + 2

    tree:add(f.sender_uuid, buffer(offset, snd_uuid_len))
    offset = offset + snd_uuid_len

    tree:add(f.rcvr_uuid, buffer(offset, rcv_uuid_len))
    offset = offset + rcv_uuid_len

    tree:add(f.account, buffer(offset, account_len))
    offset = offset + account_len

    tree:add(f.service, buffer(offset, service_len))
    offset = offset + service_len

    tree:add(f.name, buffer(offset, name_len))
    offset = offset + name_len

    tree:add(f.key, buffer(offset, key_len))
    offset = offset + key_len

    tree:append_text("SetupEncryptedChannel ")
  end

  return offset
end

-- returns 0 for invalid, 1 for nwsc response, 2 for nwsc request
function check_nwsc(buffer, pinfo, tree)
  local blen = buffer:len()

  if blen < 44 or blen > 348 then return 0 end -- absolute size check
  local len_field = buffer(0,2):uint()
  local sec_field = buffer(2,2):uint()

  if len_field + 2 == blen then -- exact size check (data is within one packet)
    if blen == 44 then -- response fixed size
      if sec_field == 0x0000 or sec_field == 0x4000 or sec_field == 0x8000 then -- check for valid response flag
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

-- returns false for control, true for data
function check_alloy(buffer, pinfo, tree)
  local length = buffer:len()
  if length < 2 then return true end
  -- check length
  local alloy_length = buffer(0, 2):uint()
  if length <= 8 or alloy_length + 2 > length then return true end
  -- check control type
  local alloy_type = buffer(2, 1):uint()
  if alloy_control_types[alloy_type] == nil then return true end
  -- check data type
  local data_type = buffer(0, 1):uint()
  if alloy_data_types[data_type] ~= nil then return false end
  return true
end

--[[
  function that finds out the type of the current dissected message and then returns the length of it
  NWSC: LL...
  Control: LLT...
  Data: TLLLL...
]]--
function pdu_length(buffer, pinfo, offset) -- dissect_tcp_pdus helper function
  if check_nwsc(buffer, pinfo, nil) > 0 then -- hack: yeah idk... it works
    return 2 + buffer(offset, 2):uint()
  end
  if check_alloy(buffer, pinfo, nil) then
    return 5 + buffer(offset + 1, 4):uint()
  end
  return 2 + buffer(offset, 2):uint()
end

-- decide here if to dissect payload with control or data
function meta_dissect(buffer, pinfo, tree)
  if check_alloy(buffer, pinfo, tree) then
    local alloy_length = buffer(1, 4):uint()
    local subtree = tree:add(alloy_proto, buffer(offset, alloy_length + 2), "Alloy Data, ")
    return dissect_alloy_data(buffer, pinfo, subtree)
  else
    local alloy_length = buffer(0, 2):uint()
    local subtree = tree:add(alloy_proto, buffer(offset, alloy_length + 2), "Alloy Control, ")
    return dissect_alloy_control(buffer, pinfo, subtree)
  end
end

function alloy_proto.dissector(buffer, pinfo, tree)
  if buffer:len() == 0 then return 0 end
  if check_nwsc(buffer, pinfo, tree) > 0 then return 0 end -- i trust the nwsc check more here -> everything that is not nwsc must be alloy
  pinfo.cols.protocol = alloy_proto.name
  pinfo.cols.info:set("Alloy ")

  return dissect_tcp_pdus(buffer, tree, 2, pdu_length, meta_dissect, true)
end