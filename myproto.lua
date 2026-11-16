-- myproto.lua : Wireshark Lua dissector for "MYP" (My Custom Protocol)
-- Transport: UDP port 9999
--
-- Packet layout (9 byte header + payload):
--   0-1  Magic          0x4D50 ("MP")
--   2    Version        1
--   3    Message Type   1=LOGIN 2=LOGIN_OK 3=DATA 4=PING 5=PONG 6=BYE
--   4    Flags          bit0=ACK requested, bit1=Urgent
--   5-6  Sequence No.   uint16 (big endian)
--   7-8  Payload Length uint16 (big endian)
--   9..  Payload        text

local myp = Proto("MYP", "My Custom Protocol")

local MYP_PORT   = 9999
local MYP_MAGIC  = 0x4D50
local HEADER_LEN = 9

local msg_types = {
  [1] = "LOGIN", [2] = "LOGIN_OK", [3] = "DATA",
  [4] = "PING",  [5] = "PONG",     [6] = "BYE"
}

-- Fields
local f_magic   = ProtoField.uint16("myp.magic",   "Magic",          base.HEX)
local f_version = ProtoField.uint8 ("myp.version", "Version",        base.DEC)
local f_type    = ProtoField.uint8 ("myp.type",    "Message Type",   base.DEC, msg_types)
local f_flags   = ProtoField.uint8 ("myp.flags",   "Flags",          base.HEX)
local f_ack     = ProtoField.bool  ("myp.flags.ack",    "ACK requested", 8, nil, 0x01)
local f_urgent  = ProtoField.bool  ("myp.flags.urgent", "Urgent",        8, nil, 0x02)
local f_seq     = ProtoField.uint16("myp.seq",     "Sequence No.",   base.DEC)
local f_len     = ProtoField.uint16("myp.length",  "Payload Length", base.DEC)
local f_payload = ProtoField.string("myp.payload", "Payload")

myp.fields = { f_magic, f_version, f_type, f_flags, f_ack, f_urgent, f_seq, f_len, f_payload }

-- Expert info (shows warnings in Wireshark's Expert Info window)
local ef_bad_len = ProtoExpert.new("myp.bad_length", "Payload length does not match packet size",
                                   expert.group.MALFORMED, expert.severity.ERROR)
local ef_bad_ver = ProtoExpert.new("myp.bad_version", "Unknown protocol version",
                                   expert.group.PROTOCOL, expert.severity.WARN)
myp.experts = { ef_bad_len, ef_bad_ver }

function myp.dissector(buffer, pinfo, tree)
  local pkt_len = buffer:len()
  if pkt_len < HEADER_LEN then return 0 end
  if buffer(0, 2):uint() ~= MYP_MAGIC then return 0 end   -- not our protocol

  pinfo.cols.protocol = "MYP"

  local subtree = tree:add(myp, buffer(), "My Custom Protocol")
  subtree:add(f_magic, buffer(0, 2))

  local ver_item = subtree:add(f_version, buffer(2, 1))
  if buffer(2, 1):uint() ~= 1 then
    ver_item:add_tvb_expert_info(ef_bad_ver, buffer(2, 1))
  end

  local mtype = buffer(3, 1):uint()
  subtree:add(f_type, buffer(3, 1))

  local flags_tree = subtree:add(f_flags, buffer(4, 1))
  flags_tree:add(f_ack,    buffer(4, 1))
  flags_tree:add(f_urgent, buffer(4, 1))

  local seq  = buffer(5, 2):uint()
  local plen = buffer(7, 2):uint()
  subtree:add(f_seq, buffer(5, 2))
  local len_item = subtree:add(f_len, buffer(7, 2))

  local payload_len = pkt_len - HEADER_LEN
  if plen ~= payload_len then
    len_item:add_tvb_expert_info(ef_bad_len, buffer(7, 2))
  end
  if payload_len > 0 then
    subtree:add(f_payload, buffer(HEADER_LEN, payload_len))
  end

  local name = msg_types[mtype] or ("UNKNOWN(" .. mtype .. ")")
  pinfo.cols.info = string.format("%s  Seq=%d  Len=%d", name, seq, plen)
  return pkt_len
end

DissectorTable.get("udp.port"):add(MYP_PORT, myp)
