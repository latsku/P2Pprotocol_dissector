-- P2P Gnutella protocol
-- This is Wireshark Lua protocol dissector for my school project. Project uses
-- Gnutella 0.6 stylish protocol to form a peer-to-peer network.
-- Protocol documents:
-- http://rfc-gnutella.sourceforge.net/src/rfc-0_6-draft.html
-- Wireshark Lua documents:
-- http://wiki.wireshark.org/Lua
-- http://wiki.wireshark.org/Lua/Dissectors
-- http://wiki.wireshark.org/Lua/Examples

-- Author: Lari Lehtomäki (lari@lehtomaki.fi)


-- Protocol declaration
p2pgnutella_proto = Proto("p2p_gnutella","P2P Gnutella v0.6 (sort of)")

-- Protocol field enumerations
local msgtype_enum = {
                    [0] = "Ping",
                    [1] = "Pong",
                    [2] = "Bye",
                    [3] = "Join",
                    [128] = "Query",
                    [129] = "Query Hit"
                }
local join_enum = { [512] = "Accept" }

-- Protocol fields
local f = p2pgnutella_proto.fields
f.pf_msg_type         = ProtoField.uint8("p2p_gnutella.type", "Msg type", base.HEX, msgtype_enum)
f.pf_msg_port         = ProtoField.uint16("p2p_gnutella.senderport", "Sender Port", base.DEC)
f.pf_orig_ip          = ProtoField.ipv4 ("p2p_gnutella.orig_ip", "Original Sender IP")
f.pf_query            = ProtoField.stringz("p2p_gnutella.query", "Query")
f.pf_query_rid        = ProtoField.uint16("p2p_gnutella.queryhit.rid", "Resource ID", base.DEC)
f.pf_query_value      = ProtoField.uint32("p2p_gnutella.queryhit.value", "Value", base.DEC)
f.pf_peer             = ProtoField.ipv4("p2p_gnutella.discovery.peer", "Peer")
f.pf_peer_port        = ProtoField.uint16("p2p_gnutella.discovery.peerport", "Peer port", base.DEC)
f.pf_join_status      = ProtoField.uint16("p2p_gnutella.join.status", "Status", base.HEX, join_enum)

-- Dissect function
function p2pgnutella_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "P2P_GNUTELLA"
    local subtree = tree:add(p2pgnutella_proto,buffer(),"P2P Gnutella v0.6 (sort of)")

    -- Header
    headertree = subtree:add(buffer(0,16),"Header")
    headertree:add(buffer(0,1),"Version: " .. buffer(0,1):uint())
    headertree:add(buffer(1,1),"TTL: " .. buffer(1,1):uint())
    headertree:add(f.pf_msg_type, buffer(2,1))
    headertree:add(f.pf_msg_port, buffer(4,2))
    headertree:add(buffer(6,2),"Payload length: " .. buffer(6,2):uint())
    headertree:add(f.pf_orig_ip, buffer(8,4))
    headertree:add(buffer(12,4),"Message Id: " .. buffer(12,4):uint())

    local msgtype = buffer(2,1):uint()

    if ( msgtype == 0x00 ) then
        pinfo.cols.info:set("Ping, TTL: " .. buffer(1,1):uint())
    elseif ( msgtype == 0x01 ) then
        pinfo.cols.info:set("Pong")
    elseif ( msgtype == 0x02 ) then
        pinfo.cols.info:set("Bye")
    elseif ( msgtype == 0x03 ) then
        pinfo.cols.info:set("Join")
    elseif ( msgtype == 0x80 ) then
        pinfo.cols.info:set("Query")
    elseif ( msgtype == 0x81 ) then
        pinfo.cols.info:set("Query Hit")
    end

    --Body
    local payloadlength = buffer(6,2):uint()
    if (((pinfo.len-66-16) > 0) and (payloadlength > 0)) then
        local bodytree = subtree:add(buffer(16,(pinfo.len-66-16)),"Body")
        if msgtype == 0x01 then
            bodytree:add(buffer(16,2), "Entry size: " .. buffer(16,2):uint())
            local entrysize = buffer(16,2):uint()
            if entrysize >= 1 then
                for i = 0, entrysize-1, 1 do
                    bodytree:add(f.pf_peer,      buffer((20+i*8),4))
                    bodytree:add(f.pf_peer_port, buffer((24+i*8),2))
                end
            end
        elseif msgtype == 0x03 then
            if buffer(16,2):uint() == 0x200 then
                pinfo.cols.info:append(", Accepted")
            end
            bodytree:add(f.pf_join_status, buffer(16,2))
        elseif msgtype == 0x80 then
            pinfo.cols.info:append(", key: " .. buffer(16, (pinfo.len-66-16)):string())
            bodytree:add(f.pf_query, buffer(16, (pinfo.len-66-16)))
        elseif msgtype == 0x81 then
            local entrysize = buffer(16,2):uint()
            pinfo.cols.info:append(", " .. entrysize .. " entries" )
            bodytree:add(buffer(16,2), "Entry size: " .. buffer(16,2):uint())
            if entrysize >= 1 then
                for i = 0, entrysize-1, 1 do
                    bodytree:add(f.pf_query_rid, buffer((20+i*8),2))
                    bodytree:add(f.pf_query_value, buffer((24+i*8),4))
                end
            end
        end
    end
end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")

-- register our protocol to handle tcp port 10001 and 8601
tcp_table:add(10001, p2pgnutella_proto)
tcp_table:add(8601,  p2pgnutella_proto)
