P2P protocol dissector for Wireshark
====================================

This is Wireshark Lua protocol dissector for my school project. Project uses
Gnutella 0.6 stylish protocol to form a peer-to-peer network.

Using with Wireshark:
    wireshark -X "lua_script:P2PGnutella.lua"


Gnutella 0.6 protocol documents:
http://rfc-gnutella.sourceforge.net/src/rfc-0_6-draft.html

Wireshark Lua documents:
http://wiki.wireshark.org/Lua
http://wiki.wireshark.org/Lua/Dissectors
http://wiki.wireshark.org/Lua/Examples