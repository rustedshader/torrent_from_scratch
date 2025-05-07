# Torrent from scatch

## Bencode (Bee Encode)
https://code.google.com/archive/p/bencode-net/wikis/BEncode.wiki


## UDP (User Datagram Protocol) 

Time outs
UDP is an 'unreliable' protocol. This means it doesn't retransmit lost packets itself. The application is responsible for this. If a response is not received after 15 * 2 ^ n seconds, the client should retransmit the request, where n starts at 0 and is increased up to 8 (3840 seconds) after every retransmission. Note that it is necessary to rerequest a connection ID when it has expired.