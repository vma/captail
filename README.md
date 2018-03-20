# captail

This a 'tail -f' implementation for streaming pcap files.

It adds a pcap header at the begining and starts streaming after the first `\r\n\r\n` to match with a new pcap packet.
