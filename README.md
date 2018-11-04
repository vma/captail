# captail

This is a 'tail -f' implementation for streaming pcap files.

Adds a pcap header at the begining and starts streaming after the first `\r\n\r\n` to match with a new bodyless sip packet.

Unfortunately, there is no easy way to match a pcap packet beginning in the middle of a stream: the [record packet][1] starts with
a timestamp and ends with the data, without any marker or delimitor.

## example usage

```bash
$ captail -h
$ captail dump.pcap | ngrep -qt -W byline -I-
```

# btail

Plain binary `tail -f` without any pcap knowledge.


[1]: https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
