# captail

This a 'tail -f' implementation for streaming pcap files.

Adds a pcap header at the begining and starts streaming after the first `\r\n\r\n` to match with a new bodyless sip packet.

## example usage

```bash
$ captail -h
$ captail dump.pcap | ngrep -qt -W byline -I-
```
