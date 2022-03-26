# Pktreplay

`pktreplay` can be used to read packets from `pcap` file or interface and write
them into interface. By default packets are written with the same rate they have
been saved into the pcap file, or, when reading from interface, as fast as they
are received.

`pktreplay` takes its inspiration from
[tcpreplay](https://tcpreplay.appneta.com), but without packet editing
capabilities.

## Usage

`pktreplay` needs to be run as `root` or (on Linux) with `cap_net_raw`
capability to be able to write raw data to the interface.

Following command line options are available:

- Options to control where packets are read from. One of these must be present:
  - `-f` or `--file <FILE>`: Read packets from pcap file `FILE`.
  - `-i` or `--interface <IFNAME>`: Read packets from given interface.
- `-o` or `--output <IFNAME>`: Write packets to interface with name `IFNAME`. If
  this option is not given, packets are written to `/dev/null`.
- `-l` or `--loop`: Loop packets from file, that is start writing packets again
  from the beginning once all packets are written. Program terminates when user
  presses ctrl+c.
- `-c` or `--count <NUM>`: Read only NUM first packets from the file and output
  them. If `--loop` is set, then loop the first NUM packets.
- `-S` or `--stats <SEC>`: Print statistics every SEC seconds.
- Options to control packet rate. Only one can be given, if none of these
  options is present, packets are written with the rate they have been saved to
  the `pcap` file:
  - `-F` or `--fullspeed`: Write packets as fast as possible.
  - `-p` or `--pps <RATE>`: Write packets with `RATE` (integer) packets per
    second.
  - `-M` or `--mbps <RATE>`: Write packets with `RATE` (float) mega(million)
    bits per second.
- Options to control internal packet buffer size. `pktreplay` reads packets into
  internal buffer from where they are written to interface.
  - `-H` or `--hi <NUM>`: Maximum number of packets to buffer. After this many
    packets are buffered, no more packets are read into the buffer until buffer
    contains only `low` number of packets.
  - `-L` or `--low <NUM>`: Low watermark for packet buffer. If buffer contains
    only this number of packets, new packets are read into the buffer until the
    buffer contains `hi` number of packets. Default value for this is half of
    the maximum number of packets.

After packets are written, a summary is written. The program can be terminated
by pressing `ctrl+C`.
