# libjuice - UDP Interactive Connectivity Establishment

libjuice :lemon::sweat_drops: (_JUICE is a UDP Interactive Connectivity Establishment library_) allows to open bidirectionnal User Datagram Protocol (UDP) streams with Network Address Translator (NAT) traversal.

The library is a simplified implementation of the Interactive Connectivity Establishment (ICE) protocol in C99 for POSIX platforms and Microsoft Windows. It supports only a single component over UDP per session in a standard single-gateway network topology, as this should be sufficient for the majority of use cases nowadays.

Licensed under LGPLv2, see [LICENSE](https://github.com/paullouisageneau/libjuice/blob/master/LICENSE).

## Compatibility

The library aims at implementing a simplified but fully compatible ICE agent ([RFC8445](https://tools.ietf.org/html/rfc8445), and [RFC5389](https://tools.ietf.org/html/rfc5389) for STUN) with an interface based on SDP ([RFC4566](https://tools.ietf.org/html/rfc4566)). It supports both IPv4 and IPv6.

The limitations compared to a fully-featured ICE agent are:
- Only UDP is supported as transport protocol. Other protocols are ignored.
- Only one component is supported. This is sufficient for WebRTC Data Channels or multiplexed RTP/RTCP ([RFC5731](https://tools.ietf.org/html/rfc5761)).
- Only the default gateway is used when gathering candidates. This should behave identically to the full implementation on most client systems and allows to greatly reduce complexity.

## Dependencies

- Nettle (https://www.lysator.liu.se/~nisse/nettle/) or OpenSSL (https://www.openssl.org/) for HMAC-SHA1
- That's it!

## Building

### Building with CMake (preferred)

```bash
$ mkdir build
$ cd build
$ cmake -DUSE_NETTLE=1 ..
$ make
```

### Building directly with Make

```bash
$ make USE_NETTLE=1
```

## Example

See [test/main.c](https://github.com/paullouisageneau/libjuice/blob/master/test/main.c) for a complete local connection example.

