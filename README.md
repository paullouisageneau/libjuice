# libjuice - UDP Interactive Connectivity Establishment

libjuice :lemon::sweat_drops: (_JUICE is a UDP Interactive Connectivity Establishment library_) allows to open bidirectionnal User Datagram Protocol (UDP) streams with Network Address Translator (NAT) traversal.

The library is a simplified implementation of the Interactive Connectivity Establishment (ICE) protocol in C for POSIX platforms (including Linux and Apple macOS) and Microsoft Windows. It supports only a single component over UDP per session in a standard single-gateway network topology, as this should be sufficient for the majority of use cases nowadays.

Licensed under LGPLv2, see [LICENSE](https://github.com/paullouisageneau/libjuice/blob/master/LICENSE).

## Compatibility

The library aims at implementing a simplified but fully compatible ICE agent ([RFC8445](https://tools.ietf.org/html/rfc8445), and [RFC5389](https://tools.ietf.org/html/rfc5389) for STUN) with an interface based on SDP ([RFC4566](https://tools.ietf.org/html/rfc4566)). It supports both IPv4 and IPv6.

The limitations compared to a fully-featured ICE agent are:
- Only UDP is supported as transport protocol. Other protocols are ignored.
- Only one component is supported. This is sufficient for WebRTC Data Channels or multiplexed RTP/RTCP ([RFC5731](https://tools.ietf.org/html/rfc5761)).
- Candidates are gathered without binding to specific network interfaces. This should behave identically to the full implementation on most client systems and allows to greatly reduce complexity.

## Dependencies

- Nettle (https://www.lysator.liu.se/~nisse/nettle/) or OpenSSL (https://www.openssl.org/) for HMAC-SHA1
- That's it!

## Building

### Clone repository

```bash
$ git clone https://github.com/paullouisageneau/libjuice.git
$ cd libjuice
```

### Building with CMake

The CMake library targets `libjuice` and `libjuice-static` respectively correspond to the shared and static libraries. The default target will build the library and tests.

#### POSIX-compliant operating systems (including Linux and Apple macOS)

```bash
$ cmake -B build -DUSE_NETTLE=1
$ cd build && make -j2
```

#### Microsoft Windows with MinGW cross-compilation

```bash
$ cmake -B build -DCMAKE_TOOLCHAIN_FILE=/usr/share/mingw/toolchain-x86_64-w64-mingw32.cmake # replace with your toolchain file
$ cd build && make -j2
```

#### Microsoft Windows with Microsoft Visual C++

```bash
$ cmake -B build -G "NMake Makefiles"
$ cd build
$ nmake
```

### Building directly with Make (Linux only)

```bash
$ make USE_NETTLE=1
```

## Example

See [test/connectivity.c](https://github.com/paullouisageneau/libjuice/blob/master/test/connectivity.c) for a complete local connection example.

