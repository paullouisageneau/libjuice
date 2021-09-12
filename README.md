# libjuice - UDP Interactive Connectivity Establishment

[![Join the chat at https://gitter.im/libjuice/community](https://badges.gitter.im/libjuice/community.svg)](https://gitter.im/libjuice/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

libjuice :lemon::sweat_drops: (_JUICE is a UDP Interactive Connectivity Establishment library_) allows to open bidirectionnal User Datagram Protocol (UDP) streams with Network Address Translator (NAT) traversal.

The library is a simplified implementation of the Interactive Connectivity Establishment (ICE) protocol, client-side and server-side, written in C without dependencies for POSIX platforms (including GNU/Linux, Android, Apple macOS and iOS) and Microsoft Windows. The client supports only a single component over UDP per session in a standard single-gateway network topology, as this should be sufficient for the majority of use cases nowadays.

libjuice is licensed under LGPLv2, see [LICENSE](https://github.com/paullouisageneau/libjuice/blob/master/LICENSE).

libjuice is available on [AUR](https://aur.archlinux.org/packages/libjuice/) and [vcpkg](https://vcpkg.info/port/libjuice).

For a STUN/TURN server application based on libjuice, see [Violet](https://github.com/paullouisageneau/violet).

## Compatibility

The library implements a simplified but fully compatible ICE agent ([RFC8445](https://tools.ietf.org/html/rfc8445), [RFC8489](https://tools.ietf.org/html/rfc8489) for STUN, and [RFC8656](https://tools.ietf.org/html/rfc8656) for TURN) with an interface based on SDP ([RFC4566](https://tools.ietf.org/html/rfc4566)). It supports both IPv4 and IPv6.

The limitations compared to a fully-featured ICE agent are:
- Only UDP is supported as transport protocol. Other protocols are ignored.
- Only one component is supported. This is sufficient for WebRTC Data Channels or multiplexed RTP/RTCP ([RFC5731](https://tools.ietf.org/html/rfc5761)).
- Candidates are gathered without binding to each network interface, which behaves identically to the full implementation on most client systems.

It also implements a lightweight STUN/TURN server ([RFC8489](https://tools.ietf.org/html/rfc8489) and [RFC8656](https://tools.ietf.org/html/rfc8656)). The server can be disabled at compile-time with the `NO_SERVER` flag.

## Dependencies

None!

Optionally, [Nettle](https://www.lysator.liu.se/~nisse/nettle/) can provide SHA1 and SHA256 algorithms instead of the internal implementation.

## Building

### Clone repository

```bash
$ git clone https://github.com/paullouisageneau/libjuice.git
$ cd libjuice
```

### Build with CMake

The CMake library targets `libjuice` and `libjuice-static` respectively correspond to the shared and static libraries. The default target will build the library and tests.

#### POSIX-compliant operating systems (including Linux and Apple macOS)

```bash
$ cmake -B build
$ cd build
$ make -j2
```

The option `USE_NETTLE` allows to use the Nettle library instead of the internal implementation for HMAC-SHA1:
```bash
$ cmake -B build -DUSE_NETTLE=1
$ cd build
$ make -j2
```

#### Microsoft Windows with MinGW cross-compilation

```bash
$ cmake -B build -DCMAKE_TOOLCHAIN_FILE=/usr/share/mingw/toolchain-x86_64-w64-mingw32.cmake # replace with your toolchain file
$ cd build
$ make -j2
```

#### Microsoft Windows with Microsoft Visual C++

```bash
$ cmake -B build -G "NMake Makefiles"
$ cd build
$ nmake
```

### Build directly with Make (Linux only)

```bash
$ make
```

The option `USE_NETTLE` allows to use the Nettle library instead of the internal implementation for HMAC-SHA1:
```bash
$ make USE_NETTLE=1
```

## Example

See [test/connectivity.c](https://github.com/paullouisageneau/libjuice/blob/master/test/connectivity.c) for a complete local connection example.

See [test/server.c](https://github.com/paullouisageneau/libjuice/blob/master/test/server.c) for a server example.

