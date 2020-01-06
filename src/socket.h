/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef JUICE_SOCKET_H
#define JUICE_SOCKET_H

#include <stdint.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#ifndef __MSVCRT_VERSION__
#define __MSVCRT_VERSION__ 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wincrypt.h>

#ifdef __MINGW32__
#include <sys/stat.h>
#include <sys/time.h>
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
#endif

#define NO_IFADDRS
#define NO_PMTUDISC

typedef SOCKET socket_t;
typedef SOCKADDR sockaddr;
typedef size_t socklen_t;
typedef u_long ctl_t;
#define close closesocket
#define ioctl ioctlsocket
#define errno ((int)WSAGetLastError())
#define IP_DONTFRAG IP_DONTFRAGMENT
#define SOCKET_TO_INT(x) 0

#else // assume POSIX

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <memory.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __ANDROID__
#define NO_IFADDRS
#else
#include <ifaddrs.h>
#endif

typedef int socket_t;
typedef int ctl_t;
#define INVALID_SOCKET -1
#define SOCKET_TO_INT(x) (x)

#endif // defined(_WIN32) || defined(_WIN64)

struct sockaddr_record {
	struct sockaddr_storage addr;
	socklen_t len;
};

#endif // JUICE_SOCKET_H
