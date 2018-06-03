/*
 * The MIT License
 *
 * Copyright 2018 arc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* 
 * File:   arcping.h
 * Author: arc
 *
 * Created on May 13, 2018, 2:13 AM
 */

#ifndef ARCPING_H
#define ARCPING_H

#ifdef __cplusplus
extern "C" {
#endif

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>

// ICMP Header Types
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRE 11
#define ICMP_ECHO_REQUEST 8
#define ICMP_MIN 8

#pragma pack(1)


// The IP header
typedef struct {
    BYTE h_len:4;
    BYTE version:4;
    BYTE tos;
    USHORT total_len;
    USHORT ident;
    USHORT flags;
    BYTE ttl;
    BYTE proto;
    USHORT checksum;
    ULONG source_ip;
    ULONG dest_ip;
}IPHeader;

// ICMP header
typedef struct {
    BYTE type;
    BYTE code;
    USHORT checksum;
    USHORT id;
    USHORT seq;
    ULONG timestamp;
}ICMPHeader;


#pragma pack()

// function prototypes
BOOL analyze_response(IPHeader* response, int size, struct sockaddr_in *src);
BOOL _receive(SOCKET s, struct sockaddr_in *src, IPHeader* response, int size);
BOOL _ping(SOCKET s, struct sockaddr_in *des, ICMPHeader *icmpheader, int size);
void setup_ping_packet(ICMPHeader *icmpheader, int size, USHORT seq);
BOOL setup_socket(char* hostname, int ttl, SOCKET *s, struct sockaddr_in *dest);
void _print_average(void);

#ifdef __cplusplus
}
#endif

#endif /* ARCPING_H */

