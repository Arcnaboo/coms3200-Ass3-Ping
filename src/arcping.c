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


#include <winsock2.h>
#include <ws2tcpip.h>
#include "arcping.h"
#include "utilities.h"

unsigned int latency[4], arcI=0;

/*
 * Standard first compliment checksum
 */
USHORT get_checksum(USHORT* packet, int size) {
    unsigned long check = 0;
    
    while (size > 1) {
        check += *packet++;
        size -= sizeof(USHORT);
    }
    
    if (size) {
        check += *(UCHAR*)packet;
    }
    
    check = (check >> 16) + (check & 0xffff);
    check += (check >> 16);
    
    return (USHORT)(~check);
}

/*
 * Setups SOCKET-in
 * setssocketop ttl so we let socket adds Ipheader auto
 * Resolves hostname to ip -> dest
 * 
 * Prints error if returns FALSE
 * 
 * returns TRUE if succesful FALSE otherwise
 */
BOOL setup_socket(char* hostname, int ttl, SOCKET *s, struct sockaddr_in *dest) {
    
    *s = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, 0);
    if (*s == INVALID_SOCKET) {
        printf("Error creating socket: %d\n", WSAGetLastError());
        
        return FALSE;
    }

    if (setsockopt(*s, IPPROTO_IP, IP_TTL, (const char*)&ttl, 
            sizeof(ttl)) == SOCKET_ERROR) {
        printf("Error setting TTL: %d\n", WSAGetLastError());
        return FALSE;
    }

    
    memset(dest, 0, sizeof(dest));
    unsigned int address = inet_addr(hostname);
    if (address != INADDR_NONE) {
        dest->sin_addr.s_addr = address;
        dest->sin_family = AF_INET;
    } else {
        struct hostent* he = gethostbyname(hostname);
        if (he != 0) {
            memcpy(&(dest->sin_addr), he->h_addr, he->h_length);
            dest->sin_family = he->h_addrtype;
        } else {
            printf("Error resolving %s\n", hostname);
            return FALSE;
        }
    }
    printf("%s resolved to %s\n", hostname, inet_ntoa(dest->sin_addr));
    return TRUE;
}

/*
 * Prepares icmp header
 * 
 * @param (ICMPHeader*)icmpheader -Out
 * 
 */
void setup_ping_packet(ICMPHeader *icmpheader, int size, USHORT seq) {

    icmpheader->type = ICMP_ECHO_REQUEST;
    icmpheader->code = 0;
    icmpheader->checksum = 0;
    
    icmpheader->id = (USHORT)GetCurrentProcessId();
    icmpheader->seq = seq;
    icmpheader->timestamp = GetTickCount();
    
    unsigned long int aaa = 0xAAAAAAAA;
    char* data = (char*)icmpheader + sizeof(ICMPHeader);
    int remaining = size - sizeof(ICMPHeader);
    
    while (remaining > 0) {
        memcpy(data, &aaa, min((int)(sizeof(aaa)), 
                remaining));
        remaining -= sizeof(aaa);
        data += sizeof(aaa);
    }
    
    icmpheader->checksum = get_checksum((USHORT*)icmpheader, size);
}

/*
 * Sends the icmpheader to designated address
 * 
 * Returns True if succesful
 * False otherwise and prints error
 */
BOOL _ping(SOCKET s, struct sockaddr_in *des, ICMPHeader *icmpheader, int size) {

    //printf("Sending packet size %d to %s\n", size, inet_ntoa(des->sin_addr));
    
    int err = sendto(s, (char*)icmpheader, size, 0, (struct sockaddr*)des, sizeof(struct sockaddr_in));
    
    if (err == SOCKET_ERROR) {
        printf( "Error sending ICMP request: %d\n", WSAGetLastError());
        return FALSE;
    }
    else if (err < size) {
        printf("was only able to sent %d bytes\n", err);
        return FALSE;
    }
    //printf("Sent %d bytes.\n", err);
    return TRUE;
}

/*
 * Receives IP packet from  Socket
 * 
 * returns true if ok
 * returns false if error and prints error
 */
BOOL _receive(SOCKET s, struct sockaddr_in *src, IPHeader* response, int size) {
   
    int length = (int) sizeof(struct sockaddr_in);
    int err = recvfrom(s, (char*)response, size + sizeof(IPHeader),
                0, (struct sockaddr*)src, &length);
    
    if (err == SOCKET_ERROR) {
        
        printf("Error receiving IP packet: %d\n", WSAGetLastError() );
        return FALSE;
    }
    //printf("IP packet received, total size %dbytes.\n", err);
    return TRUE;
}

/*
 * Analyzes response IP packet
 * prints results
 * returns false if error and prints error
 * retuns true if ok
 */
BOOL analyze_response(IPHeader* response, int size, struct sockaddr_in *src) {

    unsigned short length = response->h_len * 4;
    ICMPHeader* icmpheader = (ICMPHeader*)((char*)response + length);

    if (size < length + ICMP_MIN) {
        printf("Not enough bytes received from %s.\n ",inet_ntoa(src->sin_addr));
        return FALSE;
        
    } else if (icmpheader->type != ICMP_ECHO_REPLY) {
        
        if (icmpheader->type != ICMP_TTL_EXPIRE) {
            
            if (icmpheader->type == ICMP_DEST_UNREACH) {
                puts("Destination unreachable!");
                return FALSE;
            }
            
            puts("Unknown ICMP type");
            return FALSE;
            
        }
    } else if (icmpheader->id != (USHORT)GetCurrentProcessId()) {
        
        puts("Packet id mismatch.");
        return FALSE;
    }
   
    
    
 
    printf("ICMP packet size %dbytes from %s TTL=%u ", 
            size, inet_ntoa(src->sin_addr), (unsigned int)response->ttl);
            
    latency[arcI] = 0;
    
    if (icmpheader->type == ICMP_TTL_EXPIRE) printf("TTL Expired.\n");
    
    else {
        latency[arcI] = (unsigned int)(GetTickCount() - icmpheader->timestamp);
        printf("latency: %ums\n", latency[arcI++]);
    }

    return TRUE;
}

/*
 * Returns average of given numbers
 */
unsigned int avg(unsigned int *arr) {
    unsigned int t = 0;
    for (int i = 0; i < 4; i++) t += latency[i];
    return (t / 4);
}

/*
 * Prints average latency
 */
void _print_average(void) {
    printf("\n4 packets sent, average %ums latency.", avg((unsigned int*)&latency[0]));
}
