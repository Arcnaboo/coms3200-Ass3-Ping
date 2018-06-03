/*
 * The MIT License
 *
 * Copyright 2018 Arda 'Arc' Akgur.
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
 * File:   main.c
 * Author: Arda 'Arc' Akgur
 * 
 * Meant to be compiled on x64/x86 based Windows systems 
 * Most of em should have default winsock dll so bin would work on most win machines
 * 
 * Compile: Meant to compile on windows base machines
 *          Install MinGw minimalist gnu
 *          Netbeans ide
 *          Import files to a project
 *          Link ws2_32.a from mingw install directory in proejct properties
 *          let ide build executable
 *          or ofc you can just build with gcc.exe if u have mingw or similar 
 *          just link the winsock lib
 *
 *  
 *
 * Created on May 12, 2018, 10:12 PM
 */

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include "arcping.h"
#include "utilities.h"


#pragma comment(lib,"ws2_32.lib")

DWORD WINAPI timer(LPVOID lpParam);

BOOL _DONE = FALSE;

/* 
 * Initializes Winsock lib 
 */
void initialise_winsock(WSADATA *wsa) {
    printf("Attempting to initialize Winsock...");
    if (WSAStartup(MAKEWORD(2,2), wsa) != 0) {
        printf("Failed. Error Code : %d",WSAGetLastError());
        exit(1);
    }
    printf("Successfully initialized\n");
}



/*
 * 
 */
int main(int argc, char **argv) {
    
    if (argc != 3) {
        printf("Usage: %s host/ip ttl[1:255]\n", argv[0]);
        return 1;
    }
    
    char *hostname = strdup(argv[1]);
    int ttl = atoi(argv[2]);
    if (ttl <= 0 || ttl > 255) {
        printf("Usage: %s host/ip ttl[1:255]\n", argv[0]);
        puts("####### ttl should be between 1 and 255 ########");
        return 2;       
    }
    puts("Ping router by Arda Akgur\n\t\ts4382911\n");
    
    WSADATA wsa;
    SOCKET s;
    DWORD threadId[4];
    HANDLE threadHandles[4];
    struct sockaddr_in dest, src;
    char buffer[4196], response[4196];
    ICMPHeader *icmpheader = NULL;
    IPHeader *ipheader = NULL;
    
    int size = 32;
    
    icmpheader = (ICMPHeader*) &buffer;
    ipheader = (IPHeader*) &response;
    
    size = max(sizeof(ICMPHeader), min(1024, (unsigned int)size));
    
    initialise_winsock(&wsa);
    
    if (!setup_socket(hostname, ttl, &s, &dest)) return 3;
    
    for (int i = 0; i < 4; i++) {
        
        _DONE = FALSE;
        
        setup_ping_packet(icmpheader, size, (USHORT)i);
        
        if (!_ping(s, &dest, icmpheader, size)) return 4;
        
        threadHandles[i] = CreateThread(NULL, 0, timer, NULL, 0, &threadId[i]);
    
        if (!_receive(s, &src, ipheader, (1024 + sizeof(IPHeader)))) return 5;
    
        _DONE = TRUE;
        
        if (!analyze_response(ipheader, size, &src)) return 6;
        
        Sleep(1000);
    }
    
    
    
    _print_average();
    
    WSACleanup();
    return (EXIT_SUCCESS);
}

/*
 * Timer Thread
 * 
 * Sleeps for 1 second, if main thread not done yet then exits program
 * prints timed out message
 * 
 */
DWORD WINAPI timer(LPVOID lpParam) {
    
    Sleep(1000);
    
    if (!_DONE) {
        printf("Request timed out\n");
        exit(EXIT_SUCCESS);
    }
    
    return 0;
}
