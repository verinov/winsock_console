// client+server.cpp: Defines the entry point for the console application.
//

#include "stdafx.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "myService.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")

DWORD WINAPI Server(void*) {
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    std::list<SOCKET> clientSockets;

    int iSendResult;
    char recvbuf[BUFSIZE];
    int recvbuflen = BUFSIZE;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData); // тут куча сетевой инициализации, не надо лезть
    if (iResult != 0) {
        printf("WSAStartup (WS2_32.dll init) failed with error: %d\n", iResult);
        return 1;
    }

    sockaddr_in service;

    // Create a SOCKET for listening for incoming connection requests.
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET) {
        wprintf(L"socket function failed with error: %ld\n", WSAGetLastError());
        goto cleanup2;
    }
    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound.
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons(DEFAULT_PORT);

    iResult = bind(ListenSocket, (SOCKADDR *)& service, sizeof(service));
    if (iResult == SOCKET_ERROR) {
        wprintf(L"bind function failed with error %d\n", WSAGetLastError());
        goto cleanup3;
    }

    printf("TCP listening socket set up\n");

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        goto cleanup3;
    }
    printf("listening\n\n");

    for (;;) {
        // Accept a client socket
        ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            printf("accept failed with error: %d\n", WSAGetLastError());
            goto cleanup3;
        }

        // start independent console and corresponding threads
        // that theads are responsible for all cleanup
        SOCKET * pSocket = new SOCKET(ClientSocket);

        HANDLE hThread = CreateThread(NULL, 0, Init, pSocket, 0, NULL);
        if (NULL == hThread) {
            delete pSocket;
            goto cleanup3;
        }
        
        printf("client socket accepted\n");
    }
    return 0;

cleanup3:
    closesocket(ListenSocket);
cleanup2:
    WSACleanup();
    return 1;
}

