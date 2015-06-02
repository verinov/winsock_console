// client+server.cpp: Defines the entry point for the console application.
//

#include "stdafx.h"



#include "ClientServer.h"

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define BUFSIZE 4096
#define DEFAULT_PORT "48999"
#define IPV4ADDR "93.175.5.98"

SOCKET ConnectSocket;

DWORD WINAPI ReadFromSocket(void* arg);
DWORD WINAPI WriteToSocket(void* arg);


int __cdecl main(int argc, char** argv)
{
   // client("93.175.5.182");
   // return 0;

    printf("start client \r\n");
    if (argc == 2) {
        client(argv[1]);
    } else {
        printf("Format: %s ip_addr", argv[0]);
    }

    return 0;
}

int client(char* ipAddr)
{
    WSADATA wsaData;
    ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
        *ptr = NULL,
        hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // either an IPv6 or IPv4 address can be returned
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char sendbuf[BUFSIZE];
    char recvbuf[BUFSIZE];
    int iResult;
    int recvbuflen = BUFSIZE;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }
    
    // Resolve the server address and port
    iResult = getaddrinfo(ipAddr, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }
        
        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    if (ptr == NULL) {
        printf("connection failed\n");
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        goto ERROR1;
    }

    HANDLE hReaderThread = CreateThread(NULL, 0, ReadFromSocket, NULL, 0, NULL);

    if (NULL == hReaderThread) {
        goto ERROR2;
    }

    HANDLE hWriterThread = CreateThread(NULL, 0, WriteToSocket, NULL, 0, NULL);

    if (NULL == hWriterThread) {
        goto ERROR3;
    }

    HANDLE handlesToWait[] = { hReaderThread, hWriterThread };
    WaitForMultipleObjects(2, handlesToWait, false, INFINITE);
    
    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        goto ERROR4;
    }

    // cleanup
    TerminateThread(hReaderThread, 0);
    TerminateThread(hWriterThread, 0);
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;

ERROR4:
    TerminateThread(hWriterThread, 23);
ERROR3:
    TerminateThread(hReaderThread, 23);
ERROR2:
    closesocket(ConnectSocket);
ERROR1:
    WSACleanup();
    return 1;
}

DWORD WINAPI WriteToSocket(void* arg) {
    int iResult;

    DWORD dwRead, dwWritten;
    CHAR sendBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    // DWORD mode = 0;
    // GetConsoleMode(hStdIn, &mode);
    // SetConsoleMode(hStdIn, mode & (~ENABLE_ECHO_INPUT));

    do
    {
        bSuccess = ReadFile(hStdIn, sendBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;

        iResult = send(ConnectSocket, sendBuf, dwRead, 0);
        if (iResult == SOCKET_ERROR) {
            printf("send failed with error: %d\n", WSAGetLastError());
            return 1;
        }

    } while (iResult > 0);

    //   SetConsoleMode(hStdIn, mode);
}


DWORD WINAPI ReadFromSocket(void* arg)
// Read from our stdin and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    CHAR recvBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    int iResult;

    do {
        iResult = recv(ConnectSocket, recvBuf, BUFSIZE, 0);
        if (iResult > 0)
            ;
        else if (iResult <= 0) {
            printf("Connection closed\n");
            return 1;
        }
        else {
            printf("recv failed with error: %d\n", WSAGetLastError());
            return 1;
        }

        DWORD dwWritten;

        bool bSuccess = WriteFile(hStdOut, recvBuf,
            iResult, &dwWritten, NULL);
        Sleep(50);

        if (!bSuccess) {
            printf("WriteFile failed!!!\n");
            return 1;
        }
        FlushFileBuffers(hStdOut);
    } while (iResult > 0);
    
    return 0;
}