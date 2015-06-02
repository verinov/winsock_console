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
int personalNumber;
const int headerSize = sizeof(int);

DWORD WINAPI ReadFromSocket(void* arg);


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
        WSACleanup();
        return 1;
    }


    HANDLE hThread = CreateThread(NULL, 0, ReadFromSocket, NULL, 0, NULL);

    if (NULL == hThread) {// thread was not created,  TODO checking*/
        // TODO clean everything up
        WSACleanup();
        return 1;
    }


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
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }

    } while (iResult > 0);

    // Receive until the peer closes the connection
    
    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

 //   SetConsoleMode(hStdIn, mode);

    return 0;
}


DWORD WINAPI ReadFromSocket(void* arg)
// Read from our stdin and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
{
  //  FILE* logfile;
  //  fopen_s(&logfile, "log.txt", "wb+");


    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    CHAR recvBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    int iResult;

    do {
        iResult = recv(ConnectSocket, recvBuf, BUFSIZE, 0);
        if (iResult > 0)
            ;
          //  printf("Bytes received: %d\n", iResult);
        else if (iResult <= 0)
            printf("Connection closed\n");
        else
            printf("recv failed with error: %d\n", WSAGetLastError());

       // fwrite(recvBuf, 1, iResult, logfile);
      //  fprintf(logfile, "\n<<<%d>>>\n", iResult);
     //   fflush(logfile);

        DWORD dwWritten;

        bool bSuccess = WriteFile(hStdOut, recvBuf,
            iResult, &dwWritten, NULL);
        Sleep(50);
        if (!bSuccess) {
            printf("WriteFile failed!!!\n");
            return 0;
        }
        FlushFileBuffers(hStdOut);
       // printf("\r\nBytes received/written: %d\t%d\r\n-------------------\r\n", iResult, dwWritten);
    } while (iResult > 0);

    // Close the pipe handle so the child process stops reading. 
    
    return 0;
}