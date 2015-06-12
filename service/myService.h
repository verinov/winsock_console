
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>

#define SECURITY_WIN32
#define SEC_SUCCESS(Status) ((Status) >= 0)

#pragma comment (lib, "Secur32.lib")
#pragma comment (lib, "Ws2_32.lib")

#include "SspiExample.h"

#define BUFSIZE 1024
#define DEFAULT_PORT 48999


DWORD WINAPI Init(void* socket);
DWORD WINAPI Server(void*);

struct InitArgs {
    SOCKET socket;
    CredHandle hCred;
    struct _SecHandle  hCtxt;
};