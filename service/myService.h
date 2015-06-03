

#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>



#define BUFSIZE 1024
#define DEFAULT_PORT 48999


DWORD WINAPI Init(void* socket);
DWORD WINAPI Server(void*);
