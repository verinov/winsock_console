// console_pipe_winsock.cpp: Defines the entry point for the console application.
//

#include "stdafx.h"

#include "myService.h"

#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>

struct ChildHandles {
    HANDLE IN_Rd = NULL;
    HANDLE IN_Wr = NULL;
    HANDLE OUT_Rd = NULL;
    HANDLE OUT_Wr = NULL;
    SOCKET socket = 0;
};


HANDLE CreateChildProcess(void*);
DWORD WINAPI WriteToPipe(void* pHandles);
DWORD WINAPI ReadFromPipe(void*);
void ErrorExit(PTSTR);


/*
DWORD WINAPI ChildWatcher(HANDLE hChildProcess) {
    WaitForSingleObject(hChildProcess, INFINITE);

    TerminateProcess(hChildProcess, 23);
    CloseHandle(hChildProcess);
    ExitThread(2);
   // ExitProcess(2);
    // FIXME
}*/

bool FillHandles(ChildHandles& handles) {
    SECURITY_ATTRIBUTES saAttr;

    // Set the bInheritHandle flag so pipe handles are inherited. 
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT.
    if (!CreatePipe(&handles.OUT_Rd, &handles.OUT_Wr, &saAttr, 0)) {
        printf("StdoutRd CreatePipe\n");
        return false;
    }

    // Ensure the read handle to the pipe for STDOUT is not inherited.
    if (!SetHandleInformation(handles.OUT_Rd, HANDLE_FLAG_INHERIT, 0)) {
        printf("Stdout SetHandleInformation\n");
        return false;
    }

    // Create a pipe for the child process's STDIN. 
    if (!CreatePipe(&handles.IN_Rd, &handles.IN_Wr, &saAttr, 0)) {
        printf("Stdin CreatePipe\n");
        return false;
    }

    // Ensure the write handle to the pipe for STDIN is not inherited. 
    if (!SetHandleInformation(handles.IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
        printf("Stdin SetHandleInformation\n");
        return false;
    }

    return true;
}

bool CloseHandles(ChildHandles& handles) {
    if (!CloseHandle(handles.IN_Wr)) {
        printf("IN_Wr CloseHandle");
        return false;
    }
    if (!CloseHandle(handles.IN_Rd)) {
        printf("IN_Rd CloseHandle");
        return false;
    }
    if (!CloseHandle(handles.OUT_Wr)) {
        printf("OUT_Wr CloseHandle");
        return false;
    }
    if (!CloseHandle(handles.OUT_Rd)) {
        printf("OUT_Rd CloseHandle");
        return false;
    }

    closesocket(handles.socket);
    return true;
}


DWORD WINAPI Init(void* pSocket)
{
    ChildHandles chHandles;
    chHandles.socket = *(SOCKET*)pSocket;
    delete pSocket;

    if (!FillHandles(chHandles)) {
        goto exit2;
    }


    printf("\n->Start of parent execution.\n");

    // Create the child process with console thread and watcher thread.
    // stdin and stdout are redirected to corresponding child pipes.
    HANDLE hCmdProcess = CreateChildProcess(&chHandles);
    if (!hCmdProcess) {
        goto exit3;
    }

    // Create thread for ReadFromPipe
    HANDLE hOutputThread = CreateThread(NULL, 0, ReadFromPipe, &chHandles, 0, NULL);

    if (NULL == hOutputThread) {
        goto exit4;
    }
    
    HANDLE hInputThread = CreateThread(NULL, 0, WriteToPipe, &chHandles, 0, NULL);

    if (NULL == hInputThread) {
        goto exit5;
    }

    HANDLE handlesToWait[] = { hCmdProcess, hOutputThread, hInputThread };

    WaitForMultipleObjects(3, handlesToWait, false, INFINITE);

    TerminateProcess(hCmdProcess, 0);
    TerminateThread(hOutputThread, 0);
    TerminateThread(hInputThread, 0);

    if (!CloseHandles(chHandles)) {
        goto exit2;
    }

    return 0;

exit5:
    TerminateThread(hOutputThread, 25);
exit4:
    TerminateProcess(hCmdProcess, 24);
exit3:
    CloseHandles(chHandles);
exit2:
    WSACleanup();
    return 1;
}

HANDLE CreateChildProcess(void* pHandles)
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{
    ChildHandles handles = *(ChildHandles*)pHandles;

    TCHAR szCmdline[] = TEXT("cmd.exe");
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    BOOL bSuccess = FALSE;

    // Set up members of the PROCESS_INFORMATION structure. 

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    // Set up members of the STARTUPINFO structure. 
    // This structure specifies the STDIN and STDOUT handles for redirection.

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = handles.OUT_Wr;
    siStartInfo.hStdOutput = handles.OUT_Wr;
    siStartInfo.hStdInput = handles.IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process. 

    bSuccess = CreateProcess(NULL,
        szCmdline,     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        0,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        &piProcInfo);  // receives PROCESS_INFORMATION 

    // If an error occurs, exit the application. 
    if (!bSuccess) {
        printf("CreateProcess\n");
        return 0;
    }
    
    // Close handles to the child process and its primary thread.
    // Some applications might keep these handles to monitor the status
    // of the child process, for example. 

    //CreateThread(NULL, 0, ChildWatcher, piProcInfo.hProcess, 0, NULL);
   // CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

    return piProcInfo.hProcess;
}

DWORD WINAPI WriteToPipe(void* pHandles) {
    ChildHandles handles = *(ChildHandles*)pHandles;

    char recvbuf[BUFSIZE];
    int recvbuflen = BUFSIZE;
    int iResult;

    DWORD dwWritten;
    BOOL bSuccess = FALSE;

    do {
        iResult = recv(handles.socket, recvbuf, recvbuflen, 0);
        printf("Receive socket: %u\n", socket);

        if (iResult > 0) {
            printf("Bytes received: %d\n", iResult);

            bSuccess = WriteFile(handles.IN_Wr, recvbuf, iResult, &dwWritten, NULL);
            if (!bSuccess) break;
        }
        else if (iResult == 0)
            printf("Connection closing...\n");
        else  {
            printf("recv failed with error: %d\n", WSAGetLastError());
            return 1;
        }
    } while (iResult > 0);

    return 0;
}

DWORD WINAPI ReadFromPipe(void* pHandles)
// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
{
    ChildHandles handles = *(ChildHandles*)pHandles;

    DWORD dwRead;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    int iResult;

    do {
        bSuccess = ReadFile(handles.OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;

        DWORD dwWritten;
        bSuccess = WriteFile(hStdOut, chBuf,
            dwRead, &dwWritten, NULL);
        if (!bSuccess) break;

        iResult = send(handles.socket, chBuf, dwRead, 0);
        if (iResult == SOCKET_ERROR) {
            printf("send failed with error: %d\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }
        printf("\nBytes sent/read: %d\t%d\n", iResult, dwRead);
        printf("Socket: %u\n", handles.socket);

    } while (iResult > 0);

    return 0;
}

void ErrorExit(PTSTR lpszFunction)
// Format a readable error message, display a message box, 
// and exit from the application.
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40)*sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"),
        lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
   // ExitProcess(1);
}

