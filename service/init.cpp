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


void CreateChildProcess(void*);
DWORD WINAPI ReadFromPipe(void*);
void ErrorExit(PTSTR);

DWORD WINAPI ChildWatcher(HANDLE hChildProcess) {
    WaitForSingleObject(hChildProcess, INFINITE);
    ExitProcess(2);
    // FIXME
}


DWORD WINAPI Init(void* pSocket)
{
    ChildHandles chHandles;
    chHandles.socket = *(SOCKET*)pSocket;
    
    delete pSocket;

    SECURITY_ATTRIBUTES saAttr;

    char recvbuf[BUFSIZE];
    int recvbuflen = BUFSIZE;
    int iResult;

    printf("\n->Start of parent execution.\n");

    // Set the bInheritHandle flag so pipe handles are inherited. 

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT.
    
    if (!CreatePipe(&chHandles.OUT_Rd, &chHandles.OUT_Wr, &saAttr, 0))
        ErrorExit(TEXT("StdoutRd CreatePipe"));

    // Ensure the read handle to the pipe for STDOUT is not inherited.

    if (!SetHandleInformation(chHandles.OUT_Rd, HANDLE_FLAG_INHERIT, 0))
        ErrorExit(TEXT("Stdout SetHandleInformation"));

    // Create a pipe for the child process's STDIN. 

    if (!CreatePipe(&chHandles.IN_Rd, &chHandles.IN_Wr, &saAttr, 0))
        ErrorExit(TEXT("Stdin CreatePipe"));

    // Ensure the write handle to the pipe for STDIN is not inherited. 

    if (!SetHandleInformation(chHandles.IN_Wr, HANDLE_FLAG_INHERIT, 0))
        ErrorExit(TEXT("Stdin SetHandleInformation"));

    // Create the child process with console thread and watcher thread.
    // stdin and stdout are redirected to corresponding child pipes.
    CreateChildProcess(&chHandles);


    // Create thread for ReadFromPipe HERE
    HANDLE hThread = CreateThread(NULL, 0, ReadFromPipe, &chHandles, 0, NULL);

    if (NULL == hThread) {// thread was not created,  TODO checking*/
        // TODO clean everything up

    }
    

    // Write to the pipe that is the standard input for a child process. 
    // Data is written to the pipe's buffers, so it is not necessary to wait
    // until the child process is running before writing data.

    DWORD dwWritten;
    BOOL bSuccess = FALSE;
    HANDLE hParentStdIn = GetStdHandle(STD_INPUT_HANDLE); // HERE

    do {
        iResult = recv(chHandles.socket, recvbuf, recvbuflen, 0);

        printf("Receive socket: %u\n", socket);

        if (iResult > 0) {
            printf("Bytes received: %d\n", iResult);

            bSuccess = WriteFile(chHandles.IN_Wr, recvbuf, iResult, &dwWritten, NULL);
            if (!bSuccess) break;
        }
        else if (iResult == 0)
            printf("Connection closing...\n");
        else  {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(chHandles.socket);
            WSACleanup();
            ExitThread(1);
            return 1;
        }
    } while (iResult > 0);

    // Close the pipe handle so the child process stops reading. 

    if (!CloseHandle(chHandles.IN_Wr))
        ErrorExit(TEXT("StdInWr CloseHandle"));


    // The remaining open handles are cleaned up when this process terminates. 
    // To avoid resource leaks in a larger application, close handles explicitly. 

    ExitThread(0);
    return 0;
}

void CreateChildProcess(void* pHandles)
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
    if (!bSuccess)
        ErrorExit(TEXT("CreateProcess"));
    else
    {
        // Close handles to the child process and its primary thread.
        // Some applications might keep these handles to monitor the status
        // of the child process, for example. 

        CreateThread(NULL, 0, ChildWatcher, piProcInfo.hProcess, 0, NULL);
       // CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);
    }
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
            closesocket(handles.socket);
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
    ExitProcess(1);
}

