// console_pipe_winsock.cpp: Defines the entry point for the console application.
//

#include "stdafx.h"

#include "myService.h"

#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>

////////
#define SECURITY_WIN32
#define SEC_SUCCESS(Status) ((Status) >= 0)
#define cbMaxMessage 12000

#pragma comment (lib, "Secur32.lib")
#pragma comment (lib, "Ws2_32.lib")

#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include "SspiExample.h"
///////

extern HANDLE ghSvcStopEvent;

struct ChildHandles {
    HANDLE IN_Rd = NULL;
    HANDLE IN_Wr = NULL;
    HANDLE OUT_Rd = NULL;
    HANDLE OUT_Wr = NULL;
    SOCKET socket = 0;
    SecHandle hCtxt;
    HANDLE hTerminateEvent;
};


HANDLE CreateChildProcess(void*);
DWORD WINAPI WriteToPipe(void* pHandles);
DWORD WINAPI ReadFromPipe(void*);
void ErrorExit(PTSTR);

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

    handles.hTerminateEvent = CreateEvent(
        NULL,               // default security attributes
        TRUE,               // manual-reset event
        FALSE,              // initial state is nonsignaled
        NULL  // object name
        );
    if (handles.hTerminateEvent == NULL)
    {
        printf("CreateEvent failed (%d)\n", GetLastError());
        return false;
    }

    return true;
}

bool CloseHandles(ChildHandles& handles) {
    bool result = true;
    if (!CloseHandle(handles.IN_Wr)) {
        printf("IN_Wr CloseHandle\n");
        result = false;
    }
    if (!CloseHandle(handles.IN_Rd)) {
        printf("IN_Rd CloseHandle\n");
        result = false;
    }
    if (!CloseHandle(handles.OUT_Wr)) {
        printf("OUT_Wr CloseHandle\n");
        result = false;
    }
    if (!CloseHandle(handles.OUT_Rd)) {
        printf("OUT_Rd CloseHandle\n");
        result = false;
    }
    if (!CloseHandle(handles.hTerminateEvent)) {
        printf("TerminateEvent CloseHandle\n");
        result = false;
    }

    shutdown(handles.socket, SD_BOTH);
    closesocket(handles.socket);
    return result;
}


DWORD WINAPI Init(void* args)
{
  //  __debugbreak();
    ChildHandles chHandles;
    SOCKET socket = chHandles.socket = ((InitArgs*)args)->socket;

    SecHandle hCtxt = ((InitArgs*)args)->hCtxt;
    CredHandle hCred = ((InitArgs*)args)->hCred;
    delete args;

    if (!FillHandles(chHandles)) {
        goto exit1;
    }

    chHandles.hCtxt = hCtxt;

    CHAR pMessage[cbMaxMessage];
    DWORD cbMessage;
    DWORD cbDataToClient = 0;
    LPWSTR pUserName = NULL;
    DWORD cbUserName = 0;

    SecPkgContext_Sizes SecPkgContextSizes;
    SecPkgContext_NegotiationInfo SecPkgNegInfo;
    ULONG cbMaxSignature;
    ULONG cbSecurityTrailer;

    /////////

    SECURITY_STATUS ss;

    ss = QueryContextAttributes(
        &hCtxt,
        SECPKG_ATTR_NEGOTIATION_INFO,
        &SecPkgNegInfo);

    if (!SEC_SUCCESS(ss))
    {
        printf("QueryContextAttributes failed: 0x%08x\n", ss);
        goto exit1;
    }
    else
    {
        ;//  wprintf(L"Package Name: %s\n", SecPkgNegInfo.PackageInfo->Name);
    }

    //----------------------------------------------------------------
    //  Free the allocated buffer.

    FreeContextBuffer(SecPkgNegInfo.PackageInfo);

    //-----------------------------------------------------------------   
    //  Impersonate the client.

    ss = ImpersonateSecurityContext(&hCtxt);
    if (!SEC_SUCCESS(ss))
    {
        printf("Impersonate failed: 0x%08x\n", ss);
        goto exit1;
    }
    else
    {
        ;// printf("Impersonation worked. \n");
    }

    GetUserName(NULL, &cbUserName);
    pUserName = (LPWSTR)malloc(sizeof(TCHAR)*cbUserName);

    if (!pUserName)
    {
        printf("Memory allocation error. \n");
        RevertSecurityContext(&hCtxt); // need check for double fail?
        goto exit1;
    }

    if (!GetUserName(
        pUserName,
        &cbUserName))
    {
        printf("Could not get the client name. \n");
        RevertSecurityContext(&hCtxt); // need check for double fail?
        goto exit2;
    }
    else
    {
        _tprintf(TEXT("Client connected as :  %s\n"), pUserName);
    }

    //-----------------------------------------------------------------   
    //  Revert to self.

    ss = RevertSecurityContext(&hCtxt);
    if (!SEC_SUCCESS(ss))
    {
        printf("Revert failed: 0x%08x\n", ss);
        goto exit2;
    }
    else
    {
        ;// printf("Reverted to self.\n");
    }

    COMMTIMEOUTS cto;
    GetCommTimeouts(chHandles.OUT_Rd, &cto);
    // Set the new timeouts
    cto.ReadIntervalTimeout = 10;
    cto.ReadTotalTimeoutConstant = 100;
    cto.ReadTotalTimeoutMultiplier = 0;
    SetCommTimeouts(chHandles.OUT_Rd, &cto);


    printf("\n->Start of parent execution.\n");

    // Create the child process with console thread and watcher thread.
    // stdin and stdout are redirected to corresponding child pipes.
    HANDLE hCmdProcess = 0, hOutputThread = 0, hInputThread = 0;

    hCmdProcess = CreateChildProcess(&chHandles);
    if (!hCmdProcess) {
        goto exit2;
    }

    hOutputThread = CreateThread(NULL, 0, ReadFromPipe, &chHandles, 0, NULL);
    if (!hOutputThread) 
    {
        goto exit3;
    }
    
    hInputThread = CreateThread(NULL, 0, WriteToPipe, &chHandles, 0, NULL);
    if (!hInputThread) {
        goto exit3;
    }

    HANDLE handlesToWait[] = { hCmdProcess, hOutputThread, hInputThread, ghSvcStopEvent };

    WaitForMultipleObjects(4, handlesToWait, false, INFINITE);

exit3:
    if (!SetEvent(chHandles.hTerminateEvent))
    {
        printf("SetEvent failed (%d)\n", GetLastError());
    }

    if (WaitForMultipleObjects(3, handlesToWait, true, INFINITE) != WAIT_OBJECT_0) { // wait for all
        if (hCmdProcess) {
            TerminateProcess(hCmdProcess, 0);
        }
        if (hOutputThread) {
            TerminateThread(hOutputThread, 0);
        }
        if (hInputThread) {
            TerminateThread(hInputThread, 0);
        }
    }

    if (hCmdProcess) CloseHandle(hCmdProcess);
    if (hOutputThread) CloseHandle(hOutputThread);
    if (hInputThread) CloseHandle(hInputThread);

exit2:
    free(pUserName);
exit1:
    if (!CloseHandles(chHandles)) {
        printf("handle close failed\n");
    }

    DeleteSecurityContext(&hCtxt);
    FreeCredentialHandle(&hCred);

    return 0;
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

    char recvBuf[BUFSIZE];
    int recvbuflen = BUFSIZE;
    int iResult;

    DWORD dwWritten;
    BOOL bSuccess = FALSE;

    BYTE Data[4 * BUFSIZE];
    char* pMessage;

    SECURITY_STATUS   ss;
    ULONG             cbMaxSignature;
    ULONG             cbSecurityTrailer;
    SecPkgContext_Sizes            SecPkgContextSizes;

    ss = QueryContextAttributes(
        &handles.hCtxt,
        SECPKG_ATTR_SIZES,
        &SecPkgContextSizes);

    if (!SEC_SUCCESS(ss))
    {
        printf("Query context\n");
        return 0;
    }


    cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
    cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;

    DWORD cbRead;

    do {
        if (WaitForSingleObject(handles.hTerminateEvent, 0) != WAIT_TIMEOUT) {
            break;
        }

        if (!ReceiveMsg(
            handles.socket,
            (PBYTE)recvBuf,
            BUFSIZE,
            &cbRead))
        {
            printf("No response from client\n");
            return 0;
        }        
        
        DWORD dwWritten;

        if (cbRead > 0) {
            PCHAR pMess = (PCHAR)DecryptThis(
                (PBYTE)recvBuf,
                &cbRead,
                &handles.hCtxt,
                cbSecurityTrailer);

            bSuccess = WriteFile(handles.IN_Wr, pMess, cbRead, &dwWritten, NULL);
            if (!bSuccess) return 0;
        }
        else if (cbRead == 0) {
            ;// printf("Connection closing...\n");
        }
        else  {
            //printf("recv failed with error: %d\n", WSAGetLastError());
            return 0;
        }
    } while (cbRead > 0);

    return 1;
}

DWORD WINAPI ReadFromPipe(void* pHandles)
// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
{
  //  __debugbreak();
    ChildHandles handles = *(ChildHandles*)pHandles;

    CHAR pMessage[cbMaxMessage];

    DWORD dwRead;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    int iResult;

    DWORD cbMessage;
    PBYTE pDataToClient = NULL;
    DWORD cbDataToClient = 0;

    SECURITY_STATUS   ss;
    ULONG             cbMaxSignature;
    ULONG             cbSecurityTrailer;
    SecPkgContext_Sizes            SecPkgContextSizes;

    ss = QueryContextAttributes(
        &handles.hCtxt,
        SECPKG_ATTR_SIZES,
        &SecPkgContextSizes);

    if (!SEC_SUCCESS(ss))
    {
        printf("Query context\n");
        return 0;
    }


    COMMTIMEOUTS cto;
    if (!GetCommTimeouts(handles.OUT_Rd, &cto)) {
        printf("failed to get timeout, error %d\n", GetLastError());
    }
    // Set the new timeouts
    cto.ReadIntervalTimeout = MAXDWORD;
    cto.ReadTotalTimeoutConstant = 1;
    cto.ReadTotalTimeoutMultiplier = MAXDWORD;
    if (!SetCommTimeouts(handles.OUT_Rd, &cto)) {
        printf("failed to set timeout, error %d\n", GetLastError());
    }


    cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
    cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;

    do {
        if (WaitForSingleObject(handles.hTerminateEvent, 0) != WAIT_TIMEOUT) {
            break;
        }

        bSuccess = ReadFile(handles.OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;

        EncryptThis(
            (PBYTE)chBuf,
            dwRead,
            &pDataToClient,
            &cbDataToClient,
            cbSecurityTrailer,
            &handles.hCtxt);

        //-----------------------------------------------------------------   
        //  Send the encrypted data to client.


        if (!SendMsg(
            handles.socket,
            pDataToClient,
            cbDataToClient))
        {
            //printf("send message failed. \n");
            return 0;
        }
    } while (dwRead > 0);

    return 1;
}