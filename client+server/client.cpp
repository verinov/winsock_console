// client+server.cpp: Defines the entry point for the console application.
//

#include "stdafx.h"

#define TESTIT


#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
//--------------------

#define SECURITY_WIN32
#define SEC_SUCCESS(Status) ((Status) >= 0)

#define cbMaxMessage 12000
#define MessageAttribute ISC_REQ_CONFIDENTIALITY
#include <stdlib.h>
#include "SspiExample.h"

//  The following #define statement must be changed. ServerName must
//  be defined as the name of the computer running the server sample.
//  TargetName must be defined as the logon name of the user running 
//  the server program.

SEC_WCHAR* TargetName = 0;

#ifndef TESTIT
// name of user being authenticated
TCHAR g_pUser[100];
// name of user's domain
TCHAR *g_pDomain = 0;
// password of user being authenticated
TCHAR g_pPassword[100];

#else
// name of user being authenticated
TCHAR *g_pUser = 0;// TEXT("alex");
// name of user's domain
TCHAR *g_pDomain = 0;
// password of user being authenticated
TCHAR *g_pPassword = 0;// TEXT("1q2w3e");
#endif

TCHAR  *g_pPackage = TEXT("Negotiate");

#pragma comment (lib, "Secur32.lib")
//----------------------

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define BUFSIZE 4096
#define DEFAULT_PORT "48999"

SOCKET ConnectSocket;
CredHandle hCred;
struct _SecHandle  hCtxt;

DWORD WINAPI ReadFromSocket(void* arg);
DWORD WINAPI WriteToSocket(void* arg);
int client(char* ipAddr);


int __cdecl main(int argc, char** argv)
{
    client("93.175.5.109");
    return 0;

    printf("start client \r\n");
    if (argc == 2) {
        client(argv[1]);
    } else {
        printf("Format: %s ip_addr", argv[0]);
    }

    return 0;
}

static PSecurityFunctionTable g_pFuncs;

BOOL InitPackage(DWORD *pcbMaxMessage)
//
// Routine Description:
//    Finds, loads, and initializes the security package
// Return Value:
//    Returns TRUE is successful; otherwise FALSE is returned.
//
{
    SECURITY_STATUS ss;
    PSecPkgInfo pkgInfo;

    g_pFuncs = InitSecurityInterface();
    // Query for the package of interest
    //
    ss = g_pFuncs->QuerySecurityPackageInfo(g_pPackage, &pkgInfo);
    if (!SEC_SUCCESS(ss))  {
        printf("Could not query package info for %s, error %X\n",
            g_pPackage, ss);
        return(FALSE);
    }

    *pcbMaxMessage = pkgInfo->cbMaxToken;
    g_pFuncs->FreeContextBuffer(pkgInfo);

    return TRUE;
}


int client(char* ipAddr)
{    
    SECURITY_STATUS   ss;
    ULONG             cbMaxSignature;
    ULONG             cbSecurityTrailer;
    SecPkgContext_Sizes            SecPkgContextSizes;
    SecPkgContext_NegotiationInfo  SecPkgNegInfo;

    WSADATA wsaData;

    int iResult;

    //-------------------------------------------------------------------
    //  Initialize the socket and the SSP security package.

    if (WSAStartup(0x0101, &wsaData))
    {
        printf("Could not initialize winsock\n");
        return FALSE;
    }

    // -------------------------------------------------------------------
    //   Read login and password for destination machine
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    BOOL bSuccess;
    DWORD dwRead;

    printf("login: ");

#ifndef TESTIT
    iResult = ReadConsole(hStdIn, g_pUser, 99, &dwRead, NULL);

    g_pUser[_tcslen(g_pUser) - 2] = 0;


    if (!iResult) {
        printf("error reading login\n");
        return 2;
    }
#else
  //  g_pUser[0] = 0;
#endif
    
    printf(" pass: ");

    DWORD mode = 0;
    GetConsoleMode(hStdIn, &mode);
    SetConsoleMode(hStdIn, mode & (~ENABLE_ECHO_INPUT));
    
#ifndef TESTIT
    iResult = ReadConsole(hStdIn, g_pPassword, 99, &dwRead, NULL);

    g_pPassword[_tcslen(g_pPassword) - 2] = 0;

    if (!iResult) {
        printf("error reading password\n");
        return 2;
    }
#else
  //  g_pPassword[0] = 0;
#endif

    SetConsoleMode(hStdIn, mode);
    printf("\n");

    //--------------------------------------------------------------------
    //  Connect to a server.

    if (!ConnectAuthSocket(
        ipAddr,
        &ConnectSocket,
        &hCred,
        &hCtxt
        ))
    {
        printf("Authenticated server connection\n");
        exit(1);
    }

    //--------------------------------------------------------------------
    //   An authenticated session with a server has been established.
    //   Receive and manage a message from the server.
    //   First, find and display the name of the negotiated
    //   SSP and the size of the signature and the encryption 
    //   trailer blocks for this SSP.

    ss = g_pFuncs->QueryContextAttributes(
        &hCtxt,
        SECPKG_ATTR_NEGOTIATION_INFO,
        &SecPkgNegInfo);

    if (!SEC_SUCCESS(ss))
    {
        printf("QueryContextAttributes failed\n");
        exit(1);
    }
    else
    {
        ;//    wprintf(L"Package Name: %s\n", SecPkgNegInfo.PackageInfo->Name);
    }

    ss = g_pFuncs->QueryContextAttributes(
        &hCtxt,
        SECPKG_ATTR_SIZES,
        &SecPkgContextSizes);

    if (!SEC_SUCCESS(ss))
    {
        printf("Query context\n");
        exit(1);
    }


    cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
    cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;

    printf("InitializeSecurityContext result = 0x%08x\n", ss);

    HANDLE hReaderThread = CreateThread(NULL, 0, ReadFromSocket, NULL, 0, NULL);

    if (NULL == hReaderThread) {
        goto ERROR2;
    }

    HANDLE hWriterThread = CreateThread(NULL, 0, WriteToSocket, NULL, 0, NULL);

    if (NULL == hWriterThread) {
        goto ERROR3;
    }

    HANDLE handlesToWait[] = { hReaderThread, hWriterThread };

#ifndef TESTIT
    WaitForMultipleObjects(2, handlesToWait, false, INFINITE);
#else
    WaitForMultipleObjects(2, handlesToWait, false, INFINITE);
#endif
    //--------------------------------------------------------------------
    //  Terminate socket and security package.

    DeleteSecurityContext(&hCtxt);
    FreeCredentialHandle(&hCred);
    
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

    CHAR pMessage[cbMaxMessage];
    DWORD cbMessage;
    PBYTE pDataToClient = NULL;
    DWORD cbDataToClient = 0;

    SECURITY_STATUS   ss;
    ULONG             cbMaxSignature;
    ULONG             cbSecurityTrailer;
    SecPkgContext_Sizes            SecPkgContextSizes;
    SecPkgContext_NegotiationInfo  SecPkgNegInfo;

    ss = g_pFuncs->QueryContextAttributes(
        &hCtxt,
        SECPKG_ATTR_SIZES,
        &SecPkgContextSizes);

    if (!SEC_SUCCESS(ss))
    {
        printf("Query context\n");
        return FALSE;
    }

    cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
    cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;

    do
    {
        bSuccess = ReadFile(hStdIn, sendBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;

        EncryptThis(
            (PBYTE)sendBuf,
            dwRead,
            &pDataToClient,
            &cbDataToClient,
            cbSecurityTrailer,
            &hCtxt);

        if (!SendMsg(
            ConnectSocket,
            pDataToClient,
            cbDataToClient))
        {
            printf("send message failed. \n");
            break;
        }
     //   printf(" %d encrypted bytes sent. \n", cbDataToClient);
    } while (cbDataToClient > 0);

    return 0;
}


DWORD WINAPI ReadFromSocket(void* arg)
// Read from our stdin and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    CHAR recvBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    int iResult;
    BYTE Data[4*BUFSIZE];
    char* pMessage;

    SECURITY_STATUS   ss;
    ULONG             cbMaxSignature;
    ULONG             cbSecurityTrailer;
    SecPkgContext_Sizes            SecPkgContextSizes;
    SecPkgContext_NegotiationInfo  SecPkgNegInfo;

    ss = g_pFuncs->QueryContextAttributes(
        &hCtxt,
        SECPKG_ATTR_SIZES,
        &SecPkgContextSizes);

    if (!SEC_SUCCESS(ss))
    {
        printf("Query context\n");
        exit(1);
    }

    cbMaxSignature = SecPkgContextSizes.cbMaxSignature;
    cbSecurityTrailer = SecPkgContextSizes.cbSecurityTrailer;

    DWORD cbRead;

    do {
        if (!ReceiveMsg(
            ConnectSocket,
            (PBYTE)recvBuf,
            BUFSIZE,
            &cbRead))
        {
            printf("No response from server\n");
            exit(1);
        }
       // printf(" %d encrypted bytes received. \n", cbRead);

        if (0 == cbRead)
        {
            printf("Zero bytes received\n");
            exit(1);
        }

        pMessage = (PCHAR)DecryptThis(
            (PBYTE)recvBuf,
            &cbRead,
            &hCtxt,
            cbSecurityTrailer);

        DWORD dwWritten;

        bool bSuccess = WriteFile(hStdOut, pMessage,
            cbRead, &dwWritten, NULL);
        Sleep(50);

        if (!bSuccess) {
            printf("WriteFile failed!!!\n");
            return 1;
        }
        FlushFileBuffers(hStdOut);
    } while (cbRead > 0);
    
    return 0;
}


//--------------------------------------------------------------------
//  ConnectAuthSocket establishes an authenticated socket connection 
//  with a server and initializes needed security package resources.

BOOL ConnectAuthSocket(
    char* ipAddr,
    SOCKET            *s,
    CredHandle        *hCred,
struct _SecHandle *hCtxt)
{
    ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
        *ptr = NULL,
        hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = PF_UNSPEC; // either an IPv6 or IPv4 address can be returned
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    // Resolve the server address and port
    int iResult = getaddrinfo(ipAddr, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        return 0;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to server
        *s = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (*s == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            return 0;
        }

        // Connect to server.
        iResult = connect(*s, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(*s);
            *s = INVALID_SOCKET;
            continue;
        }
        break;
    }

    if (ptr == NULL) {
        printf("connection failed\n");
        return 0;
    }

    freeaddrinfo(result);

    if (*s == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        return 0;
    }

    //--------------------------------------------------------------------
    //  Authenticate the connection. 

    if (!DoAuthentication(*s, hCred, hCtxt))
    {
        closesocket(*s);
        printf("Authentication\n");
        exit(1);
    }

    BYTE msg;
    DWORD cbIn;
    if (!ReceiveMsg(*s, &msg, sizeof(msg), &cbIn)) {
        printf("Authentication failed\n");
        closesocket(*s);
    }

    return msg;
}  // end ConnectAuthSocket 

BOOL DoAuthentication(SOCKET s, CredHandle *hCred, struct _SecHandle *hCtxt)

{
    BOOL done = FALSE;
    BOOL fSuccess = FALSE;
    DWORD cbMaxMessageLocal;
    if (!InitPackage(&cbMaxMessageLocal))
        return FALSE;

    BOOL        fDone = FALSE;
    DWORD       cbOut = 0;
    DWORD       cbIn = 0;
    PBYTE       pInBuf;
    PBYTE       pOutBuf;


    if (!(pInBuf = (PBYTE)malloc(cbMaxMessage)))
    {
        printf("Memory allocation\n");
        return FALSE;
    }

    if (!(pOutBuf = (PBYTE)malloc(cbMaxMessage)))
    {
        printf("Memory allocation\n");
        goto exit1;
    }

    cbOut = cbMaxMessage;
    if (!GenClientContext(
        NULL,
        0,
        pOutBuf,
        &cbOut,
        &fDone,
        TargetName,
        hCred,
        hCtxt
        ))
    {
        goto exit2;
    }

    if (!SendMsg(s, pOutBuf, cbOut))
    {
        printf("Send message failed\n");
        exit(1);
    }
   // printf("sent %d bytes\n", cbOut);

    while (!fDone)
    {
        if (!ReceiveMsg(
            s,
            pInBuf,
            cbMaxMessage,
            &cbIn))
        {
            printf("Receive message failed\n");
            exit(1);
        }
       // printf("received %d bytes\n", cbIn);
        cbOut = cbMaxMessage;

        if (!GenClientContext(
            pInBuf,
            cbIn,
            pOutBuf,
            &cbOut,
            &fDone,
            TargetName,
            hCred,
            hCtxt))
        {
            printf("GenClientContext failed\n");
            exit(1);
        }
        if (!SendMsg(
            s,
            pOutBuf,
            cbOut))
        {
            printf("Send message 2  failed\n");
            goto exit2;
        }
      //  printf("sent %d bytes\n", cbOut);
    }

    free(pInBuf);
    free(pOutBuf);
    return TRUE;

exit2:
    free(pInBuf);
exit1:
    free(pOutBuf);
    return FALSE;
}

BOOL GenClientContext(
    BYTE *pIn,
    DWORD cbIn,
    BYTE *pOut,
    DWORD *pcbOut,
    BOOL *pfDone,
    SEC_WCHAR *pszTarget,
    CredHandle *hCred,
struct _SecHandle *hCtxt)
{
    SECURITY_STATUS   ss;
    TimeStamp         Lifetime;
    SecBufferDesc     OutBuffDesc;
    SecBuffer         OutSecBuff;
    SecBufferDesc     InBuffDesc;
    SecBuffer         InSecBuff;
    ULONG             ContextAttributes;
    BOOL              fNewContext = FALSE;

    static TCHAR      lpPackageName[1024] = TEXT("Negotiate");

    SEC_WINNT_AUTH_IDENTITY authData;

    if (NULL == pIn)
    {
        // first call - get the credential handle
        fNewContext = TRUE;

        //strcpy_s((CHAR*)lpPackageName, 1024 * sizeof(TCHAR), "Negotiate");


        authData.User = g_pUser && g_pUser[0] ? (unsigned short*)g_pUser : 0;
        authData.UserLength = g_pUser ? _tcslen(g_pUser) : 0;
        authData.Domain = (unsigned short*)g_pDomain;
        authData.DomainLength = g_pDomain ? _tcslen(g_pDomain) : 0;
        authData.Password = g_pPassword && g_pPassword[0] ? (unsigned short*)g_pPassword : 0;
        authData.PasswordLength = g_pPassword ? _tcslen(g_pPassword) : 0;

        authData.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        ss = g_pFuncs->AcquireCredentialsHandle(
            NULL,
            lpPackageName,
            SECPKG_CRED_OUTBOUND,
            NULL,
            &authData,
            NULL,
            NULL,
            hCred,
            &Lifetime);

        if (!(SEC_SUCCESS(ss)))
        {
            printf("AcquireCreds failed\n");
            return FALSE;
        }
    }

    //--------------------------------------------------------------------
    //  Prepare the buffers.

    OutBuffDesc.ulVersion = 0;
    OutBuffDesc.cBuffers = 1;
    OutBuffDesc.pBuffers = &OutSecBuff;

    OutSecBuff.cbBuffer = *pcbOut;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer = pOut;

    //-------------------------------------------------------------------
    //  The input buffer is created only if a message has been received 
    //  from the server.

    if (pIn)
    {
        InBuffDesc.ulVersion = 0;
        InBuffDesc.cBuffers = 1;
        InBuffDesc.pBuffers = &InSecBuff;

        InSecBuff.cbBuffer = cbIn;
        InSecBuff.BufferType = SECBUFFER_TOKEN;
        InSecBuff.pvBuffer = pIn;

        ss = g_pFuncs->InitializeSecurityContext(
            hCred,
            hCtxt,
            pszTarget,
            MessageAttribute,
            0,
            SECURITY_NATIVE_DREP,
            &InBuffDesc,
            0,
            hCtxt,
            &OutBuffDesc,
            &ContextAttributes,
            &Lifetime);
    }
    else
    {
        ss = g_pFuncs->InitializeSecurityContext(
            hCred, // _In_opt_ PCredHandle phCredential
            fNewContext ? NULL : hCtxt, // _In_opt_ PCtxtHandle phContext
            pszTarget, // _In_ SEC_CHAR *pszTargetName
            MessageAttribute, //  _In_ ULONG fContextReq
            0, // Reserved1
            SECURITY_NATIVE_DREP, // _In_ ULONG TargetDataRep
            fNewContext ? NULL : &InBuffDesc, // _In_opt_ PSecBufferDesc pInput
            0, // Reserved2
            hCtxt, // _Inout_opt_ PCtxtHandle phNewContext
            &OutBuffDesc, // _Inout_opt_ PSecBufferDesc pOutput
            &ContextAttributes, // _Out_ PULONG pfContextAttr
            &Lifetime); // _Out_opt_ PTimeStamp ptsExpiry
    }

    if (!SEC_SUCCESS(ss))
    {
        printf("InitializeSecurityContext failed\n");
        return FALSE;
    }

    //-------------------------------------------------------------------
    //  If necessary, complete the token.

    if ((SEC_I_COMPLETE_NEEDED == ss)
        || (SEC_I_COMPLETE_AND_CONTINUE == ss))
    {
        ss = g_pFuncs->CompleteAuthToken(hCtxt, &OutBuffDesc);
        if (!SEC_SUCCESS(ss))
        {
            printf("complete failed: 0x%08x\n", ss);
            return FALSE;
        }
    }

    *pcbOut = OutSecBuff.cbBuffer;

    *pfDone = !((SEC_I_CONTINUE_NEEDED == ss) ||
        (SEC_I_COMPLETE_AND_CONTINUE == ss));

   // printf("Token buffer generated (%lu bytes):\n", OutSecBuff.cbBuffer);
   // PrintHexDump(OutSecBuff.cbBuffer, (PBYTE)OutSecBuff.pvBuffer);
    return TRUE;

}

