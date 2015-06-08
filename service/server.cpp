// client+server.cpp: Defines the entry point for the console application.
//


#include "stdafx.h"

#include "myService.h"




//-----------------


#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>


static PBYTE g_pInBuf = NULL;
static PBYTE g_pOutBuf = NULL;
static DWORD g_cbMaxMessage;
static TCHAR g_lpPackageName[1024] = TEXT("Negotiate");

BOOL AcceptAuthSocket(SOCKET *ServerSocket, CredHandle *hCred, struct _SecHandle *hCtxt);

static PSecurityFunctionTable g_pFuncs;

DWORD WINAPI Server(void*) {
        WSADATA wsaData;
        SECURITY_STATUS ss;
        PSecPkgInfo pkgInfo;

        //-----------------------------------------------------------------   
        //  Set the default package to negotiate.
        //strcpy_s((CHAR*)g_lpPackageName, 1024 * sizeof(TCHAR), L"Negotiate");
       
        //-----------------------------------------------------------------   
        //  Initialize the socket interface and the security package.

        if (WSAStartup(0x0101, &wsaData))
        {
            printf("Could not initialize winsock: \n");
            cleanup();
        }

        g_pFuncs = InitSecurityInterface();

        ss = g_pFuncs->QuerySecurityPackageInfo(
            g_lpPackageName,
            &pkgInfo);

        if (!SEC_SUCCESS(ss))
        {
            printf("Could not query package info for %s, error 0x%08x\n",
                g_lpPackageName, ss);
            cleanup();
        }

        g_cbMaxMessage = pkgInfo->cbMaxToken;

        FreeContextBuffer(pkgInfo);

        g_pInBuf = (PBYTE)malloc(g_cbMaxMessage);
        g_pOutBuf = (PBYTE)malloc(g_cbMaxMessage);

        if (NULL == g_pInBuf || NULL == g_pOutBuf)
        {
            printf("Memory allocation error.\n");
            cleanup();
        }

        //-----------------------------------------------------------------   
        //  Start looping for clients.

        while (TRUE)
        {
            InitArgs *initArgs = new InitArgs;

            //-----------------------------------------------------------------   
            //  Make an authenticated connection with client.
            if (!AcceptAuthSocket(&initArgs->socket, &initArgs->hCred, &initArgs->hCtxt))
            {
                printf("Could not authenticate the socket.\n");
                delete initArgs;
                continue;
            }

            HANDLE hThread = CreateThread(NULL, 0, Init, initArgs, 0, NULL);
            if (NULL == hThread) {
                delete initArgs;
                printf("create thread failed!\n");
                return 27;
            }

            printf("client socket accepted\n");
        }  // end while loop


        // impossible
        printf("Server ran to completion without error.\n");
        cleanup();
        return 0;
}


BOOL AcceptAuthSocket(SOCKET *ServerSocket, CredHandle *hCred, struct _SecHandle *hCtxt)
{
    SOCKET sockListen;
    SOCKET sockClient;
    SOCKADDR_IN sockIn;

    //-----------------------------------------------------------------   
    //  Create listening socket.

    sockListen = socket(
        PF_INET,
        SOCK_STREAM,
        0);

    if (INVALID_SOCKET == sockListen)
    {
        printf("Failed to create socket: %u\n", GetLastError());
        return(FALSE);
    }

    //-----------------------------------------------------------------   
    //  Bind to local port.

    sockIn.sin_family = AF_INET;
    sockIn.sin_addr.s_addr = 0;
    sockIn.sin_port = htons(DEFAULT_PORT);

    if (SOCKET_ERROR == bind(
        sockListen,
        (LPSOCKADDR)&sockIn,
        sizeof(sockIn)))
    {
        closesocket(sockListen);
        printf("bind failed: %u\n", GetLastError());
        return(FALSE);
    }

    //-----------------------------------------------------------------   
    //  Listen for client.

    if (SOCKET_ERROR == listen(sockListen, 1))
    {
        closesocket(sockListen);
        printf("Listen failed: %u\n", GetLastError());
        return(FALSE);
    }
    else
    {
        printf("Listening ! \n");
    }

    //-----------------------------------------------------------------   
    //  Accept client.

    sockClient = accept(
        sockListen,
        NULL,
        NULL);

    if (INVALID_SOCKET == sockClient)
    {
        closesocket(sockListen);
        printf("accept failed: %u\n", GetLastError());
        return(FALSE);
    }

    closesocket(sockListen);

    *ServerSocket = sockClient;

    SECURITY_STATUS   ss;
    TimeStamp         Lifetime;
    ss = g_pFuncs->AcquireCredentialsHandle(
        NULL,
        g_lpPackageName,
        SECPKG_CRED_INBOUND,
        NULL,
        NULL,
        NULL,
        NULL,
        hCred,
        &Lifetime);

    if (!SEC_SUCCESS(ss))
    {
        printf("AcquireCreds failed: 0x%08x\n", ss);
        return(FALSE);
    }

    BYTE msg = DoAuthentication(sockClient, hCred, hCtxt);
    if (!SendMsg(sockClient, &msg, sizeof(msg)) || !msg) {
        printf("Authentication failed\n");
        closesocket(sockClient);
    }
    if (!msg) {
        printf("(because of status send failed)\n");
    }

    return msg;
}  // end AcceptAuthSocket  

BOOL DoAuthentication(SOCKET AuthSocket, CredHandle *hCred, struct _SecHandle *hCtxt)
{
    
    DWORD cbIn, cbOut;
    BOOL done = FALSE;
    
    BOOL fNewConversation;

    fNewConversation = TRUE;

    while (!done)
    {
        if (!ReceiveMsg(
            AuthSocket,
            g_pInBuf,
            g_cbMaxMessage,
            &cbIn))
        {
            return(FALSE);
        }

        cbOut = g_cbMaxMessage;

        if (!GenServerContext(
            g_pInBuf,
            cbIn,
            g_pOutBuf,
            &cbOut,
            &done,
            fNewConversation,
            hCred,
            hCtxt))
        {
            printf("GenServerContext failed.\n");
            return(FALSE);
        }
        fNewConversation = FALSE;
        if (!SendMsg(
            AuthSocket,
            g_pOutBuf,
            cbOut))
        {
            printf("Sending message failed.\n");
            return(FALSE);
        }
    }

    return(TRUE);
}  // end DoAuthentication

BOOL GenServerContext(
    BYTE *pIn,
    DWORD cbIn,
    BYTE *pOut,
    DWORD *pcbOut,
    BOOL *pfDone,
    BOOL fNewConversation,
    CredHandle *hCred,
struct _SecHandle *hCtxt)
{
    SECURITY_STATUS   ss;
    TimeStamp         Lifetime;
    SecBufferDesc     OutBuffDesc;
    SecBuffer         OutSecBuff;
    SecBufferDesc     InBuffDesc;
    SecBuffer         InSecBuff;
    ULONG             Attribs = 0;

    //----------------------------------------------------------------
    //  Prepare output buffers.

    OutBuffDesc.ulVersion = 0;
    OutBuffDesc.cBuffers = 1;
    OutBuffDesc.pBuffers = &OutSecBuff;

    OutSecBuff.cbBuffer = *pcbOut;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer = pOut;

    //----------------------------------------------------------------
    //  Prepare input buffers.

    InBuffDesc.ulVersion = 0;
    InBuffDesc.cBuffers = 1;
    InBuffDesc.pBuffers = &InSecBuff;

    InSecBuff.cbBuffer = cbIn;
    InSecBuff.BufferType = SECBUFFER_TOKEN;
    InSecBuff.pvBuffer = pIn;

   // printf("Token buffer received (%lu bytes):\n", InSecBuff.cbBuffer);

    ss = g_pFuncs->AcceptSecurityContext(
        hCred,
        fNewConversation ? NULL : hCtxt,
        &InBuffDesc,
        Attribs,
        SECURITY_NATIVE_DREP,
        hCtxt,
        &OutBuffDesc,
        &Attribs,
        &Lifetime);

    if (!SEC_SUCCESS(ss))
    {
        printf("AcceptSecurityContext failed: 0x%08x\n", ss);
        return FALSE;
    }

    //----------------------------------------------------------------
    //  Complete token if applicable.

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


  //  printf("Token buffer generated (%lu bytes):\n",
  //      OutSecBuff.cbBuffer);

    *pfDone = !((SEC_I_CONTINUE_NEEDED == ss)
        || (SEC_I_COMPLETE_AND_CONTINUE == ss));

    printf("AcceptSecurityContext result = 0x%08x\n", ss);

    return TRUE;

}  // end GenServerContext


void cleanup()
{
    if (g_pInBuf)
        free(g_pInBuf);

    if (g_pOutBuf)
        free(g_pOutBuf);

    WSACleanup();
    exit(0);
}
