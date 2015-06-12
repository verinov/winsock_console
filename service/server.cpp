// client+server.cpp: Defines the entry point for the console application.
//


#include "stdafx.h"
#include "myService.h"

#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>

SOCKET g_sockListen = 0;
static PBYTE g_pInBuf = NULL;
static PBYTE g_pOutBuf = NULL;
static DWORD g_cbMaxMessage;
static TCHAR g_lpPackageName[32] = TEXT("Negotiate");

extern HANDLE ghSvcStopEvent;

BOOL AcceptAuthSocket(SOCKET *ServerSocket, CredHandle *hCred, struct _SecHandle *hCtxt);

static PSecurityFunctionTable g_pFuncs;

DWORD WINAPI Server(void*) {
        WSADATA wsaData;
        SECURITY_STATUS ss;
        PSecPkgInfo pkgInfo;

        if (WSAStartup(0x0101, &wsaData))
        {
            printf("Could not initialize winsock: \n");
            goto cleanup;
        }

        g_pFuncs = InitSecurityInterface();

        ss = g_pFuncs->QuerySecurityPackageInfo(
            g_lpPackageName,
            &pkgInfo);

        if (!SEC_SUCCESS(ss))
        {
            printf("Could not query package info for %s, error 0x%08x\n",
                g_lpPackageName, ss);
            goto cleanup;
        }

        g_cbMaxMessage = pkgInfo->cbMaxToken;

        FreeContextBuffer(pkgInfo);

        g_pInBuf = (PBYTE)malloc(g_cbMaxMessage);
        g_pOutBuf = (PBYTE)malloc(g_cbMaxMessage);

        if (NULL == g_pInBuf || NULL == g_pOutBuf)
        {
            printf("Memory allocation error.\n");
            goto cleanup;
        }

        // -----------------------------------------------------------
        // create listen socket
        SOCKADDR_IN sockIn;
        g_sockListen = socket(
            PF_INET,
            SOCK_STREAM,
            0);

        if (INVALID_SOCKET == g_sockListen)
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
            g_sockListen,
            (LPSOCKADDR)&sockIn,
            sizeof(sockIn)))
        {
            closesocket(g_sockListen);
            printf("bind failed: %u\n", GetLastError());
            return(FALSE);
        }

        //-----------------------------------------------------------------   
        //  Listen for client.

        if (SOCKET_ERROR == listen(g_sockListen, 1))
        {
            closesocket(g_sockListen);
            printf("Listen failed: %u\n", GetLastError());
            return(FALSE);
        }
        else
        {
            printf("Listening ! \n");
        }

        //-----------------------------------------------------------------   
        //  Start looping for clients.

        while (TRUE)
        {
            if (WaitForSingleObject(ghSvcStopEvent, 0) != WAIT_TIMEOUT) {
                break;
            }

            InitArgs *initArgs = new InitArgs;

            initArgs->socket = accept(
                g_sockListen,
                NULL,
                NULL);

            if (INVALID_SOCKET == initArgs->socket)
            {
                printf("accept failed: %u\n", GetLastError());
                goto skip1;
            }

            //-----------------------------------------------------------------   
            //  Make an authenticated connection with client.
            if (!DoAuthentication(initArgs->socket, &initArgs->hCred, &initArgs->hCtxt))
            {
                printf("Could not authenticate the socket.\n");
                goto skip2;
            }

            HANDLE hThread = CreateThread(NULL, 0, Init, initArgs, 0, NULL);
            if (NULL == hThread) {
                printf("create thread failed!\n");
                return 27;
            }
            // now Init() thread is responsible for all three handles

            printf("client socket accepted\n");

            CloseHandle(hThread);

            continue;
        skip2:
            closesocket(initArgs->socket);
        skip1:
            delete initArgs;
        }  // end while loop

    cleanup:
        if (g_pInBuf)
            free(g_pInBuf);

        if (g_pOutBuf)
            free(g_pOutBuf);

        WSACleanup();
        exit(0);
}

BOOL DoAuthentication(SOCKET socket, CredHandle *hCred, struct _SecHandle *hCtxt)
{
    BYTE msg = 1;
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
        goto fail;
    }

    DWORD cbIn, cbOut;
    BOOL done = FALSE;
    
    BOOL fNewConversation;

    fNewConversation = TRUE;

    while (!done)
    {
        if (!ReceiveMsg(
            socket,
            g_pInBuf,
            g_cbMaxMessage,
            &cbIn))
        {
            goto fail;
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
            goto fail;
        }
        fNewConversation = FALSE;
        if (!SendMsg(
            socket,
            g_pOutBuf,
            cbOut))
        {
            printf("Sending message failed.\n");
            goto fail;
        }
    }

    goto success;

fail:
    msg = 0;
success:

    if (!SendMsg(socket, &msg, sizeof(msg)) || !msg) {
        printf("Authentication failed\n");
        return FALSE;
    }
    return TRUE;
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
