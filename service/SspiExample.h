//  SspiExample.h

#include <sspi.h>
#include <windows.h>

BOOL SendMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf);
BOOL ReceiveMsg(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD *pcbRead);
BOOL SendBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf);
BOOL ReceiveBytes(SOCKET s, PBYTE pBuf, DWORD cbBuf, DWORD *pcbRead);

BOOL GenClientContext(
    BYTE *pIn,
    DWORD cbIn,
    BYTE *pOut,
    DWORD *pcbOut,
    BOOL *pfDone,
    SEC_WCHAR *pszTarget,
    CredHandle *hCred,
struct _SecHandle *hCtxt
    );

BOOL GenServerContext(
    BYTE *pIn,
    DWORD cbIn,
    BYTE *pOut,
    DWORD *pcbOut,
    BOOL *pfDone,
    BOOL  fNewCredential,
    CredHandle *hCred,
struct _SecHandle *hCtxt
    );

BOOL EncryptThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE ** ppOutput,
    ULONG * pcbOutput,
    ULONG cbSecurityTrailer,
struct _SecHandle *hCtxt);

PBYTE DecryptThis(
    PBYTE achData,
    LPDWORD pcbMessage,
struct _SecHandle *hCtxt,
    ULONG   cbSecurityTrailer
    );

BOOL
SignThis(
PBYTE pMessage,
ULONG cbMessage,
BYTE ** ppOutput,
LPDWORD pcbOutput
);


BOOL ConnectAuthSocket(
    char* ipAddr,
    SOCKET *s,
    CredHandle *hCred,
struct _SecHandle *hcText
    );

BOOL CloseAuthSocket(SOCKET s);

BOOL DoAuthentication(SOCKET s, CredHandle *hCred, struct _SecHandle *hCtxt);
