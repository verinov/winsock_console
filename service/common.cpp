#include "stdafx.h"

#include "myService.h"

BOOL SendMsg(
    SOCKET s,
    PBYTE pBuf,
    DWORD cbBuf)
{
    if (0 == cbBuf)
        return(TRUE);

    //----------------------------------------------------------------
    //  Send the size of the message.

    if (!SendBytes(
        s,
        (PBYTE)&cbBuf,
        sizeof(cbBuf)))
    {
        return(FALSE);
    }

    //----------------------------------------------------------------    
    //  Send the body of the message.

    if (!SendBytes(
        s,
        pBuf,
        cbBuf))
    {
        return(FALSE);
    }

    return(TRUE);
} // end SendMsg   



PBYTE DecryptThis(
    PBYTE              pBuffer,
    LPDWORD            pcbMessage,
struct _SecHandle *hCtxt,
    ULONG              cbSecurityTrailer)
{
    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    PBYTE             pSigBuffer;
    PBYTE             pDataBuffer;
    DWORD             SigBufferSize;

    //-------------------------------------------------------------------
    //  By agreement, the server encrypted the message and set the size
    //  of the trailer block to be just what it needed. DecryptMessage 
    //  needs the size of the trailer block. 
    //  The size of the trailer is in the first DWORD of the
    //  message received. 

    SigBufferSize = *((DWORD *)pBuffer);
   // printf("data before decryption including trailer (%lu bytes):\n",
   //     *pcbMessage);
   // PrintHexDump(*pcbMessage, (PBYTE)pBuffer);

    //--------------------------------------------------------------------
    //  By agreement, the server placed the trailer at the beginning 
    //  of the message that was sent immediately following the trailer 
    //  size DWORD.

    pSigBuffer = pBuffer + sizeof(DWORD);

    //--------------------------------------------------------------------
    //  The data comes after the trailer.

    pDataBuffer = pSigBuffer + SigBufferSize;

    //--------------------------------------------------------------------
    //  *pcbMessage is reset to the size of just the encrypted bytes.

    *pcbMessage = *pcbMessage - SigBufferSize - sizeof(DWORD);

    //--------------------------------------------------------------------
    //  Prepare the buffers to be passed to the DecryptMessage function.

    BuffDesc.ulVersion = 0;
    BuffDesc.cBuffers = 2;
    BuffDesc.pBuffers = SecBuff;

    SecBuff[0].cbBuffer = SigBufferSize;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer = pSigBuffer;

    SecBuff[1].cbBuffer = *pcbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer = pDataBuffer;

    ss = DecryptMessage(
        hCtxt,
        &BuffDesc,
        0,
        &ulQop);

    if (!SEC_SUCCESS(ss))
    {
        printf("DecryptMessage failed");
    }

    //-------------------------------------------------------------------
    //  Return a pointer to the decrypted data. The trailer data
    //  is discarded.

    return pDataBuffer;

}

BOOL ReceiveMsg(
    SOCKET s,
    PBYTE pBuf,
    DWORD cbBuf,
    DWORD *pcbRead)
{
    DWORD cbRead;
    DWORD cbData;

    //-----------------------------------------------------------------
    //  Retrieve the number of bytes in the message.

    if (!ReceiveBytes(
        s,
        (PBYTE)&cbData,
        sizeof(cbData),
        &cbRead))
    {
        return(FALSE);
    }

    if (sizeof(cbData) != cbRead)
    {
        return(FALSE);
    }

    //----------------------------------------------------------------
    //  Read the full message.

    if (!ReceiveBytes(
        s,
        pBuf,
        cbData,
        &cbRead))
    {
        return(FALSE);
    }

    if (cbRead != cbData)
    {
        return(FALSE);
    }

    *pcbRead = cbRead;

    return(TRUE);
}  // end ReceiveMsg    

BOOL SendBytes(
    SOCKET s,
    PBYTE pBuf,
    DWORD cbBuf)
{
    PBYTE pTemp = pBuf;
    int cbSent, cbRemaining = cbBuf;

    if (0 == cbBuf)
    {
        return(TRUE);
    }

    while (cbRemaining)
    {
        cbSent = send(
            s,
            (const char *)pTemp,
            cbRemaining,
            0);
        if (SOCKET_ERROR == cbSent)
        {
            printf("send failed: %u\n", GetLastError());
            return FALSE;
        }

        pTemp += cbSent;
        cbRemaining -= cbSent;
    }

    return TRUE;
}  // end SendBytes

BOOL ReceiveBytes(
    SOCKET s,
    PBYTE pBuf,
    DWORD cbBuf,
    DWORD *pcbRead)
{
    PBYTE pTemp = pBuf;
    int cbRead, cbRemaining = cbBuf;

    while (cbRemaining)
    {
        cbRead = recv(
            s,
            (char *)pTemp,
            cbRemaining,
            0);
        if (0 == cbRead)
        {
            break;
        }

        if (SOCKET_ERROR == cbRead)
        {
            printf("recv failed: %u\n", GetLastError());
            return FALSE;
        }

        cbRemaining -= cbRead;
        pTemp += cbRead;
    }

    *pcbRead = cbBuf - cbRemaining;

    return TRUE;
}  // end ReceivesBytes

BOOL EncryptThis(
    PBYTE pMessage,
    ULONG cbMessage,
    BYTE ** ppOutput,
    ULONG * pcbOutput,
    ULONG cbSecurityTrailer,
struct _SecHandle *hCtxt)
{
    SECURITY_STATUS   ss;
    SecBufferDesc     BuffDesc;
    SecBuffer         SecBuff[2];
    ULONG             ulQop = 0;
    ULONG             SigBufferSize;

    //-----------------------------------------------------------------
    //  The size of the trailer (signature + padding) block is 
    //  determined from the global cbSecurityTrailer.

    SigBufferSize = cbSecurityTrailer;

  //  printf("Data before encryption: %s\n", pMessage);
  //  printf("Length of data before encryption: %d \n", cbMessage);

    //-----------------------------------------------------------------
    //  Allocate a buffer to hold the signature,
    //  encrypted data, and a DWORD  
    //  that specifies the size of the trailer block.

    * ppOutput = (PBYTE)malloc(
        SigBufferSize + cbMessage + sizeof(DWORD));

    //------------------------------------------------------------------
    //  Prepare buffers.

    BuffDesc.ulVersion = 0;
    BuffDesc.cBuffers = 2;
    BuffDesc.pBuffers = SecBuff;

    SecBuff[0].cbBuffer = SigBufferSize;
    SecBuff[0].BufferType = SECBUFFER_TOKEN;
    SecBuff[0].pvBuffer = *ppOutput + sizeof(DWORD);

    SecBuff[1].cbBuffer = cbMessage;
    SecBuff[1].BufferType = SECBUFFER_DATA;
    SecBuff[1].pvBuffer = pMessage;

    ss = EncryptMessage(
        hCtxt,
        ulQop,
        &BuffDesc,
        0);

    if (!SEC_SUCCESS(ss))
    {
        printf("EncryptMessage failed: 0x%08x\n", ss);
        return(FALSE);
    }
    else
    {
     //   printf("The message has been encrypted. \n");
    }

    //------------------------------------------------------------------
    //  Indicate the size of the buffer in the first DWORD. 

    *((DWORD *)*ppOutput) = SecBuff[0].cbBuffer;

    //-----------------------------------------------------------------
    //  Append the encrypted data to our trailer block
    //  to form a single block. 
    //  Putting trailer at the beginning of the buffer works out 
    //  better. 

    memcpy(*ppOutput + SecBuff[0].cbBuffer + sizeof(DWORD), pMessage,
        cbMessage);

    *pcbOutput = cbMessage + SecBuff[0].cbBuffer + sizeof(DWORD);

   // printf("data after encryption including trailer (%lu bytes):\n",
   //     *pcbOutput);
   // PrintHexDump(*pcbOutput, *ppOutput);

    return TRUE;

}  // end EncryptThis
