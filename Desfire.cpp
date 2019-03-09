/************************************************************************************
 * 
 * @author   Elmü
 * 
 * This library has been tested with Desfire EV1 cards. 
 * It will surely not work with older Desfire cards (deprecated) because legacy authentication is not implemented.
 * I have older code with lagacy authentication. If you are interested contact me on Codeproject.
 * 
 * This library is based on code from the following open source libraries:
 * https://github.com/nceruchalu/easypay
 * https://github.com/leg0/libfreefare
 * http://liblogicalaccess.islog.com
 * 
 * The open source code has been completely rewritten for the Arduino compiler by Elmü.
 * Check for a new version on:
 * http://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup
 * 
*************************************************************************************
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include "Desfire.h"
#include "Secrets.h"

Desfire::Desfire() 
    : mi_CmacBuffer(mu8_CmacBuffer_Data, sizeof(mu8_CmacBuffer_Data))
{
    mpi_SessionKey       = NULL;
    mu8_LastAuthKeyNo    = NOT_AUTHENTICATED;
    mu8_LastPN532Error   = 0;    
    mu32_LastApplication = 0x000000; // No application selected

    // The PICC master key on an empty card is a simple DES key filled with 8 zeros
    const byte ZERO_KEY[24] = {0};
    DES2_DEFAULT_KEY.SetKeyData(ZERO_KEY,  8, 0); // simple DES
    DES3_DEFAULT_KEY.SetKeyData(ZERO_KEY, 24, 0); // triple DES
     AES_DEFAULT_KEY.SetKeyData(ZERO_KEY, 16, 0);
}

// Whenever the RF field is switched off, these variables must be reset
bool Desfire::SwitchOffRfField()
{
    mu8_LastAuthKeyNo    = NOT_AUTHENTICATED;
    mu32_LastApplication = 0x000000; // No application selected

    return PN532::SwitchOffRfField();
}

/**************************************************************************
    Does an ISO authentication with a 2K3DES key or an AES authentication with an AES key.
    pi_Key must be an instance of DES or AES.
    The authentication is a 3-pass process where both sides prove that they use the same master key
    without ever exposing that key. Only random values are exchanged.
    Not all commands require authentication.    
    If you want to authenticate for an application you must call SelectApplication() first.
    If you select application 0x000000 pi_Key must be the PICC master key (set u8_KeyNo = 0),
    otherwise one of the up to 14 application keys is chosen with u8_KeyNo.
    IMPORTANT: If the card expects the 3K3DES default key you must pass a 3K3DES key full of 24 zeroes,
    although this is in reality a simple DES key (K1 == K2 == K3). Otherwise the session key is calculated wrong.
**************************************************************************/
bool Desfire::Authenticate(byte u8_KeyNo, DESFireKey* pi_Key)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** Authenticate(KeyNo= %d, Key= ", u8_KeyNo);
        Utils::Print(s8_Buf);
        pi_Key->PrintKey();
        Utils::Print(")\r\n");
    }

    byte u8_Command;
    switch (pi_Key->GetKeyType())
    { 
        case DF_KEY_AES:    u8_Command = DFEV1_INS_AUTHENTICATE_AES; break;
        case DF_KEY_2K3DES:
        case DF_KEY_3K3DES: u8_Command = DFEV1_INS_AUTHENTICATE_ISO; break;
        default:
            Utils::Print("Invalid key\r\n");
            return false;
    }

    TX_BUFFER(i_Params, 1);
    i_Params.AppendUint8(u8_KeyNo);

    // Request a random of 16 byte, but depending of the key the PICC may also return an 8 byte random
    DESFireStatus e_Status;
    byte u8_RndB_enc[16]; // encrypted random B
    int s32_Read = DataExchange(u8_Command, &i_Params, u8_RndB_enc, 16, &e_Status, MAC_None);
    if (e_Status != ST_MoreFrames || (s32_Read != 8 && s32_Read != 16))
    {
        Utils::Print("Authentication failed (1)\r\n");
        return false;
    }

    int s32_RandomSize = s32_Read;

    byte u8_RndB[16];  // decrypted random B
    pi_Key->ClearIV(); // Fill IV with zeroes !ONLY ONCE HERE!
    if (!pi_Key->CryptDataCBC(CBC_RECEIVE, KEY_DECIPHER, u8_RndB, u8_RndB_enc, s32_RandomSize))
        return false;  // key not set

    byte u8_RndB_rot[16]; // rotated random B
    Utils::RotateBlockLeft(u8_RndB_rot, u8_RndB, s32_RandomSize);

    byte u8_RndA[16];
    Utils::GenerateRandom(u8_RndA, s32_RandomSize);

    TX_BUFFER(i_RndAB, 32); // (randomA + rotated randomB)
    i_RndAB.AppendBuf(u8_RndA,     s32_RandomSize);
    i_RndAB.AppendBuf(u8_RndB_rot, s32_RandomSize);

    TX_BUFFER(i_RndAB_enc, 32); // encrypted (randomA + rotated randomB)
    i_RndAB_enc.SetCount(2*s32_RandomSize);
    if (!pi_Key->CryptDataCBC(CBC_SEND, KEY_ENCIPHER, i_RndAB_enc, i_RndAB, 2*s32_RandomSize))
        return false;

    if (mu8_DebugLevel > 0)
    {
        Utils::Print("* RndB_enc:  ");
        Utils::PrintHexBuf(u8_RndB_enc,  s32_RandomSize, LF);
        Utils::Print("* RndB:      ");
        Utils::PrintHexBuf(u8_RndB,      s32_RandomSize, LF);
        Utils::Print("* RndB_rot:  ");
        Utils::PrintHexBuf(u8_RndB_rot,  s32_RandomSize, LF);
        Utils::Print("* RndA:      ");
        Utils::PrintHexBuf(u8_RndA,      s32_RandomSize, LF);
        Utils::Print("* RndAB:     ");
        Utils::PrintHexBuf(i_RndAB,      2*s32_RandomSize, LF);
        Utils::Print("* RndAB_enc: ");
        Utils::PrintHexBuf(i_RndAB_enc,  2*s32_RandomSize, LF);
    }

    byte u8_RndA_enc[16]; // encrypted random A
    s32_Read = DataExchange(DF_INS_ADDITIONAL_FRAME, &i_RndAB_enc, u8_RndA_enc, s32_RandomSize, &e_Status, MAC_None);
    if (e_Status != ST_Success || s32_Read != s32_RandomSize)
    {
        Utils::Print("Authentication failed (2)\r\n");
        return false;
    }

    byte u8_RndA_dec[16]; // decrypted random A
    if (!pi_Key->CryptDataCBC(CBC_RECEIVE, KEY_DECIPHER, u8_RndA_dec, u8_RndA_enc, s32_RandomSize))
        return false;

    byte u8_RndA_rot[16]; // rotated random A
    Utils::RotateBlockLeft(u8_RndA_rot, u8_RndA, s32_RandomSize);   

    if (mu8_DebugLevel > 0)
    {
        Utils::Print("* RndA_enc:  ");
        Utils::PrintHexBuf(u8_RndA_enc, s32_RandomSize, LF);
        Utils::Print("* RndA_dec:  ");
        Utils::PrintHexBuf(u8_RndA_dec, s32_RandomSize, LF);
        Utils::Print("* RndA_rot:  ");
        Utils::PrintHexBuf(u8_RndA_rot, s32_RandomSize, LF);
    }

    // Last step: Check if the received random A is equal to the sent random A.
    if (memcmp(u8_RndA_dec, u8_RndA_rot, s32_RandomSize) != 0)
    {
        Utils::Print("Authentication failed (3)\r\n");
        return false;
    }

    // The session key is composed from RandA and RndB
    TX_BUFFER(i_SessKey, 24);
    i_SessKey.AppendBuf(u8_RndA, 4);
    i_SessKey.AppendBuf(u8_RndB, 4);

    if (pi_Key->GetKeySize() > 8) // the following block is not required for simple DES
    {
        switch (pi_Key->GetKeyType())
        {  
            case DF_KEY_2K3DES:
                i_SessKey.AppendBuf(u8_RndA + 4, 4);
                i_SessKey.AppendBuf(u8_RndB + 4, 4);
                break;
                
            case DF_KEY_3K3DES:
                i_SessKey.AppendBuf(u8_RndA +  6, 4);
                i_SessKey.AppendBuf(u8_RndB +  6, 4);
                i_SessKey.AppendBuf(u8_RndA + 12, 4);
                i_SessKey.AppendBuf(u8_RndB + 12, 4);
                break;
    
            case DF_KEY_AES:
                i_SessKey.AppendBuf(u8_RndA + 12, 4);
                i_SessKey.AppendBuf(u8_RndB + 12, 4);
                break;
    
            default: // avoid stupid gcc compiler warning
                break;
        }
    }
       
    if (pi_Key->GetKeyType() == DF_KEY_AES) mpi_SessionKey = &mi_AesSessionKey;
    else                                    mpi_SessionKey = &mi_DesSessionKey;
    
    if (!mpi_SessionKey->SetKeyData(i_SessKey, i_SessKey.GetCount(), 0) ||
        !mpi_SessionKey->GenerateCmacSubkeys())
        return false;

    if (mu8_DebugLevel > 0)
    {
        Utils::Print("* SessKey:   ");
        mpi_SessionKey->PrintKey(LF);
    }

    mu8_LastAuthKeyNo = u8_KeyNo;   
    return true;
}

/**************************************************************************
    ATTENTION: 
    Be very careful when you change the PICC master key (for application {0x000000})!
    If you don't know what you are doing you may have to throw the card into the dustbin!
    There is NO way to reanimate the card when you lost the master key.
    -----------------------------------------------------------------------
    Does a key change. You must first call Authenticate().
    To change an application key you must also call SelectApplication().
    To make it complicated NXP defines two different procedures:
    Changing the same key number that was used for authentication and changing another key. 
    After changing a key you have to authenticate again with the new key.
    pi_CurKey must be the old key (currently stored in u8_KeyNo) that you want to change into pi_NewKey.
    pi_CurKey may be NULL if you change the same key number that was used for authetication 
    or if the current key is the factory default key.
**************************************************************************/
bool Desfire::ChangeKey(byte u8_KeyNo, DESFireKey* pi_NewKey, DESFireKey* pi_CurKey)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** ChangeKey(KeyNo= %d)\r\n", u8_KeyNo);
        Utils::Print(s8_Buf);
    }

    if (mu8_LastAuthKeyNo == NOT_AUTHENTICATED)
    {
        Utils::Print("Not authenticated\r\n");
        return false;
    }

    if (mu8_DebugLevel > 0)
    {
        Utils::Print("* SessKey IV:  ");
        mpi_SessionKey->PrintIV(LF);
        Utils::Print("* New Key:     ");
        pi_NewKey->PrintKey(LF);
    }    

    if (!DESFireKey::CheckValid(pi_NewKey))
        return false;

    TX_BUFFER(i_Cryptogram, 40);
    i_Cryptogram.AppendBuf(pi_NewKey->Data(), pi_NewKey->GetKeySize(16));

    bool b_SameKey = (u8_KeyNo == mu8_LastAuthKeyNo);  // false -> change another key than the one that was used for authentication

    // The type of key can only be changed for the PICC master key.
    // Applications must define their key type in CreateApplication().
    if (mu32_LastApplication == 0x000000)
        u8_KeyNo |= pi_NewKey->GetKeyType();

    // The following if() applies only to application keys.
    // For the PICC master key b_SameKey is always true because there is only ONE key (#0) at the PICC level.
    if (!b_SameKey) 
    {
        if (!DESFireKey::CheckValid(pi_CurKey))
            return false;

        if (mu8_DebugLevel > 0)
        {
            Utils::Print("* Cur Key:     ");
            pi_CurKey->PrintKey(LF);
        }        

        // The current key and the new key must be XORed        
        Utils::XorDataBlock(i_Cryptogram, pi_CurKey->Data(), pi_CurKey->GetKeySize(16));
    }

    // While DES stores the key version in bit 0 of the key bytes, AES transmits the version separately
    if (pi_NewKey->GetKeyType() == DF_KEY_AES)
    {
        i_Cryptogram.AppendUint8(pi_NewKey->GetKeyVersion());
    }

    byte u8_Command[] = { DF_INS_CHANGE_KEY, u8_KeyNo };   
    uint32_t u32_Crc = Utils::CalcCrc32(u8_Command, 2, i_Cryptogram, i_Cryptogram.GetCount());
    i_Cryptogram.AppendUint32(u32_Crc);

    if (mu8_DebugLevel > 0)
    {
        Utils::Print("* CRC Crypto:  0x");
        Utils::PrintHex32(u32_Crc, LF);
    }

    if (!b_SameKey)
    {
        uint32_t u32_CrcNew = Utils::CalcCrc32(pi_NewKey->Data(), pi_NewKey->GetKeySize(16));
        i_Cryptogram.AppendUint32(u32_CrcNew);        

        if (mu8_DebugLevel > 0)
        {
            Utils::Print("* CRC New Key: 0x");
            Utils::PrintHex32(u32_CrcNew, LF);
        }
    }

    // Get the padded length of the Cryptogram to be encrypted
    int s32_CryptoLen = 24;
    if (i_Cryptogram.GetCount() > 24) s32_CryptoLen = 32;
    if (i_Cryptogram.GetCount() > 32) s32_CryptoLen = 40;

    // For a blocksize of 16 byte (AES) the data length 24 is not valid -> increase to 32
    s32_CryptoLen = mpi_SessionKey->CalcPaddedBlockSize(s32_CryptoLen);

    byte u8_Cryptogram_enc[40] = {0}; // encrypted cryptogram
    if (!mpi_SessionKey->CryptDataCBC(CBC_SEND, KEY_ENCIPHER, u8_Cryptogram_enc, i_Cryptogram, s32_CryptoLen))
        return false;

    if (mu8_DebugLevel > 0)
    {
        Utils::Print("* Cryptogram:  ");
        Utils::PrintHexBuf(i_Cryptogram, s32_CryptoLen, LF);
        Utils::Print("* Cryptog_enc: ");
        Utils::PrintHexBuf(u8_Cryptogram_enc, s32_CryptoLen, LF);
    }

    TX_BUFFER(i_Params, 41);
    i_Params.AppendUint8(u8_KeyNo);
    i_Params.AppendBuf  (u8_Cryptogram_enc, s32_CryptoLen);

    // If the same key has been changed the session key is no longer valid. (Authentication required)
    if (b_SameKey) mu8_LastAuthKeyNo = NOT_AUTHENTICATED;

    return (0 == DataExchange(DF_INS_CHANGE_KEY, &i_Params, NULL, 0, NULL, MAC_Rmac));
}

/**************************************************************************
    Get the version of the key (optional)
    To store a version number in the key use DES::SetKeyVersion() 
    before calling Desfire::ChangeKey()
**************************************************************************/
bool Desfire::GetKeyVersion(byte u8_KeyNo, byte* pu8_Version)
{
    char s8_Buf[80];
    if (mu8_DebugLevel > 0)
    {
        sprintf(s8_Buf, "\r\n*** GetKeyVersion(KeyNo= %d)\r\n", u8_KeyNo);
        Utils::Print(s8_Buf);
    }

    TX_BUFFER(i_Params, 1);
    i_Params.AppendUint8(u8_KeyNo);

    if (1 != DataExchange(DF_INS_GET_KEY_VERSION, &i_Params, pu8_Version, 1, NULL, MAC_TmacRmac))
        return false;

    if (mu8_DebugLevel > 0)
    {
        Utils::Print("Version: 0x");
        Utils::PrintHex8(*pu8_Version, LF);
    }
    return true;
}

/**************************************************************************
    Reads several production details of the Desfire card
    If RandomID mode is active, the UID will be returned as 00 00 00 00 00 00 00
**************************************************************************/
bool Desfire::GetCardVersion(DESFireCardVersion* pk_Version)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** GetCardVersion()\r\n");

    byte* pu8_Ptr = (byte*)pk_Version;

    DESFireStatus e_Status;
    int s32_Read = DataExchange(DF_INS_GET_VERSION, NULL, pu8_Ptr, 7, &e_Status, MAC_TmacRmac);
    if (s32_Read != 7 || e_Status != ST_MoreFrames)
        return false;

    pu8_Ptr += 7;
    s32_Read = DataExchange(DF_INS_ADDITIONAL_FRAME, NULL, pu8_Ptr, 7, &e_Status, MAC_Rmac);
    if (s32_Read != 7 || e_Status != ST_MoreFrames)
        return false;

    pu8_Ptr += 7;
    s32_Read = DataExchange(DF_INS_ADDITIONAL_FRAME, NULL, pu8_Ptr, 14, &e_Status, MAC_Rmac);
    if (s32_Read != 14 || e_Status != ST_Success)
        return false;

    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        Utils::Print("--- Desfire Card Details ---\r\n");
        sprintf(s8_Buf, "Hardware Version: %d.%d\r\n", pk_Version->hardwareMajVersion, pk_Version->hardwareMinVersion);
        Utils::Print(s8_Buf);
        sprintf(s8_Buf, "Software Version: %d.%d\r\n", pk_Version->softwareMajVersion, pk_Version->softwareMinVersion);
        Utils::Print(s8_Buf);
        sprintf(s8_Buf, "EEPROM size:      %d byte\r\n", 1 << (pk_Version->hardwareStorageSize / 2));
        Utils::Print(s8_Buf);
        sprintf(s8_Buf, "Production:       week %X, year 20%02X\r\n", pk_Version->cwProd, pk_Version->yearProd);
        Utils::Print(s8_Buf);
        Utils::Print("UID no:           ");         
        Utils::PrintHexBuf(pk_Version->uid, 7, LF);
        Utils::Print("Batch no:         ");         
        Utils::PrintHexBuf(pk_Version->batchNo, 5, LF);
    }
    return true;
}

/**************************************************************************
    Erases all content from the card (all files and all applications)
**************************************************************************/
bool Desfire::FormatCard()
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** FormatCard()\r\n");

    return (0 == DataExchange(DF_INS_FORMAT_PICC, NULL, NULL, 0, NULL, MAC_TmacRmac));
}

/**************************************************************************
    Gets the settings of the master key.
    First you must call SelectApplication()
    After selecting the application 0x000000 the settings of the PICC master key 
    will be returned, otherwise the settings of the selected application master key.
    pu8_KeyCount will contain the max number of keys for an application.
    pu8_KeyCount will be = 1 for the application ID 0x000000.
    pe_KeyType returns the type of key for the application (2K3DES / AES)
**************************************************************************/
bool Desfire::GetKeySettings(DESFireKeySettings* pe_Settg, byte* pu8_KeyCount, DESFireKeyType* pe_KeyType)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** GetKeySettings()\r\n");
  
    byte u8_RetData[2];
    if (2 != DataExchange(DF_INS_GET_KEY_SETTINGS, NULL, u8_RetData, 2, NULL, MAC_TmacRmac))
        return false;

    *pe_Settg = (DESFireKeySettings)u8_RetData[0];
    *pu8_KeyCount = u8_RetData[1] & 0x0F;
    *pe_KeyType   = (DESFireKeyType)(u8_RetData[1] & 0xF0);

    if (mu8_DebugLevel > 0)
    {
         char s8_Buf[80];
         sprintf(s8_Buf, "Settings: 0x%02X, KeyCount: %d, KeyType: %s\r\n", *pe_Settg, *pu8_KeyCount, DESFireKey::GetKeyTypeAsString(*pe_KeyType));
         Utils::Print(s8_Buf);
    }
    return true;
}

/**************************************************************************
    Changes the settings of the PICC or application master key.
    First you must call SelectApplication() and authenticate with the master key.
**************************************************************************/
bool Desfire::ChangeKeySettings(DESFireKeySettings e_NewSettg)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** ChangeKeySettings(0x%02X)\r\n", e_NewSettg);
        Utils::Print(s8_Buf);
    }

    TX_BUFFER(i_Params, 16);
    i_Params.AppendUint8(e_NewSettg);

    // The TX CMAC must not be calculated here because a CBC encryption operation has already been executed
    return (0 == DataExchange(DF_INS_CHANGE_KEY_SETTINGS, &i_Params, NULL, 0, NULL, MAC_TcryptRmac));
}

/**************************************************************************
    Enables random ID mode in which the card sends another UID each time.
    In Random UID mode the card sends a 4 byte UID that always starts with 0x80.
    To get the real UID of the card call GetRealCardID()
    ---------------------------------------------------------------------
    ATTENTION ATTENTION ATTENTION ATTENTION ATTENTION ATTENTION ATTENTION
    ---------------------------------------------------------------------
    NXP does not provide any way to turn off Random ID mode.
    If you once call this funtion the card will send random ID FOREVER!
    ---------------------------------------------------------------------
    ATTENTION ATTENTION ATTENTION ATTENTION ATTENTION ATTENTION ATTENTION
    ---------------------------------------------------------------------
**************************************************************************/
bool Desfire::EnableRandomIDForever()
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** EnableRandomIDForever()\r\n");

    TX_BUFFER(i_Command, 2);
    i_Command.AppendUint8(DFEV1_INS_SET_CONFIGURATION);
    i_Command.AppendUint8(0x00); // subcommand 00
    
    TX_BUFFER(i_Params, 16);
    i_Params.AppendUint8(0x02); // 0x02 = enable random ID, 0x01 = disable format

    // The TX CMAC must not be calculated here because a CBC encryption operation has already been executed
    return (0 == DataExchange(&i_Command, &i_Params, NULL, 0, NULL, MAC_TcryptRmac));
}

/**************************************************************************
    This command makes only sense if the card is in Random UID mode.
    It allows to obtain the real UID of the card.
    If Random ID mode is not active use ReadPassiveTargetID() or GetCardVersion()
    instead to get the UID.
    A previous authentication is required.
**************************************************************************/
bool Desfire::GetRealCardID(byte u8_UID[7])
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** GetRealCardID()\r\n");

    if (mu8_LastAuthKeyNo == NOT_AUTHENTICATED)
    {
        Utils::Print("Not authenticated\r\n");
        return false;
    }

    RX_BUFFER(i_Data, 16);
    if (16 != DataExchange(DFEV1_INS_GET_CARD_UID, NULL, i_Data, 16, NULL, MAC_TmacRcrypt))
        return false;

    // The card returns UID[7] + CRC32[4] encrypted with the session key
    // Copy the 7 bytes of the UID to the output buffer
    i_Data.ReadBuf(u8_UID, 7);

    // Get the CRC sent by the card
    uint32_t u32_Crc1 = i_Data.ReadUint32();

    // The CRC must be calculated over the UID + the status byte appended
    byte u8_Status = ST_Success;
    uint32_t u32_Crc2 = Utils::CalcCrc32(u8_UID, 7, &u8_Status, 1);

    if (mu8_DebugLevel > 1)
    {
        Utils::Print("* CRC:       0x");
        Utils::PrintHex32(u32_Crc2, LF);
    }

    if (u32_Crc1 != u32_Crc2)
    {
        Utils::Print("Invalid CRC\r\n");
        return false;
    }

    if (mu8_DebugLevel > 0)
    {
        Utils::Print("Real UID: ");
        Utils::PrintHexBuf(u8_UID, 7, LF);
    }
    return true;
}

/**************************************************************************
    Get the remaining free memory on the card.
    NOTE: This function gives stranges results:
    8k Card formatted: EPPROM size: 8192 bytes > Free memory: 7936 bytes.
    4k Card formatted: EPPROM size: 4096 bytes < Free memory: 4864 bytes!
**************************************************************************/
bool Desfire::GetFreeMemory(uint32_t* pu32_Memory)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** GetFreeMemory()\r\n");

    *pu32_Memory = 0;    
 
    RX_BUFFER(i_Data, 3);
    if (3 != DataExchange(DFEV1_INS_FREE_MEM, NULL, i_Data, 3, NULL, MAC_TmacRmac))
        return false;
 
    *pu32_Memory = i_Data.ReadUint24();
 
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "Free memory: %d bytes\r\n", (int)*pu32_Memory);
        Utils::Print(s8_Buf);
    }
    return true;
}

/**************************************************************************
    returns all Application ID's (AID) stored on the card. (maximum = 28 / card)
    Each application ID is 3 bytes.
    pu32_IDlist:   Must point to an uint32_t[28] array
    ps32_AppCount: The count of DESFireAppId's that have been stored in pk_IDlist.
**************************************************************************/
bool Desfire::GetApplicationIDs(uint32_t u32_IDlist[28], byte* pu8_AppCount)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** GetApplicationIDs()\r\n");

    memset(u32_IDlist, 0, 28 * sizeof(uint32_t));

    RX_BUFFER(i_RxBuf, 28*3); // 3 byte per application
    byte* pu8_Ptr = i_RxBuf;

    DESFireStatus e_Status;
    int s32_Read1 = DataExchange(DF_INS_GET_APPLICATION_IDS, NULL, pu8_Ptr, MAX_FRAME_SIZE, &e_Status, MAC_TmacRmac);
    if (s32_Read1 < 0)
        return false;

    // If there are more than 19 applications, they will be sent in two frames
    int s32_Read2 = 0;
    if (e_Status == ST_MoreFrames)
    {
        pu8_Ptr += s32_Read1;
        s32_Read2 = DataExchange(DF_INS_ADDITIONAL_FRAME, NULL, pu8_Ptr, 28 * 3 - s32_Read1, NULL, MAC_Rmac);
        if (s32_Read2 < 0)
            return false;
    }

    i_RxBuf.SetSize (s32_Read1 + s32_Read2);
    *pu8_AppCount = (s32_Read1 + s32_Read2) / 3;

    // Convert 3 byte array -> 4 byte array
    for (byte i=0; i<*pu8_AppCount; i++)
    {
        u32_IDlist[i] = i_RxBuf.ReadUint24();
    }

    if (mu8_DebugLevel > 0)
    {
        if (*pu8_AppCount == 0)
        {
            Utils::Print("No Application ID's.\r\n");
        }
        else for (byte i=0; i<*pu8_AppCount; i++)
        {
            char s8_Buf[80];
            sprintf(s8_Buf, "Application %2d: 0x%06X\r\n", i, (unsigned int)u32_IDlist[i]);
            Utils::Print(s8_Buf);
        }
    }
    return true;
}

/**************************************************************************
    Creates a new application
    You must call SelectApplication(0x000000) before and authenticate with the PICC master key!
    u32_AppID:   The unique ID of the application
    e_Settg:     The application master key settings
    u8_KeyCount: The count of keys to be stored in the application
    e_KeyType:   Defines the key type for the application (2K3DES / AES)
**************************************************************************/
bool Desfire::CreateApplication(uint32_t u32_AppID, DESFireKeySettings e_Settg, byte u8_KeyCount, DESFireKeyType e_KeyType)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** CreateApplication(App= 0x%06X, KeyCount= %d, Type= %s)\r\n", (unsigned int)u32_AppID, u8_KeyCount, DESFireKey::GetKeyTypeAsString(e_KeyType));
        Utils::Print(s8_Buf);
    }

    if (e_KeyType == DF_KEY_INVALID)
    {
        Utils::Print("Invalid key type\r\n");
        return false;
    }

    TX_BUFFER(i_Params, 5);
    i_Params.AppendUint24(u32_AppID);
    i_Params.AppendUint8 (e_Settg);
    i_Params.AppendUint8 (u8_KeyCount | e_KeyType);

    return (0 == DataExchange(DF_INS_CREATE_APPLICATION, &i_Params, NULL, 0, NULL, MAC_TmacRmac));
}

/**************************************************************************
    Deletes an application after checking that it exists.
    When you call DeleteApplication() and the application does not exist,
    an ST_AppNotFound error is returned and the authentication is invalidated.
    To avoid this error, this function calls first GetApplicationIDs()
**************************************************************************/
bool Desfire::DeleteApplicationIfExists(uint32_t u32_AppID)
{
    uint32_t u32_IDlist[28];
    byte     u8_AppCount;
    if (!GetApplicationIDs(u32_IDlist, &u8_AppCount))
        return false;

    bool b_Found = false;
    for (byte i=0; i<u8_AppCount; i++)
    {
        if (u32_IDlist[i] == u32_AppID)
            b_Found = true;
    }
    if (!b_Found)
        return true;

    return DeleteApplication(u32_AppID);
}

/**************************************************************************
    Deletes an application
    You must call SelectApplication(0x000000) before and authenticate with the PICC master key!
**************************************************************************/
bool Desfire::DeleteApplication(uint32_t u32_AppID)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** DeleteApplication(0x%06X)\r\n", (unsigned int)u32_AppID);
        Utils::Print(s8_Buf);
    }

    TX_BUFFER(i_Params, 3);
    i_Params.AppendUint24(u32_AppID);   

    return (0 == DataExchange(DF_INS_DELETE_APPLICATION, &i_Params, NULL, 0, NULL, MAC_TmacRmac));
}

/**************************************************************************
    Selects an application
    If u8_AppID is 0x000000 the PICC level is selected
**************************************************************************/
bool Desfire::SelectApplication(uint32_t u32_AppID)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** SelectApplication(0x%06X)\r\n", (unsigned int)u32_AppID);
        Utils::Print(s8_Buf);
    }

    TX_BUFFER(i_Params, 3);
    i_Params.AppendUint24(u32_AppID);

    // This command does not return a CMAC because after selecting another application the session key is no longer valid. (Authentication required)
    if (0 != DataExchange(DF_INS_SELECT_APPLICATION, &i_Params, NULL, 0, NULL, MAC_None))
        return false;

    mu8_LastAuthKeyNo    = NOT_AUTHENTICATED; // set to invalid value (the selected app requires authentication)
    mu32_LastApplication = u32_AppID;
    return true;
}

/**************************************************************************
    returns all File ID's for the selected application. 
    Desfire EV1: maximum = 32 files per application.
    u8_FileIDs:     Buffer of 32 bytes
    ps32_FileCount: The count of file Id's that have been written to u8_FileIDs.
**************************************************************************/
bool Desfire::GetFileIDs(byte* u8_FileIDs, byte* pu8_FileCount)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** GetFileIDs()\r\n");

    int s32_Read = DataExchange(DF_INS_GET_FILE_IDS, NULL, u8_FileIDs, 32, NULL, MAC_TmacRmac);
    if (s32_Read < 0)
        return false;

    *pu8_FileCount = s32_Read;

    if (mu8_DebugLevel > 0)
    {
        if (*pu8_FileCount == 0)
        {
            Utils::Print("No files.\r\n");
        }
        else 
        {
            Utils::Print("File ID's: ");
            Utils::PrintHexBuf(u8_FileIDs, s32_Read, LF);
        }
    }
    return true;
}

/**************************************************************************
    Gets the settings of a file.
**************************************************************************/
bool Desfire::GetFileSettings(byte u8_FileID, DESFireFileSettings* pk_Settings)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** GetFileSettings(ID= %d)\r\n", u8_FileID);
        Utils::Print(s8_Buf);
    }

    memset(pk_Settings, 0, sizeof(DESFireFileSettings));

    TX_BUFFER(i_Params, 1);
    i_Params.AppendUint8(u8_FileID);
  
    RX_BUFFER(i_RetData, 20);
    int s32_Read = DataExchange(DF_INS_GET_FILE_SETTINGS, &i_Params, i_RetData, 20, NULL, MAC_TmacRmac);
    if (s32_Read < 7)
        return false;

    i_RetData.SetSize(s32_Read);

    pk_Settings->e_FileType = (DESFireFileType)      i_RetData.ReadUint8();
    pk_Settings->e_Encrypt  = (DESFireFileEncryption)i_RetData.ReadUint8();
    pk_Settings->k_Permis.Unpack                    (i_RetData.ReadUint16());

    char s8_Buf[150];
    if (mu8_DebugLevel > 0)
    {
        sprintf(s8_Buf, "Type: %d, Encrypt: %d, Access Read: 0x%X, Write: 0x%X, Rd+Wr: 0x%X, Change: 0x%X\r\n", 
                        pk_Settings->e_FileType, pk_Settings->e_Encrypt,
                        pk_Settings->k_Permis.e_ReadAccess,         pk_Settings->k_Permis.e_WriteAccess, 
                        pk_Settings->k_Permis.e_ReadAndWriteAccess, pk_Settings->k_Permis.e_ChangeAccess);
        Utils::Print(s8_Buf);
    }    

    switch (pk_Settings->e_FileType)
    {
        case MDFT_STANDARD_DATA_FILE:
        case MDFT_BACKUP_DATA_FILE:
            pk_Settings->u32_FileSize = i_RetData.ReadUint24();
        
            if (mu8_DebugLevel > 0)
            {
                sprintf(s8_Buf, "FileSize: %d\r\n", (int)pk_Settings->u32_FileSize);
                Utils::Print(s8_Buf);
            }
            return true;

        case MDFT_VALUE_FILE_WITH_BACKUP:
            pk_Settings->u32_LowerLimit         = i_RetData.ReadUint32();
            pk_Settings->u32_UpperLimit         = i_RetData.ReadUint32();
            pk_Settings->u32_LimitedCreditValue = i_RetData.ReadUint32();
            pk_Settings->b_LimitedCreditEnabled = i_RetData.ReadUint8() == 0x01;

            if (mu8_DebugLevel > 0)
            {
                sprintf(s8_Buf, "LowerLimit: %d, UpperLimit: %d, CreditValue: %d, LimitEnabled: %d\r\n", 
                        (int)pk_Settings->u32_LowerLimit, (int)pk_Settings->u32_UpperLimit, (int)pk_Settings->u32_LimitedCreditValue, (int)pk_Settings->b_LimitedCreditEnabled);
                Utils::Print(s8_Buf);
            }
            return true;
            
        case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
        case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
            pk_Settings->u32_RecordSize           = i_RetData.ReadUint24();
            pk_Settings->u32_MaxNumberRecords     = i_RetData.ReadUint24();
            pk_Settings->u32_CurrentNumberRecords = i_RetData.ReadUint24();
            
            if (mu8_DebugLevel > 0)
            {
                sprintf(s8_Buf, "RecordSize: %d, MaxRecords: %d, CurrentRecords: %d\r\n", 
                        (int)pk_Settings->u32_RecordSize, (int)pk_Settings->u32_MaxNumberRecords, (int)pk_Settings->u32_CurrentNumberRecords);
                Utils::Print(s8_Buf);
            }
            return true;
            
        default:
            return false; // unknown file type
    }
}

/**************************************************************************
    Creates a standard data file (a simple binary file) of a fixed size in the selected application.
**************************************************************************/
bool Desfire::CreateStdDataFile(byte u8_FileID, DESFireFilePermissions* pk_Permis, int s32_FileSize)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** CreateStdDataFile(ID= %d, Size= %d)\r\n", u8_FileID, s32_FileSize);
        Utils::Print(s8_Buf);
    }

    uint16_t u16_Permis = pk_Permis->Pack();
  
    TX_BUFFER(i_Params, 7);
    i_Params.AppendUint8 (u8_FileID);
    i_Params.AppendUint8 (CM_PLAIN);
    i_Params.AppendUint16(u16_Permis);
    i_Params.AppendUint24(s32_FileSize); // only the low 3 bytes are used

    return (0 == DataExchange(DF_INS_CREATE_STD_DATA_FILE, &i_Params, NULL, 0, NULL, MAC_TmacRmac));

}

/**************************************************************************
    Deletes a file in the selected application
**************************************************************************/
bool Desfire::DeleteFile(byte u8_FileID)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** DeleteFile(ID= %d)\r\n", u8_FileID);
        Utils::Print(s8_Buf);
    }

    TX_BUFFER(i_Params, 1);
    i_Params.AppendUint8(u8_FileID);

    return (0 == DataExchange(DF_INS_DELETE_FILE, &i_Params, NULL, 0, NULL, MAC_TmacRmac));
}

/**************************************************************************
    Reads a block of data from a Standard Data File or a Backup Data File.
    If (s32_Offset + s32_Length > file length) you will get a LimitExceeded error.
    If the file permissins are not set to AR_FREE you must authenticate either
    with the key in e_ReadAccess or the key in e_ReadAndWriteAccess.   
**************************************************************************/
bool Desfire::ReadFileData(byte u8_FileID, int s32_Offset, int s32_Length, byte* u8_DataBuffer)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** ReadFileData(ID= %d, Offset= %d, Length= %d)\r\n", u8_FileID, s32_Offset, s32_Length);
        Utils::Print(s8_Buf);
    }

    // With intention this command does not use DF_INS_ADDITIONAL_FRAME because the CMAC must be calculated over all frames received.
    // When reading a lot of data this could lead to a buffer overflow in mi_CmacBuffer.
    while (s32_Length > 0)
    {
        int s32_Count = min(s32_Length, 48); // the maximum that can be transferred in one frame (must be a multiple of 16 if encryption is used)

        TX_BUFFER(i_Params, 7);
        i_Params.AppendUint8 (u8_FileID);
        i_Params.AppendUint24(s32_Offset); // only the low 3 bytes are used
        i_Params.AppendUint24(s32_Count);  // only the low 3 bytes are used
        
        DESFireStatus e_Status;
        int s32_Read = DataExchange(DF_INS_READ_DATA, &i_Params, u8_DataBuffer, s32_Count, &e_Status, MAC_TmacRmac);
        if (e_Status != ST_Success || s32_Read <= 0)
            return false; // ST_MoreFrames is not allowed here!

        s32_Length    -= s32_Read;
        s32_Offset    += s32_Read;
        u8_DataBuffer += s32_Read;
    }
    return true;
}

/**************************************************************************
    Writes data to a Standard Data File or a Backup Data File.
    If the file permissins are not set to AR_FREE you must authenticate either
    with the key in e_WriteAccess or the key in e_ReadAndWriteAccess.
**************************************************************************/
bool Desfire::WriteFileData(byte u8_FileID, int s32_Offset, int s32_Length, const byte* u8_DataBuffer)
{
    if (mu8_DebugLevel > 0)
    {
        char s8_Buf[80];
        sprintf(s8_Buf, "\r\n*** WriteFileData(ID= %d, Offset= %d, Length= %d)\r\n", u8_FileID, s32_Offset, s32_Length);
        Utils::Print(s8_Buf);
    }

    // With intention this command does not use DF_INS_ADDITIONAL_FRAME because the CMAC must be calculated over all frames sent.
    // When writing a lot of data this could lead to a buffer overflow in mi_CmacBuffer.
    while (s32_Length > 0)
    {
        int s32_Count = min(s32_Length, MAX_FRAME_SIZE - 8); // DF_INS_WRITE_DATA + u8_FileID + s32_Offset + s32_Count = 8 bytes
              
        TX_BUFFER(i_Params, MAX_FRAME_SIZE); 
        i_Params.AppendUint8 (u8_FileID);
        i_Params.AppendUint24(s32_Offset); // only the low 3 bytes are used
        i_Params.AppendUint24(s32_Count);  // only the low 3 bytes are used
        i_Params.AppendBuf(u8_DataBuffer, s32_Count);

        DESFireStatus e_Status;
        int s32_Read = DataExchange(DF_INS_WRITE_DATA, &i_Params, NULL, 0, &e_Status, MAC_TmacRmac);
        if (e_Status != ST_Success || s32_Read != 0)
            return false; // ST_MoreFrames is not allowed here!

        s32_Length    -= s32_Count;
        s32_Offset    += s32_Count;
        u8_DataBuffer += s32_Count;
    }
    return true;
}

/**************************************************************************
    Reads the value of a Value File
**************************************************************************/
bool Desfire::ReadFileValue(byte u8_FileID, uint32_t* pu32_Value)
{
	TX_BUFFER(i_Params, 1);
	i_Params.AppendUint8(u8_FileID);

	RX_BUFFER(i_RetData, 4);
	if (4 != DataExchange(DF_INS_GET_VALUE, &i_Params, i_RetData, 4, NULL, MAC_TmacRmac))
		return false;

	*pu32_Value = i_RetData.ReadUint32();
	return true;
}

// ########################################################################
// ####                      LOW LEVEL FUNCTIONS                      #####
// ########################################################################

// If this value is != 0, the PN532 has returned an error code while executing the latest command.
// Typically a Timeout error (Value = 0x01) means that the card is too far away from the reader.
// Interestingly a timeout occurres typically when authenticating. 
// The commands that are executed first (GetKeyVersion and SelectApplication) execute without problems.
// But it when it comes to Authenticate() the card suddenly does not respond anymore -> Timeout from PN532.
// Conclusion: It seems that a Desfire card increases its power consumption in the moment when encrypting data,
// so when it is too far away from the antenna -> the connection dies -> no answer -> timeout.
byte Desfire::GetLastPN532Error()
{
    return mu8_LastPN532Error;
}

/**************************************************************************
    Sends data to the card and receives the response.
    u8_Command    = Desfire command without additional paramaters
    pi_Command    = Desfire command + possible additional paramaters that will not be encrypted
    pi_Params     = Desfire command parameters that may be encrypted (MAC_Tcrypt). This paramater may also be null.
    u8_RecvBuf    = buffer that receives the received data (should be the size of the expected recv data)
   s32_RecvSize   = buffer size of u8_RecvBuf
    pe_Status     = if (!= NULL) -> receives the status byte
    e_Mac         = defines CMAC calculation
    returns the byte count that has been read into u8_RecvBuf or -1 on error
**************************************************************************/
int Desfire::DataExchange(byte u8_Command, TxBuffer* pi_Params, byte* u8_RecvBuf, int s32_RecvSize, DESFireStatus* pe_Status, DESFireCmac e_Mac)
{
    TX_BUFFER(i_Command, 1);
    i_Command.AppendUint8(u8_Command);
  
    return DataExchange(&i_Command, pi_Params, u8_RecvBuf, s32_RecvSize, pe_Status, e_Mac);
}
int Desfire::DataExchange(TxBuffer* pi_Command,               // in (command + params that are not encrypted)
                          TxBuffer* pi_Params,                // in (parameters that may be encrypted)
                          byte* u8_RecvBuf, int s32_RecvSize, // out
                          DESFireStatus* pe_Status,           // out
                          DESFireCmac    e_Mac)               // in
{
    if (pe_Status) *pe_Status = ST_Success;
    mu8_LastPN532Error = 0;

    TX_BUFFER(i_Empty, 1);
    if (pi_Params == NULL)
        pi_Params = &i_Empty;

    // The response for INDATAEXCHANGE is always: 
    // - 0xD5
    // - 0x41
    // - Status byte from PN532        (0 if no error)
    // - Status byte from Desfire card (0 if no error)
    // - data bytes ...
    int s32_Overhead = 11; // Overhead added to payload = 11 bytes = 7 bytes for PN532 frame + 3 bytes for INDATAEXCHANGE response + 1 card status byte
    if (e_Mac & MAC_Rmac) s32_Overhead += 8; // + 8 bytes for CMAC
  
    // mu8_PacketBuffer is used for input and output
    if (2 + pi_Command->GetCount() + pi_Params->GetCount() > PN532_PACKBUFFSIZE || s32_Overhead + s32_RecvSize > PN532_PACKBUFFSIZE)    
    {
        Utils::Print("DataExchange(): Invalid parameters\r\n");
        return -1;
    }

    if (e_Mac & (MAC_Tcrypt | MAC_Rcrypt))
    {
        if (mu8_LastAuthKeyNo == NOT_AUTHENTICATED)
        {
            Utils::Print("Not authenticated\r\n");
            return -1;
        }
    }

    if (e_Mac & MAC_Tcrypt) // CRC and encrypt pi_Params
    {
        if (mu8_DebugLevel > 0)
        {
            Utils::Print("* Sess Key IV: ");
            mpi_SessionKey->PrintIV(LF);
        }    
    
        // The CRC is calculated over the command (which is not encrypted) and the parameters to be encrypted.
        uint32_t u32_Crc = Utils::CalcCrc32(pi_Command->GetData(), pi_Command->GetCount(), pi_Params->GetData(), pi_Params->GetCount());
        if (!pi_Params->AppendUint32(u32_Crc))
            return -1; // buffer overflow
    
        int s32_CryptCount = mpi_SessionKey->CalcPaddedBlockSize(pi_Params->GetCount());
        if (!pi_Params->SetCount(s32_CryptCount))
            return -1; // buffer overflow
    
        if (mu8_DebugLevel > 0)
        {
            Utils::Print("* CRC Params:  0x");
            Utils::PrintHex32(u32_Crc, LF);
            Utils::Print("* Params:      ");
            Utils::PrintHexBuf(pi_Params->GetData(), s32_CryptCount, LF);
        }
    
        if (!mpi_SessionKey->CryptDataCBC(CBC_SEND, KEY_ENCIPHER, pi_Params->GetData(), pi_Params->GetData(), s32_CryptCount))
            return -1;
    
        if (mu8_DebugLevel > 0)
        {
            Utils::Print("* Params_enc:  ");
            Utils::PrintHexBuf(pi_Params->GetData(), s32_CryptCount, LF);
        }    
    }

    byte u8_Command = pi_Command->GetData()[0];

    byte u8_CalcMac[16];
    if ((e_Mac & MAC_Tmac) &&                       // Calculate the TX CMAC only if the caller requests it 
        (u8_Command != DF_INS_ADDITIONAL_FRAME) &&  // In case of DF_INS_ADDITIONAL_FRAME there are never parameters passed -> nothing to do here
        (mu8_LastAuthKeyNo != NOT_AUTHENTICATED))   // No session key -> no CMAC calculation possible
    { 
        mi_CmacBuffer.Clear();
        if (!mi_CmacBuffer.AppendBuf(pi_Command->GetData(), pi_Command->GetCount()) ||
            !mi_CmacBuffer.AppendBuf(pi_Params ->GetData(), pi_Params ->GetCount()))
            return -1;
      
        // The CMAC must be calculated here although it is not transmitted, because it maintains the IV up to date.
        // The initialization vector must always be correct otherwise the card will give an integrity error the next time the session key is used.
        if (!mpi_SessionKey->CalculateCmac(mi_CmacBuffer, u8_CalcMac))
            return -1;

        if (mu8_DebugLevel > 1)
        {
            Utils::Print("TX CMAC:  ");
            Utils::PrintHexBuf(u8_CalcMac, mpi_SessionKey->GetBlockSize(), LF);
        }
    }

    int P=0;
    mu8_PacketBuffer[P++] = PN532_COMMAND_INDATAEXCHANGE;
    mu8_PacketBuffer[P++] = 1; // Card number (Logical target number)

    memcpy(mu8_PacketBuffer + P, pi_Command->GetData(), pi_Command->GetCount());
    P += pi_Command->GetCount();

    memcpy(mu8_PacketBuffer + P, pi_Params->GetData(),  pi_Params->GetCount());
    P += pi_Params->GetCount();

    if (!SendCommandCheckAck(mu8_PacketBuffer, P))
        return -1;

    byte s32_Len = ReadData(mu8_PacketBuffer, s32_RecvSize + s32_Overhead);

    // ReadData() returns 3 byte if status error from the PN532
    // ReadData() returns 4 byte if status error from the Desfire card
    if (s32_Len < 3 || mu8_PacketBuffer[1] != PN532_COMMAND_INDATAEXCHANGE + 1)
    {
        Utils::Print("DataExchange() failed\r\n");
        return -1;
    }

    // Here we get two status bytes that must be checked
    byte u8_PN532Status = mu8_PacketBuffer[2]; // contains errors from the PN532
    byte u8_CardStatus  = mu8_PacketBuffer[3]; // contains errors from the Desfire card

    mu8_LastPN532Error = u8_PN532Status;

    if (!CheckPN532Status(u8_PN532Status) || s32_Len < 4)
        return -1;

    // After any error that the card has returned the authentication is invalidated.
    // The card does not send any CMAC anymore until authenticated anew.
    if (u8_CardStatus != ST_Success && u8_CardStatus != ST_MoreFrames)
    {
        mu8_LastAuthKeyNo = NOT_AUTHENTICATED; // A new authentication is required now
    }

    if (!CheckCardStatus((DESFireStatus)u8_CardStatus))
        return -1;

    if (pe_Status)
       *pe_Status = (DESFireStatus)u8_CardStatus;

    s32_Len -= 4; // 3 bytes for INDATAEXCHANGE response + 1 byte card status

    // A CMAC may be appended to the end of the frame.
    // The CMAC calculation is important because it maintains the IV of the session key up to date.
    // If the IV is out of sync with the IV in the card, the next encryption with the session key will result in an Integrity Error.
    if ((e_Mac & MAC_Rmac) &&                                              // Calculate RX CMAC only if the caller requests it
        (u8_CardStatus == ST_Success || u8_CardStatus == ST_MoreFrames) && // In case of an error there is no CMAC in the response
        (mu8_LastAuthKeyNo != NOT_AUTHENTICATED))                          // No session key -> no CMAC calculation possible
    {
        // For example GetCardVersion() calls DataExchange() 3 times:
        // 1. u8_Command = DF_INS_GET_VERSION      -> clear CMAC buffer + append received data
        // 2. u8_Command = DF_INS_ADDITIONAL_FRAME -> append received data
        // 3. u8_Command = DF_INS_ADDITIONAL_FRAME -> append received data
        if (u8_Command != DF_INS_ADDITIONAL_FRAME)
        {
            mi_CmacBuffer.Clear();
        }

        // This is an intermediate frame. More frames will follow. There is no CMAC in the response yet.
        if (u8_CardStatus == ST_MoreFrames)
        {
            if (!mi_CmacBuffer.AppendBuf(mu8_PacketBuffer + 4, s32_Len))
                return -1;
        }
        
        if ((s32_Len >= 8) &&             // If the response is shorter than 8 bytes it surely does not contain a CMAC
           (u8_CardStatus == ST_Success)) // Response contains CMAC only in case of success
        {
            s32_Len -= 8; // Do not return the received CMAC to the caller and do not include it into the CMAC calculation
          
            byte* u8_RxMac = mu8_PacketBuffer + 4 + s32_Len;
            
            // The CMAC is calculated over the RX data + the status byte appended to the END of the RX data!
            if (!mi_CmacBuffer.AppendBuf(mu8_PacketBuffer + 4, s32_Len) ||
                !mi_CmacBuffer.AppendUint8(u8_CardStatus))
                return -1;

            if (!mpi_SessionKey->CalculateCmac(mi_CmacBuffer, u8_CalcMac))
                return -1;

            if (mu8_DebugLevel > 1)
            {
                Utils::Print("RX CMAC:  ");
                Utils::PrintHexBuf(u8_CalcMac, mpi_SessionKey->GetBlockSize(), LF);
            }
      
            // For AES the CMAC is 16 byte, but only 8 are transmitted
            if (memcmp(u8_RxMac, u8_CalcMac, 8) != 0)
            {
                Utils::Print("CMAC Mismatch\r\n");
                return -1;
            }
        }
    }

    if (s32_Len > s32_RecvSize)
    {
        Utils::Print("DataExchange() Buffer overflow\r\n");
        return -1;
    } 

    if (u8_RecvBuf && s32_Len)
    {
        memcpy(u8_RecvBuf, mu8_PacketBuffer + 4, s32_Len);

        if (e_Mac & MAC_Rcrypt) // decrypt received data with session key
        {
            if (!mpi_SessionKey->CryptDataCBC(CBC_RECEIVE, KEY_DECIPHER, u8_RecvBuf, u8_RecvBuf, s32_Len))
                return -1;

            if (mu8_DebugLevel > 1)
            {
                Utils::Print("Decrypt:  ");
                Utils::PrintHexBuf(u8_RecvBuf, s32_Len, LF);
            }        
        }    
    }
    return s32_Len;
}

// Checks the status byte that is returned from the card
bool Desfire::CheckCardStatus(DESFireStatus e_Status)
{
    switch (e_Status)
    {
        case ST_Success:    // Success
        case ST_NoChanges:  // No changes made
        case ST_MoreFrames: // Another frame will follow
            return true;

        default: break; // This is just to avoid stupid gcc compiler warnings
    }

    Utils::Print("Desfire Error: ");
    switch (e_Status)
    {
        case ST_OutOfMemory:
            Utils::Print("Not enough EEPROM memory.\r\n");
            return false;
        case ST_IllegalCommand:
            Utils::Print("Illegal command.\r\n");
            return false;
        case ST_IntegrityError:
            Utils::Print("Integrity error.\r\n");
            return false;
        case ST_KeyDoesNotExist:
            Utils::Print("Key does not exist.\r\n");
            return false;
        case ST_WrongCommandLen:
            Utils::Print("Wrong command length.\r\n");
            return false;
        case ST_PermissionDenied:
            Utils::Print("Permission denied.\r\n");
            return false;
        case ST_IncorrectParam:
            Utils::Print("Incorrect parameter.\r\n");
            return false;
        case ST_AppNotFound:
            Utils::Print("Application not found.\r\n");
            return false;
        case ST_AppIntegrityError:
            Utils::Print("Application integrity error.\r\n");
            return false;
        case ST_AuthentError:
            Utils::Print("Authentication error.\r\n");
            return false;
        case ST_LimitExceeded:
            Utils::Print("Limit exceeded.\r\n");
            return false;
        case ST_CardIntegrityError:
            Utils::Print("Card integrity error.\r\n");
            return false;
        case ST_CommandAborted:
            Utils::Print("Command aborted.\r\n");
            return false;
        case ST_CardDisabled:
            Utils::Print("Card disabled.\r\n");
            return false;
        case ST_InvalidApp:
            Utils::Print("Invalid application.\r\n");
            return false;
        case ST_DuplicateAidFiles:
            Utils::Print("Duplicate AIDs or files.\r\n");
            return false;
        case ST_EepromError:
            Utils::Print("EEPROM error.\r\n");
            return false;
        case ST_FileNotFound:
            Utils::Print("File not found.\r\n");
            return false;
        case ST_FileIntegrityError:
            Utils::Print("File integrity error.\r\n");
            return false;
        default:
            Utils::Print("0x");
            Utils::PrintHex8((byte)e_Status, LF);
            return false;
    }
}

// ########################################################################
// ####                          SELFTEST                             #####
// ########################################################################

// To execute this function set COMPILE_SELFTEST to 'true' in DoorOpenerSketch.ino
// This function tests all the other functions in this class.
// You need an empty Desfire card with the factory default PICC master key.
// The PICC master key will not be changed, but everyting else will be erased.
// If any error occurres the test is aborted and the function returns false.
bool Desfire::Selftest()
{
    // Activate the RF field and start communication with the card
    byte u8_Length; // 4 or 7
    byte u8_UID[8];
    eCardType e_CardType;
    if (!ReadPassiveTargetID(u8_UID, &u8_Length, &e_CardType))
        return false;    

    if ((e_CardType & CARD_Desfire) == 0)
    {
        Utils::Print("The selftest requires a Desfire card.\r\n");
        return false;
    }

    // Switch to PICC level
    if (!SelectApplication(0x000000))
        return false;

    byte u8_Version;
    if (!Desfire::GetKeyVersion(0, &u8_Version))
        return false;

    if (u8_Version != 0)
    {
        Utils::Print("The selftest requires an empty Desfire card (factory default DES key)\r\n");
        return false;
    }

    // Authenticate with the factory default PICC master key (always DES)
    if (!Authenticate(0, &DES2_DEFAULT_KEY))
        return false;

    // Get the Desfire card version
    DESFireCardVersion k_Version;
    if (!GetCardVersion(&k_Version))
        return false;

    // Delete all applications and all their files
    if (!FormatCard())
        return false;

    // Print the free memory on the card
    uint32_t u32_FreeMem;
    if (!GetFreeMemory(&u32_FreeMem))
        return false;

    // ----------------------------------------------------------------------

    // Create an application with two 2K3DES keys
    uint32_t u32_App2KDES = 0x00DE16;
    if (!CreateApplication(u32_App2KDES, KS_FACTORY_DEFAULT, 2, DF_KEY_2K3DES))
        return false;

    // Create an application with two 3K3DES keys
    uint32_t u32_App3KDES = 0x00DE24;
    if (!CreateApplication(u32_App3KDES, KS_FACTORY_DEFAULT, 2, DF_KEY_3K3DES))
        return false;

    // Create an application with two AES keys
    uint32_t u32_AppAES = 0x00AE16;
    if (!CreateApplication(u32_AppAES,   KS_FACTORY_DEFAULT, 2, DF_KEY_AES))
        return false;

    // Create another application that will later be deleted
    uint32_t u32_AppDel = 0xAABBCC;
    if (!CreateApplication(u32_AppDel, KS_FACTORY_DEFAULT, 1, DF_KEY_2K3DES))
        return false;

    // Get a list of all applications
    uint32_t u32_IDlist[28];
    byte u8_AppCount;
    if (!GetApplicationIDs(u32_IDlist, &u8_AppCount))
        return false;

    if (u8_AppCount != 4 || u32_IDlist[0] != u32_App2KDES || u32_IDlist[1] != u32_App3KDES || u32_IDlist[2] != u32_AppAES || u32_IDlist[3] != u32_AppDel)
    {
        Utils::Print("GetApplicationIDs() failed\r\n");
        return false;
    }

    // Delete the last application
    if (!DeleteApplication(u32_AppDel))
        return false;

    // Get the list of all applications again
    if (!GetApplicationIDs(u32_IDlist, &u8_AppCount))
        return false;

    if (u8_AppCount != 3)
    {
        Utils::Print("DeleteApplication() failed\r\n");
        return false;
    }

    // ----------------------------------------------------------------------

    // Select the 2K3DES application
    if (!SelectApplication(u32_App2KDES))
        return false;

    // Authenticate access to the new application with the default key
    if (!Authenticate(0, &DES2_DEFAULT_KEY))
        return false;  

    // Get the key settings, key count and key type of the application
    DESFireKeySettings e_Settg;
    DESFireKeyType     e_KeyType;
    byte u8_KeyCount;
    if (!GetKeySettings(&e_Settg, &u8_KeyCount, &e_KeyType))
        return false;

    if (e_Settg != KS_FACTORY_DEFAULT || u8_KeyCount != 2 || e_KeyType != DF_KEY_2K3DES)
    {
        Utils::Print("GetKeySettings() failed\r\n");
        return false;
    }

    // ----------------------------------------------------------------------

    const byte u8_KeyA[24] = { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 };
    const byte u8_KeyB[24] = { 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8 };
    
    DES i_Des2KeyA, i_Des2KeyB;
    DES i_Des3KeyA, i_Des3KeyB;
    AES i_AesKeyA,  i_AesKeyB;
    
    if (!i_Des2KeyA.SetKeyData(u8_KeyA, 16, CARD_KEY_VERSION) ||
        !i_Des2KeyB.SetKeyData(u8_KeyB, 16, CARD_KEY_VERSION) ||
        !i_Des3KeyA.SetKeyData(u8_KeyA, 24, CARD_KEY_VERSION) ||
        !i_Des3KeyB.SetKeyData(u8_KeyB, 24, CARD_KEY_VERSION) ||
        !i_AesKeyA .SetKeyData(u8_KeyA, 16, CARD_KEY_VERSION) ||
        !i_AesKeyB .SetKeyData(u8_KeyB, 16, CARD_KEY_VERSION))
        return false;

    if (!SelftestKeyChange(u32_App2KDES, &DES2_DEFAULT_KEY, &i_Des2KeyA, &i_Des2KeyB) ||
        !SelftestKeyChange(u32_App3KDES, &DES3_DEFAULT_KEY, &i_Des3KeyA, &i_Des3KeyB) ||
        !SelftestKeyChange(u32_AppAES,    &AES_DEFAULT_KEY, &i_AesKeyA,  &i_AesKeyB))
        return false;

    Utils::Print("--------------------------------------------------------------\r\n");

    const int FILE_LENGTH = 80; // this exceeds the frame size -> requires two frames for write / read    

    // Create Standard Data File no 5 with 80 bytes length
    DESFireFilePermissions k_Permis;
    k_Permis.e_ReadAccess         = AR_KEY0; // u8_MasterKeyB 
    k_Permis.e_WriteAccess        = AR_KEY0; // u8_MasterKeyB
    k_Permis.e_ReadAndWriteAccess = AR_KEY1; // u8_SecondKeyB
    k_Permis.e_ChangeAccess       = AR_KEY1; // u8_SecondKeyB
    if (!CreateStdDataFile(5, &k_Permis, FILE_LENGTH))
        return false;

    // Get a list of all files in the application
    byte u8_FileIDs[32];
    byte u8_FileCount;
    if (!GetFileIDs(u8_FileIDs, &u8_FileCount))
        return false;

    if (u8_FileCount != 1 || u8_FileIDs[0] != 5)
    {
        Utils::Print("GetFileIDs() failed\r\n");
        return false;
    }

    // Get the file settings
    DESFireFileSettings k_Settings;
    if (!GetFileSettings(5, &k_Settings))
        return false;

    if (k_Settings.e_FileType      != MDFT_STANDARD_DATA_FILE ||
        k_Settings.e_Encrypt       != CM_PLAIN ||
        k_Settings.k_Permis.Pack() != k_Permis.Pack() ||
        k_Settings.u32_FileSize    != FILE_LENGTH)
    {
        Utils::Print("GetFileSettings() failed\r\n");
        return false;
    }

    // ----------------

    // Write 80 bytes to the file    
    byte u8_TxData[FILE_LENGTH];
    for (int i=0; i<FILE_LENGTH; i++)
    {
        u8_TxData[i] = i;
    }
    
    if (!WriteFileData(5, 0, FILE_LENGTH, u8_TxData))
        return false;
    
    // Read 80 bytes from the file
    byte u8_RxData[FILE_LENGTH];
    if (!ReadFileData(5, 0, FILE_LENGTH, u8_RxData))
        return false;

    if (memcmp(u8_TxData, u8_RxData, FILE_LENGTH) != 0)
    {
        Utils::Print("Read/Write file failed\r\n");
        return false;
    }

    // ----------------

    if (!DeleteFile(5))
        return false;

    if (!GetFileIDs(u8_FileIDs, &u8_FileCount))
        return false;

    if (u8_FileCount != 0)
    {
        Utils::Print("DeleteFile() failed\r\n");
        return false;
    }

    // ----------------    

    // Switch to PICC level
    if (!SelectApplication(0x000000))
        return false;

    // Authenticate with the factory default PICC master key
    if (!Authenticate(0, &DES2_DEFAULT_KEY))
        return false;

    // Leave a clean card
    if (!FormatCard())
        return false;
    
    return true;
}

// Changing the application key #0 is a completely different procedure from changing the key #1
// So both must be tested thoroughly. 
// If there should be any bug in ChangeKey() the consequence may be a card that you cannot authenticate anymore!
bool Desfire::SelftestKeyChange(uint32_t u32_Application, DESFireKey* pi_DefaultKey, DESFireKey* pi_NewKeyA, DESFireKey* pi_NewKeyB)
{ 
    Utils::Print("--------------------------------------------------------------\r\n");
  
    // Never change the PICC master key in the Selftest!
    if (u32_Application == 0x000000)
        return false;
  
    if (!SelectApplication(u32_Application))
        return false;

    // Authenticate access to the new application with the default key
    if (!Authenticate(0, pi_DefaultKey))
        return false;  

    // As this command uses encryption it must be tested with all key types.
    byte u8_UID[7];
    if (!GetRealCardID(u8_UID))
        return false;

    // ---------- key #0 -> A ----------

    // Change the application key #0
    if (!ChangeKey(0, pi_NewKeyA, NULL))
        return false;

    // Authenticate with the new application master key
    if (!Authenticate(0, pi_NewKeyA))
        return false;

    // ---------- Key Settings ----------

    DESFireKeySettings e_Settg;
    DESFireKeyType     e_KeyType;
    byte u8_KeyCount;

    // As this command uses encryption it must be tested with all key types.
    // Change key settings from 0x0F (KS_FACTORY_DEFAULT) -> 0x0D
    if (!ChangeKeySettings((DESFireKeySettings)0x0D))
        return false;

    if (!GetKeySettings(&e_Settg, &u8_KeyCount, &e_KeyType))
        return false;

    if (e_Settg != 0x0D || u8_KeyCount != 2 || e_KeyType != pi_NewKeyA->GetKeyType())
    {
        Utils::Print("ChangeKeySettings() failed\r\n");
        return false;
    }                

    // Change key settings back to 0x0F (KS_FACTORY_DEFAULT)
    if (!ChangeKeySettings(KS_FACTORY_DEFAULT))
        return false;

    // ---------- key #0 -> B ----------

    // Change the application key #0 again
    if (!ChangeKey(0, pi_NewKeyB, NULL))
        return false;

    // Authenticate with the new application master key
    if (!Authenticate(0, pi_NewKeyB))
        return false;

    // ---------- key version ----------

    byte u8_KeyVersion;
    if (!Desfire::GetKeyVersion(0, &u8_KeyVersion))
        return false;

    if (u8_KeyVersion != CARD_KEY_VERSION)
    {
        Utils::Print("GetKeyVersion() failed\r\n");
        return false;
    }

    // ---------- key #0 -> 0 ----------

    // Restore key #0 back to the default key
    if (!ChangeKey(0, pi_DefaultKey, NULL))
        return false;

    if (!Authenticate(0, pi_DefaultKey))
        return false;  

    // ---------- key #1 ----------

    // Change the application key #1
    if (!ChangeKey(1, pi_NewKeyA, pi_DefaultKey))
        return false;

    // Change the application key #1 again
    if (!ChangeKey(1, pi_NewKeyB, pi_NewKeyA))
        return false;

    if (!Authenticate(1, pi_NewKeyB))
        return false;

    return true;
}

