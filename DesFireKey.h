/**************************************************************************
    
    @author   Elmü
    This class is the base class for the classes AES and DES.
    It manages all the key stuff that both have in common.

    Check for a new version on:
    http://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup
	
**************************************************************************/

#ifndef DESFIRE_KEY_H
#define DESFIRE_KEY_H

#include "Buffer.h"

enum DESFireCipher
{
    KEY_ENCIPHER = 0,
    KEY_DECIPHER = 1
};

// Cipher Block Chaining mode
enum DESFireCBC
{
    CBC_SEND,
    CBC_RECEIVE
};

// These values must be OR-ed with the key number when executing command DF_INS_CHANGE_KEY
enum DESFireKeyType
{
    DF_KEY_2K3DES  = 0x00, // for DFEV1_INS_AUTHENTICATE_ISO + DF_INS_AUTHENTICATE_LEGACY
    DF_KEY_3K3DES  = 0x40, // for DFEV1_INS_AUTHENTICATE_ISO
    DF_KEY_AES     = 0x80, // for DFEV1_INS_AUTHENTICATE_AES
    DF_KEY_INVALID = 0xFF    
};

// This is the base class for DES and AES
class DESFireKey
{
public:
    DESFireKey() 
    {
        ms32_KeySize   = 0;
        ms32_BlockSize = 0;
        mu8_Version    = 0;
        me_KeyType     = DF_KEY_INVALID;
    }
    virtual ~DESFireKey() 
    {
    }

    // These abstract functions must be overridden in the derived DES and AES classes
    virtual bool SetKeyData(const byte* u8_Key, int s32_KeySize, byte u8_Version) = 0;
    virtual bool CryptDataBlock(byte* u8_Out, const byte* u8_In, DESFireCipher e_Cipher) = 0;
    
    // The CBC alorithm XOR's the data with the previous result (Cipher Block Chaining)
    // https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
    // However NXP (Philips) uses a modified scheme.
    // If XOR is executed before or after encryption depends on the data being sent or received.
    // s32_ByteCount = Count of bytes to crypt (must always be a multiple of 8 (DES) or 16 (AES))
    bool CryptDataCBC(DESFireCBC e_CBC, DESFireCipher e_Cipher, byte* u8_Out, const byte* u8_In, int s32_ByteCount)
    {
        if (s32_ByteCount < ms32_BlockSize ||
            s32_ByteCount % ms32_BlockSize)
        {
            Utils::Print("Invalid CBC block size\r\n");  
            return false;
        }
      
        byte u8_Temp[16];
        for (int B=0; B<s32_ByteCount/ms32_BlockSize; B++)
        {
            if (e_CBC == CBC_SEND)
            {
                Utils::XorDataBlock(u8_Temp, u8_In, mu8_IV, ms32_BlockSize);
                if (!CryptDataBlock(u8_Out, u8_Temp, e_Cipher)) return false;
                memcpy(mu8_IV, u8_Out, ms32_BlockSize);
            }
            else // CBC_RECEIVE
            {
                if (!CryptDataBlock(u8_Temp, u8_In, e_Cipher)) return false;
                Utils::XorDataBlock(u8_Temp, u8_Temp, mu8_IV, ms32_BlockSize); // Step 1 (mu8_IV is used here)
                memcpy(mu8_IV, u8_In,   ms32_BlockSize);                       // Step 2 (mu8_IV can be changed now, u8_In has not yet been modified)
                memcpy(u8_Out, u8_Temp, ms32_BlockSize);                       // Step 3 (here also u8_In is modified if u8_Out and u8_In are the same buffer)
            }
            u8_In  += ms32_BlockSize;
            u8_Out += ms32_BlockSize;
        }
        return true;
    }

    // Generates the two subkeys mu8_Cmac1 and mu8_Cmac2 that are used for CMAC calulation with the session key
    bool GenerateCmacSubkeys()
    {
        uint8_t u8_R = (ms32_BlockSize == 8) ? 0x1B : 0x87;
        uint8_t u8_Data[16] = {0};     
        
        ClearIV();
        if (!CryptDataCBC(CBC_RECEIVE, KEY_ENCIPHER, u8_Data, u8_Data, ms32_BlockSize))
            return false;

        memcpy (mu8_Cmac1, u8_Data, ms32_BlockSize);
        Utils::BitShiftLeft(mu8_Cmac1, ms32_BlockSize);
        if (u8_Data[0] & 0x80)
            mu8_Cmac1[ms32_BlockSize-1] ^= u8_R;
        
        memcpy (mu8_Cmac2, mu8_Cmac1, ms32_BlockSize);
        Utils::BitShiftLeft(mu8_Cmac2, ms32_BlockSize);
        if (mu8_Cmac1[0] & 0x80)
            mu8_Cmac2[ms32_BlockSize-1] ^= u8_R;

        return true;
    }

    // Calculate the CMAC (Cipher-based Message Authentication Code) from the given data.
    // The CMAC is the initialization vector (IV) after a CBC encryption of the given data.
    // ATTENTION: The content of i_Buffer will be modified!!
    bool CalculateCmac(TxBuffer& i_Buffer, byte u8_Cmac[16])
    {
        // If the data length is not a multiple of the block size -> pad the buffer with 80,00,00,00,....
        if ((i_Buffer.GetCount() == 0) || (i_Buffer.GetCount() % ms32_BlockSize))
        {
            if (!i_Buffer.AppendUint8(0x80))
                return false; // Buffer is full
                
            while (i_Buffer.GetCount() % ms32_BlockSize)
            {
                if (!i_Buffer.AppendUint8(0x00))
                    return false; // Buffer is full
            }
            Utils::XorDataBlock(i_Buffer + i_Buffer.GetCount() - ms32_BlockSize, mu8_Cmac2, ms32_BlockSize);
        } 
        else // no padding required
        {
            Utils::XorDataBlock(i_Buffer + i_Buffer.GetCount() - ms32_BlockSize, mu8_Cmac1, ms32_BlockSize);
        }

        if (!CryptDataCBC(CBC_SEND, KEY_ENCIPHER, i_Buffer, i_Buffer, i_Buffer.GetCount()))
            return false;
            
        memcpy(u8_Cmac, mu8_IV, ms32_BlockSize);
        return true;
    }
    
    inline byte* Data()
    {
        return mu8_Key;
    }

    // s32_MinSize = 16 -> returns 16 for simple DES keys (instead of 8)!
    // This is required because ChangeKey() operates only on 16 or 24  bytes.
    // In case of a simple DES key (8 byte long) the upper 8 byte and the lower 8 byte are identical. (See DES::SetKeyData())
    // The Desfire card detects automatically that this 16 byte key is really a simple 8 byte DES key.
    inline int GetKeySize(int s32_MinSize=0) 
    { 
        return max(s32_MinSize, ms32_KeySize); 
    }   

    inline DESFireKeyType GetKeyType()
    {
        return me_KeyType;
    }

    // The size of the data blocks that are encrypted by CryptDataBlock()
    inline int GetBlockSize() 
    { 
        return ms32_BlockSize; 
    }   

    // Desfire stores a key version on the card. This is irrelevant for encryption.
    inline byte GetKeyVersion() 
    { 
        return mu8_Version; 
    }

    // fill the IV with zeroes
    inline void ClearIV() 
    {
        memset(mu8_IV, 0, ms32_BlockSize);
    }

    // just for debugging
    inline void PrintIV(const char* s8_LF=NULL)
    {
        Utils::PrintHexBuf(mu8_IV, ms32_BlockSize, s8_LF);
    }

    static bool CheckValid(DESFireKey* pi_Key)
    {
        if (pi_Key == NULL || pi_Key->GetKeyType() == DF_KEY_INVALID)
        {
            Utils::Print("Invalid key\r\n");
            return false;
        }
        return true;
    }

    // Determines the block size required to encrypt the data with the length s32_ByteCount using this key
    int CalcPaddedBlockSize(int s32_ByteCount)
    {
        while (s32_ByteCount % ms32_BlockSize)
        {
            s32_ByteCount++;
        }
        return s32_ByteCount;
    }

    // Just for debugging
    void PrintKey(const char* s8_LF=NULL)
    {
        // Even if an 8 byte simple DES key is used, the function ChangeKey() works internally always with 16 bytes.
        // For a simple DES key 16 byte will be printed where the first half is idententical to the second half.
        Utils::PrintHexBuf(mu8_Key, GetKeySize(16));

        Utils::Print(" (");
        Utils::Print(GetKeyTypeAsString(me_KeyType, ms32_KeySize));
        Utils::Print(")", s8_LF);
    }

    static const char* GetKeyTypeAsString(DESFireKeyType e_KeyType, int s32_KeySize=0)
    {
        switch (e_KeyType)
        {
            case DF_KEY_2K3DES: 
                switch (s32_KeySize)
                {
                    case  8: return "DES";    // simple (8  bytes)
                    case 16: return "2K3DES"; // double (16 bytes) 
                    default: return "3DES";   // size unknown
                }
            case DF_KEY_3K3DES: return "3K3DES"; // triple (24 bytes)
            case DF_KEY_AES:    return "AES";
            default:            return "INVALID";
        }
    }

protected:
    byte mu8_IV[16];  // Initialization Vector for CBC
    byte mu8_Key[24];
    int  ms32_KeySize;
    int  ms32_BlockSize;
    byte mu8_Version;
    DESFireKeyType me_KeyType;

    byte mu8_Cmac1[16]; // CMAC subkey 1
    byte mu8_Cmac2[16]; // CMAC subkey 2
};

#endif // DESFIRE_KEY_H
