/**************************************************************************
    
    @author   Elmü   
    This class has only been tested with Mifare Classic 1K cards.

    ATTENTION: Mifare Classic cards have been hacked. 
    They are not safe because they can be cloned very easily.
    Use Desfire EV1 cards instead!

    Check for a new version on http://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup
	
**************************************************************************/

#include "Classic.h"
#include "Buffer.h"

/**************************************************************************
    Prints 1 kB of the card's EEPROM memory to the Serial output.

    s8_KeyType = 'A' -> u8_Keys are key A, 'B' -> u8_Keys are key B
    u8_Keys    = one 6 byte authorization key for each sector
    For example:
    byte u8_Keys[] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,   // key for Sector 0 (Block 0..3)
                       0x00,0x00,0x00,0x00,0x00,0x00,   // key for Sector 1 (Block 4..7)
                       etc..                  
                       0xA1,0xA2,0xA3,0xA4,0xA5,0xA6 }; // key for Sector 15
**************************************************************************/
bool Classic::DumpCardMemory(char s8_KeyType, const byte* u8_Keys, bool b_ShowAccessBits)
{
    byte u8_UidLen; // 4 or 7
    byte u8_Uid[8];
    eCardType e_CardType;
    if (!ReadPassiveTargetID(u8_Uid, &u8_UidLen, &e_CardType))
        return false;

    if (u8_UidLen == 0)
    {
        Utils::Print("No card present.\r\n");
        return false;
    }

    char s8_Buf[50];
    byte u8_Data[20];
    for (int B=0; B<64; B++)
    {
        if  ((B % 4) == 0) // first block of sector
        {
            sprintf(s8_Buf, "*** Sector %02d:\r\n", B/4);
            Utils::Print(s8_Buf);
      
            // Authorizing the first block of a sector is enough (1 sector = 4 blocks)
            bool b_OK = AuthenticateDataBlock(B, s8_KeyType, u8_Keys, u8_Uid, u8_UidLen);
            u8_Keys += 6;
            
            if (!b_OK)
            {
                DeselectCard();
                B += 3; // Skip the next 3 blocks of the same sector because they will also fail.
                continue;
            }
        }

        sprintf((char*)u8_Data, "Block %02d: ", B);
        Utils::Print((char*)u8_Data);
        
        if (ReadDataBlock(B, u8_Data))
        {
            Utils::PrintHexBuf(u8_Data, 16);

            uint32_t u32_Value;
            byte     u8_Address;
            if (GetValue(u8_Data, &u32_Value, &u8_Address))
            {
                sprintf(s8_Buf, " Value[0x%02X]= %u", u8_Address, (unsigned int)u32_Value);
                Utils::Print(s8_Buf);
            }

            Utils::Print(LF);

            if (b_ShowAccessBits && (B & 3) == 3)
                ShowAccessBits(B & 0xFC, u8_Data[7], u8_Data[8]);
        }
    }
    return true;
}

/**************************************************************************
    Dispay which Key has read/write access to data, the keys and the access bits.
    For more details see "Mifare KeyA, KeyB, Sector AccessBits.pdf"
**************************************************************************/
void Classic::ShowAccessBits(byte u8_Block, byte u8_Byte7, byte u8_Byte8)
{
    byte C1 = u8_Byte7 >> 4;
    byte C2 = u8_Byte8 & 0xF;
    byte C3 = u8_Byte8 >> 4;
    
    byte u8_Access[4];
    for (int i=0; i<4; i++)
    {
        u8_Access[i] = ((C1 & 1) << 2) | ((C2 & 1) << 1) | (C3 & 1);
        C1 >>= 1;
        C2 >>= 1;
        C3 >>= 1;
    }

    char s8_Buf[80];
    for (int B=0; B<3; B++)
    {
        switch (u8_Access[B])
        {
            case 0: sprintf(s8_Buf, "Access block %02d: read data: key A|B, write data: key A|B\r\n", u8_Block); break;
            case 1: 
            case 2: sprintf(s8_Buf, "Access block %02d: read data: key A|B, write data: never\r\n",   u8_Block); break;
            case 3: sprintf(s8_Buf, "Access block %02d: read data: key B,   write data: key B\r\n",   u8_Block); break;
            case 4: 
            case 6: sprintf(s8_Buf, "Access block %02d: read data: key A|B, write data: key B\r\n",   u8_Block); break;
            case 5: sprintf(s8_Buf, "Access block %02d: read data: key B,   write data: never\r\n",   u8_Block); break;
            case 7: sprintf(s8_Buf, "Access block %02d: read data: never,   write data: never\r\n",   u8_Block); break;
        }
        Utils::Print(s8_Buf);
        u8_Block ++;
    }

    switch (u8_Access[3]) // Trailer
    {
        case 0: Utils::Print("Access KEYA: read: never,   write: key A\r\nAccess BITS: read: key A,   write: never\r\nAccess KEYB: read: key A,   write: key A\r\n"); break;
        case 1: Utils::Print("Access KEYA: read: never,   write: key A\r\nAccess BITS: read: key A,   write: key A\r\nAccess KEYB: read: key A,   write: key A\r\n"); break;
        case 2: Utils::Print("Access KEYA: read: never,   write: never\r\nAccess BITS: read: key A,   write: never\r\nAccess KEYB: read: key A,   write: never\r\n"); break;
        case 3: Utils::Print("Access KEYA: read: never,   write: key B\r\nAccess BITS: read: key A|B, write: key B\r\nAccess KEYB: read: never,   write: key B\r\n"); break;
        case 4: Utils::Print("Access KEYA: read: never,   write: key B\r\nAccess BITS: read: key A|B, write: never\r\nAccess KEYB: read: never,   write: key B\r\n"); break;
        case 5: Utils::Print("Access KEYA: read: never,   write: never\r\nAccess BITS: read: key A|B, write: key B\r\nAccess KEYB: read: never,   write: never\r\n"); break;
        case 6: 
        case 7: Utils::Print("Access KEYA: read: never,   write: never\r\nAccess BITS: read: key A|B, write: never\r\nAccess KEYB: read: never,   write: never\r\n"); break;
    }
}

/**************************************************************************
    This function interprets a block of 16 byte in u8_Data as a 32 bit Value.
    For more details see "Mifare KeyA, KeyB, Sector AccessBits.pdf"
    If the data block does not contain a valid value -> return false
    pu32_Value  returns the value that has been read   (may be NULL)
    pu32_Adress returns the address that has been read (may be NULL)
**************************************************************************/
bool Classic::GetValue(byte* u8_Data, uint32_t* pu32_Value, byte* pu8_Address)
{
    byte u8_Addr = u8_Data[12];
    if (u8_Addr != 0xFF - u8_Data[13] ||
        u8_Addr != u8_Data[14]        ||
        u8_Addr != 0xFF - u8_Data[15])
        return false;

    uint32_t u32_Value = 0;
    for (int i=3; i>=0; i--)
    {
        if (u8_Data[i+0] != u8_Data[i+8] ||
            u8_Data[i+0] != 0xFF - u8_Data[i+4])
            return false;

        u32_Value <<= 8;
        u32_Value += u8_Data[i];           
    }

    if (pu32_Value)  *pu32_Value  = u32_Value;
    if (pu8_Address) *pu8_Address = u8_Addr;
    return true;
}

/**************************************************************************
    This function writes a 32 bit Value into a 16 byte data block in u8_Data
    For more details see "Mifare KeyA, KeyB, Sector AccessBits.pdf"
**************************************************************************/
void Classic::SetValue(byte* u8_Data, uint32_t u32_Value, byte u8_Address)
{
    for (int i=0; i<4; i++)
    {
        byte u8_Value = (byte)u32_Value;
        u8_Data[i+0] = u8_Value;
        u8_Data[i+4] = 0xFF - u8_Value;
        u8_Data[i+8] = u8_Value;
        u32_Value >>= 8;
    }
  
    u8_Data[12] = u8_Data[14] = u8_Address;
    u8_Data[13] = u8_Data[15] = 0xFF - u8_Address;
}

// -------------------------------------------------------------------------------------------------------------------------

/**************************************************************************
    Tries to authenticate a memory block on a MIFARE card using a 6 byte key.
    
    Each sector (64 byte) is secured by 2 different keys: Key A and B
    of which each key may have different permissions (read / write).
    For example: key A has read permission and key B has read + write permission
    See "DataSheets\Mifare KeyA, KeyB, Sector AccessBits.pdf"
    
    Default keys on an empty card may be:
    FF FF FF FF FF FF
    00 00 00 00 00 00
    D3 F7 D3 F7 D3 F7
    A0 A1 A2 A3 A4 A5
    B0 B1 B2 B3 B4 B5
    4D 3A 99 C3 51 DD
    1A 98 2C 7E 45 9A
    AA BB CC DD EE FF
    AB CD EF 12 34 56
    71 4C 5C 88 6E 97
    58 7E E5 F9 35 0F
    A0 47 8C C3 90 91
    53 3C B6 C7 23 F6
    8F D0 A4 F2 56 E9

    IMPORTANT: In case of an authentication error you must call DeselectCard()
               before authenticating another sector.
              
    u8_Block   = 0..63 for 1KB cards, and 0..255 for 4KB cards
    s8_KeyType = 'A' -> u8_KeyData is key A, 'B' -> u8_KeyData is key B
    u8_KeyData = the 6 byte authorization key (KeyA or KeyB)
    u8_Uid     = a buffer with the UID of the card
    u8_UidLen  = length of UID (4 or 7 bytes)
**************************************************************************/
bool Classic::AuthenticateDataBlock(byte u8_Block, char s8_KeyType, const byte* u8_KeyData, const byte* u8_Uid, byte u8_UidLen) 
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** AuthenticateDataBlock()\r\n");
    
    byte u8_Command;
    switch (s8_KeyType)
    { 
        case 'A': u8_Command = MIFARE_CMD_AUTH_A; break;
        case 'B': u8_Command = MIFARE_CMD_AUTH_B; break;
        default: return false;
    }

    TX_BUFFER(i_Params, 16)
    i_Params.AppendBuf(u8_KeyData, 6);
    i_Params.AppendBuf(u8_Uid, u8_UidLen);
    return DataExchange(u8_Command, u8_Block, i_Params, i_Params.GetCount());
}

/**************************************************************************
    Reads a 16 byte data block at the specified block address on a MIFARE card.

    u8_Block  = 0..63 for 1KB cards, and 0..255 for 4KB cards
    u8_Data   = a buffer that receives the 16 bytes that have been read
**************************************************************************/
bool Classic::ReadDataBlock(byte u8_Block, byte* u8_Data)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** ReadDataBlock()\r\n");
    
    return DataExchange(MIFARE_CMD_READ, u8_Block, u8_Data, 0);
}

/**************************************************************************
    Write a 16 byte data block at the specified block address on a MIFARE card.

    u8_Block  = 0..63 for 1KB cards, and 0..255 for 4KB cards
    u8_Data   = a buffer with 16 bytes to be written
**************************************************************************/
bool Classic::WriteDataBlock(byte u8_Block, byte* u8_Data)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** WriteDataBlock()\r\n");
    
    return DataExchange(MIFARE_CMD_WRITE, u8_Block, u8_Data, 16);
}

/**************************************************************************
    This is a private function. Do not call directly!
    Authenticates, reads or writes a data block of 16 bytes.
    u8_Command = MIFARE_CMD_AUTH_A, MIFARE_CMD_AUTH_B, MIFARE_CMD_READ, MIFARE_CMD_WRITE
    u8_Block   = 0..63 for 1KB cards, and 0..255 for 4KB cards
    u8_Data    = 16 byte data buffer (output for read operation, input otherwise)
    u8_DataLen = length of u8_Data (set == 0 for command MIFARE_CMD_READ)
**************************************************************************/
bool Classic::DataExchange(byte u8_Command, byte u8_Block, byte* u8_Data, byte u8_DataLen)
{
    mu8_PacketBuffer[0] = PN532_COMMAND_INDATAEXCHANGE;
    mu8_PacketBuffer[1] = 1; // Card number (Logical target number)
    mu8_PacketBuffer[2] = u8_Command;
    mu8_PacketBuffer[3] = u8_Block;

    memcpy(mu8_PacketBuffer + 4, u8_Data, u8_DataLen);
    
    if (!SendCommandCheckAck(mu8_PacketBuffer, 4 + u8_DataLen))
        return false;
  
    byte len = ReadData(mu8_PacketBuffer, 26);
    if (len < 3 || mu8_PacketBuffer[1] != PN532_COMMAND_INDATAEXCHANGE + 1)
    {
        Utils::Print("DataExchange failed\r\n");
        return false;
    }

    // Check the status byte from the PN532 (returns 3 bytes in case of error)
    if (!CheckPN532Status(mu8_PacketBuffer[2]))
        return false;

    if (u8_Command == MIFARE_CMD_READ)
    {
        if (len < 19)
        {
            Utils::Print("DataExchange returned invalid data\r\n");
            return false;
        }
        memcpy(u8_Data, mu8_PacketBuffer + 3, 16);
    }   
    return true;
}



