
#ifndef CLASSIC_H
#define CLASSIC_H

#include "PN532.h"

// ---------------------------------------------------------------

// Mifare Commands
#define MIFARE_CMD_AUTH_A                   (0x60)
#define MIFARE_CMD_AUTH_B                   (0x61)
#define MIFARE_CMD_READ                     (0x30)
#define MIFARE_CMD_WRITE                    (0xA0)
#define MIFARE_CMD_TRANSFER                 (0xB0)
#define MIFARE_CMD_DECREMENT                (0xC0)
#define MIFARE_CMD_INCREMENT                (0xC1)
#define MIFARE_CMD_STORE                    (0xC2)
#define MIFARE_ULTRALIGHT_CMD_WRITE         (0xA2)

// ---------------------------------------------------------------

class Classic : public PN532
{
  public:
    bool DumpCardMemory(char s8_KeyType, const byte* u8_Keys, bool b_ShowAccessBits);
    bool AuthenticateDataBlock(byte u8_Block, char s8_KeyType, const byte* u8_KeyData, const byte* u8_Uid, byte u8_UidLen);
    bool ReadDataBlock (byte u8_Block, byte* u8_Data);
    bool WriteDataBlock(byte u8_Block, byte* u8_Data);
    bool GetValue(byte* u8_Data, uint32_t* pu32_Value, byte* pu8_Address);
    void SetValue(byte* u8_Data, uint32_t   u32_Value, byte   u8_Address);
   
 private:
    bool DataExchange(byte u8_Command, byte u8_Block, byte* u8_Data, byte u8_DataLen);
    void ShowAccessBits(byte u8_Block, byte u8_Byte7, byte u8_Byte8);    
};

#endif
