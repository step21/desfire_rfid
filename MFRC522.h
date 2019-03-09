
#ifndef MFRC522_H
#define MFRC522_H

#include "Utils.h"

// ----------------------------------------------------------------------

// This parameter may be used to slow down the software SPI bus speed.
// This is required when there is a long cable between the MFRC522 and the Teensy.
// This delay in microseconds (not milliseconds!) is made between toggeling the CLK line.
// Use an oscilloscope to check the resulting speed!
// A value of 50 microseconds results in a clock signal of 10 kHz
// A value of 0 results in maximum speed (depends on CPU speed).
// This parameter is not used for hardware SPI mode.
#define MFRC522_SOFT_SPI_DELAY  50

// The clock (in Hertz) when using Hardware SPI mode
// This parameter is not used for software SPI mode.
#define MFRC522_HARD_SPI_CLOCK  1000000

// The maximum time to wait for an answer from the MFRC522
// Do NOT use infinite timeouts like in Adafruit code!
#define MFRC522_TIMEOUT  1000

// The packet buffer is used for sending commands and for receiving responses from the MFRC522
#define MFRC522_PACKBUFFSIZE   80

// ----------------------------------------------------------------------

#define MFRC522_PREAMBLE                      (0x00)
#define MFRC522_STARTCODE1                    (0x00)
#define MFRC522_STARTCODE2                    (0xFF)
#define MFRC522_POSTAMBLE                     (0x00)

#define MFRC522_HOSTTOMFRC522                   (0xD4)
#define MFRC522_MFRC522TOHOST                   (0xD5)

// MFRC522 Commands
#define MFRC522_COMMAND_DIAGNOSE              (0x00)
#define MFRC522_COMMAND_GETFIRMWAREVERSION    (0x02)
#define MFRC522_COMMAND_GETGENERALSTATUS      (0x04)
#define MFRC522_COMMAND_READREGISTER          (0x06)
#define MFRC522_COMMAND_WRITEREGISTER         (0x08)
#define MFRC522_COMMAND_READGPIO              (0x0C)
#define MFRC522_COMMAND_WRITEGPIO             (0x0E)
#define MFRC522_COMMAND_SETSERIALBAUDRATE     (0x10)
#define MFRC522_COMMAND_SETPARAMETERS         (0x12)
#define MFRC522_COMMAND_SAMCONFIGURATION      (0x14)
#define MFRC522_COMMAND_POWERDOWN             (0x16)
#define MFRC522_COMMAND_RFCONFIGURATION       (0x32)
#define MFRC522_COMMAND_RFREGULATIONTEST      (0x58)
#define MFRC522_COMMAND_INJUMPFORDEP          (0x56)
#define MFRC522_COMMAND_INJUMPFORPSL          (0x46)
#define MFRC522_COMMAND_INLISTPASSIVETARGET   (0x4A)
#define MFRC522_COMMAND_INATR                 (0x50)
#define MFRC522_COMMAND_INPSL                 (0x4E)
#define MFRC522_COMMAND_INDATAEXCHANGE        (0x40)
#define MFRC522_COMMAND_INCOMMUNICATETHRU     (0x42)
#define MFRC522_COMMAND_INDESELECT            (0x44)
#define MFRC522_COMMAND_INRELEASE             (0x52)
#define MFRC522_COMMAND_INSELECT              (0x54)
#define MFRC522_COMMAND_INAUTOPOLL            (0x60)
#define MFRC522_COMMAND_TGINITASTARGET        (0x8C)
#define MFRC522_COMMAND_TGSETGENERALBYTES     (0x92)
#define MFRC522_COMMAND_TGGETDATA             (0x86)
#define MFRC522_COMMAND_TGSETDATA             (0x8E)
#define MFRC522_COMMAND_TGSETMETADATA         (0x94)
#define MFRC522_COMMAND_TGGETINITIATORCOMMAND (0x88)
#define MFRC522_COMMAND_TGRESPONSETOINITIATOR (0x90)
#define MFRC522_COMMAND_TGGETTARGETSTATUS     (0x8A)

#define MFRC522_WAKEUP                        (0x55)

#define MFRC522_SPI_STATUSREAD                (0x02)
#define MFRC522_SPI_DATAWRITE                 (0x01)
#define MFRC522_SPI_DATAREAD                  (0x03)
#define MFRC522_SPI_READY                     (0x01)

#define MFRC522_I2C_ADDRESS                   (0x48 >> 1)
#define MFRC522_I2C_READY                     (0x01)

#define MFRC522_GPIO_P30                      (0x01)
#define MFRC522_GPIO_P31                      (0x02)
#define MFRC522_GPIO_P32                      (0x04)
#define MFRC522_GPIO_P33                      (0x08)
#define MFRC522_GPIO_P34                      (0x10)
#define MFRC522_GPIO_P35                      (0x20)
#define MFRC522_GPIO_VALIDATIONBIT            (0x80)

#define CARD_TYPE_106KB_ISO14443A           (0x00) // card baudrate 106 kB
#define CARD_TYPE_212KB_FELICA              (0x01) // card baudrate 212 kB
#define CARD_TYPE_424KB_FELICA              (0x02) // card baudrate 424 kB
#define CARD_TYPE_106KB_ISO14443B           (0x03) // card baudrate 106 kB
#define CARD_TYPE_106KB_JEWEL               (0x04) // card baudrate 106 kB

// Prefixes for NDEF Records (to identify record type), not used
#define NDEF_URIPREFIX_NONE                 (0x00)
#define NDEF_URIPREFIX_HTTP_WWWDOT          (0x01)
#define NDEF_URIPREFIX_HTTPS_WWWDOT         (0x02)
#define NDEF_URIPREFIX_HTTP                 (0x03)
#define NDEF_URIPREFIX_HTTPS                (0x04)
#define NDEF_URIPREFIX_TEL                  (0x05)
#define NDEF_URIPREFIX_MAILTO               (0x06)
#define NDEF_URIPREFIX_FTP_ANONAT           (0x07)
#define NDEF_URIPREFIX_FTP_FTPDOT           (0x08)
#define NDEF_URIPREFIX_FTPS                 (0x09)
#define NDEF_URIPREFIX_SFTP                 (0x0A)
#define NDEF_URIPREFIX_SMB                  (0x0B)
#define NDEF_URIPREFIX_NFS                  (0x0C)
#define NDEF_URIPREFIX_FTP                  (0x0D)
#define NDEF_URIPREFIX_DAV                  (0x0E)
#define NDEF_URIPREFIX_NEWS                 (0x0F)
#define NDEF_URIPREFIX_TELNET               (0x10)
#define NDEF_URIPREFIX_IMAP                 (0x11)
#define NDEF_URIPREFIX_RTSP                 (0x12)
#define NDEF_URIPREFIX_URN                  (0x13)
#define NDEF_URIPREFIX_POP                  (0x14)
#define NDEF_URIPREFIX_SIP                  (0x15)
#define NDEF_URIPREFIX_SIPS                 (0x16)
#define NDEF_URIPREFIX_TFTP                 (0x17)
#define NDEF_URIPREFIX_BTSPP                (0x18)
#define NDEF_URIPREFIX_BTL2CAP              (0x19)
#define NDEF_URIPREFIX_BTGOEP               (0x1A)
#define NDEF_URIPREFIX_TCPOBEX              (0x1B)
#define NDEF_URIPREFIX_IRDAOBEX             (0x1C)
#define NDEF_URIPREFIX_FILE                 (0x1D)
#define NDEF_URIPREFIX_URN_EPC_ID           (0x1E)
#define NDEF_URIPREFIX_URN_EPC_TAG          (0x1F)
#define NDEF_URIPREFIX_URN_EPC_PAT          (0x20)
#define NDEF_URIPREFIX_URN_EPC_RAW          (0x21)
#define NDEF_URIPREFIX_URN_EPC              (0x22)
#define NDEF_URIPREFIX_URN_NFC              (0x23)

enum eCardType
{
    CARD_Unknown   = 0, // Mifare Classic or other card
    CARD_Desfire   = 1, // A Desfire card with normal 7 byte UID  (bit 0)
    CARD_DesRandom = 3, // A Desfire card with 4 byte random UID  (bit 0 + 1)
};

class MFRC522
{
 public:
    MFRC522();
    
    #if USE_SOFTWARE_SPI
        void InitSoftwareSPI(byte u8_Clk, byte u8_Miso, byte u8_Mosi, byte u8_Sel, byte u8_Reset);
    #endif
    #if USE_HARDWARE_SPI
        void InitHardwareSPI(byte u8_Sel, byte u8_Reset);    
    #endif
    #if USE_HARDWARE_I2C
        void InitI2C        (byte u8_Reset);
    #endif
    
    // Generic MFRC522 functions
    void begin();  
    void SetDebugLevel(byte level);
    bool SamConfig();
    bool GetFirmwareVersion(byte* pIcType, byte* pVersionHi, byte* pVersionLo, byte* pFlags);
    bool WriteGPIO(bool P30, bool P31, bool P33, bool P35);
    bool SetPassiveActivationRetries();
    bool DeselectCard();
    bool ReleaseCard();
    bool SelectCard();

    // This function is overridden in Desfire.cpp
    virtual bool SwitchOffRfField();
            
    // ISO14443A functions
    bool ReadPassiveTargetID(byte* uidBuffer, byte* uidLength, eCardType* pe_CardType);

 protected:	
    // Low Level functions
    bool CheckMFRC522Status(byte u8_Status);
    bool SendCommandCheckAck(byte *cmd, byte cmdlen);    
    byte ReadData    (byte* buff, byte len);
    bool ReadPacket  (byte* buff, byte len);
    void WriteCommand(byte* cmd,  byte cmdlen);
    void SendPacket  (byte* buff, byte len);
    bool IsReady();
    bool WaitReady();
    bool ReadAck();
    void SpiWrite(byte c);
    byte SpiRead(void);

    byte mu8_DebugLevel;   // 0, 1, or 2
    byte mu8_PacketBuffer[MFRC522_PACKBUFFSIZE];

 private:
    byte mu8_ClkPin;
    byte mu8_MisoPin;  
    byte mu8_MosiPin;  
    byte mu8_SselPin;  
    byte mu8_ResetPin;
};

#endif
