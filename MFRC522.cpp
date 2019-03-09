/**************************************************************************
    @file     MFRC522.cpp
    @author   Adafruit Industries, Elmü,step21
    @license  BSD (see license.txt)

    (Probably) based partially on the code for the MFRC522

	  Driver for NXP's MFRC522 NFC/13.56MHz RFID Transceiver

    ----------------------------------------------------------
    April 2016, modifications by Elmü:
    The code from Adafruit was a VERY SLOPPY code just for testing and playing around but not usable for production.
    It has been rewritten completely by Elmü.
    IRQ is not required anymore in I2C mode. Now the software handshake is used instead.
    Removed all compiler warnings that appeared when compiling Adafruit code.
    Bugfix: Adafruit used strncmp() to compare binary data which is completey wrong -> replaced with memcmp()
    Bugfix: (Severe bug) Adafruit code does not check for valid return packets. The checksum is completely irgnored. Bytes received before the start code are not skipped!
    Bugfix: (Severe bug) Adafruit code used a timeout = 0 (wait forever). This is completely wrong. If the chip does not respond, the code hangs forever!
    Bugfix: Adafruit code does not allow to distinguish why readPassiveTargetID() returns false. (because there is no card or because of communication problem?)
    Added support for Value blocks (in Mifare.cpp)
    Added memory Dump (in Mifare.cpp)
    AuthenticateDataBlock(), ReadDataBlock() and WriteDataBlock() rewritten (in Mifare.cpp)
    Implemented the correct wake up procedure (sending MFRC522_WAKEUP) instead of sending getFirmwareVersion.
    Debug output was buggy: The checksum bytes were displayed as 0xFFFFFFFC instead of 0xFC and removed useless "0x" before each byte.
    Detailed debug output was missing. Added display of valid data bytes inside the packet.
    SPI slow speed added (using Software SPI to get 10kHz clock)
    getFirmwareVersion() was a very clumsy and cryptic command -> completely rewritten
    writeGPIO() rewritten -> no warning about wrong usage anymore.
    setPassiveActivationRetries() did not have any error checking at all.
    Ugly code in writecommand() completely rewritten
    Crappy code like this removed:   int offset = mb_UsingSPI ? 5 : 6;
    ----------------------------------------------------------

    Check for a new version on http://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup
    
**************************************************************************/

#include "MFRC522.h"

/**************************************************************************
    Constructor
**************************************************************************/
MFRC522::MFRC522()
{
    mu8_ClkPin     = 0;
    mu8_MisoPin    = 0;  
    mu8_MosiPin    = 0;  
    mu8_SselPin    = 0;  
    mu8_ResetPin   = 0;
}

/**************************************************************************
    Initializes for hardware I2C usage.
    param  reset     The RSTPD_N pin
**************************************************************************/
#if USE_HARDWARE_I2C
    void MFRC522::InitI2C(byte u8_Reset)
    {
        mu8_ResetPin = u8_Reset;
        Utils::SetPinMode(mu8_ResetPin, OUTPUT);
    }
#endif

/**************************************************************************
    Initializes for software SPI usage.
    param  clk       SPI clock pin (SCK)
    param  miso      SPI MISO pin
    param  mosi      SPI MOSI pin
    param  sel       SPI chip select pin (CS/SSEL)
    param  reset     Location of the RSTPD_N pin
**************************************************************************/
#if USE_SOFTWARE_SPI
    void MFRC522::InitSoftwareSPI(byte u8_Clk, byte u8_Miso, byte u8_Mosi, byte u8_Sel, byte u8_Reset)
    {
        mu8_ClkPin     = u8_Clk;
        mu8_MisoPin    = u8_Miso;
        mu8_MosiPin    = u8_Mosi;
        mu8_SselPin    = u8_Sel;
        mu8_ResetPin   = u8_Reset;
    
        Utils::SetPinMode(mu8_ResetPin, OUTPUT);  
        Utils::SetPinMode(mu8_SselPin,  OUTPUT);
        Utils::SetPinMode(mu8_ClkPin,   OUTPUT);   
        Utils::SetPinMode(mu8_MosiPin,  OUTPUT);
        Utils::SetPinMode(mu8_MisoPin,  INPUT);
    }
#endif

/**************************************************************************
    Initializes for hardware SPI uage.
    param  sel       SPI chip select pin (CS/SSEL)
    param  reset     Location of the RSTPD_N pin
**************************************************************************/
#if USE_HARDWARE_SPI
    void MFRC522::InitHardwareSPI(byte u8_Sel, byte u8_Reset)
    {
        mu8_SselPin  = u8_Sel;
        mu8_ResetPin = u8_Reset;
    
        Utils::SetPinMode(mu8_ResetPin, OUTPUT);
        Utils::SetPinMode(mu8_SselPin,  OUTPUT);
    }
#endif

/**************************************************************************
    Reset the MFRC522, wake up and start communication
**************************************************************************/
void MFRC522::begin() 
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** begin()\r\n");

    Utils::WritePin(mu8_ResetPin, HIGH);
    Utils::DelayMilli(10);
    Utils::WritePin(mu8_ResetPin, LOW);
    Utils::DelayMilli(400);
    Utils::WritePin(mu8_ResetPin, HIGH);
    Utils::DelayMilli(10);  // Small delay required before taking other actions after reset. See datasheet section 12.23, page 209.
  
    #if (USE_HARDWARE_SPI || USE_SOFTWARE_SPI) 
    {
        #if USE_HARDWARE_SPI
            SpiClass::Begin(MFRC522_HARD_SPI_CLOCK);
        #endif

        // Wake up the MFRC522 (chapter 7.2.11) -> send a sequence of 0x55 (dummy bytes)
        byte u8_Buffer[20];
        memset(u8_Buffer, MFRC522_WAKEUP, sizeof(u8_Buffer));
        SendPacket(u8_Buffer, sizeof(u8_Buffer));

        if (mu8_DebugLevel > 1)
        {
            Utils::Print("Send WakeUp packet: ");
            Utils::PrintHexBuf(u8_Buffer, sizeof(u8_Buffer), LF);
        }
    }
    #elif USE_HARDWARE_I2C
    {
        I2cClass::Begin();
    }
    #endif
}

/**************************************************************************
    Enable / disable debug output to SerialClass
    0 = Off, 1 = high level debug, 2 = low level debug (more details)
**************************************************************************/
void MFRC522::SetDebugLevel(byte level)
{
    mu8_DebugLevel = level;
}

/**************************************************************************
    Gets the firmware version of the PN5xx chip
    returns:
    pIcType = Version of the IC. For MFRC522, this byte is 0x32
    pVersionHi, pVersionLo = Firmware version
    pFlags, bit 0 = Support of ISO 14443A
    pFlags, bit 1 = Support of ISO 14443B
    pFlags, bit 2 = Support of ISO 18092
**************************************************************************/
bool MFRC522::GetFirmwareVersion(byte* pIcType, byte* pVersionHi, byte* pVersionLo, byte* pFlags) 
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** GetFirmwareVersion()\r\n");
    
    mu8_PacketBuffer[0] = MFRC522_COMMAND_GETFIRMWAREVERSION;
    if (!SendCommandCheckAck(mu8_PacketBuffer, 1))
        return 0;

    byte len = ReadData(mu8_PacketBuffer, 13);
    if (len != 6 || mu8_PacketBuffer[1] != MFRC522_COMMAND_GETFIRMWAREVERSION + 1)
    {
        Utils::Print("GetFirmwareVersion failed\r\n");
        return false;
    }

    *pIcType    = mu8_PacketBuffer[2];
    *pVersionHi = mu8_PacketBuffer[3];
    *pVersionLo = mu8_PacketBuffer[4];
    *pFlags     = mu8_PacketBuffer[5];    
    return true;
}

/**************************************************************************
    Configures the SAM (Secure Access Module)
**************************************************************************/
bool MFRC522::SamConfig(void)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** SamConfig()\r\n");
  
    mu8_PacketBuffer[0] = MFRC522_COMMAND_SAMCONFIGURATION;
    mu8_PacketBuffer[1] = 0x01; // normal mode;
    mu8_PacketBuffer[2] = 0x14; // timeout 50ms * 20 = 1 second
    mu8_PacketBuffer[3] = 0x01; // use IRQ pin!
  
    if (!SendCommandCheckAck(mu8_PacketBuffer, 4))
        return false;
  
    byte len = ReadData(mu8_PacketBuffer, 9);
    if (len != 2 || mu8_PacketBuffer[1] != MFRC522_COMMAND_SAMCONFIGURATION + 1)
    {
        Utils::Print("SamConfig failed\r\n");
        return false;
    }
    return true;
}

/**************************************************************************
    Sets the amount of reties that the MFRC522 tries to activate a target
**************************************************************************/
bool MFRC522::SetPassiveActivationRetries() 
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** SetPassiveActivationRetries()\r\n");
  
    mu8_PacketBuffer[0] = MFRC522_COMMAND_RFCONFIGURATION;
    mu8_PacketBuffer[1] = 5;    // Config item 5 (MaxRetries)
    mu8_PacketBuffer[2] = 0xFF; // MxRtyATR (default = 0xFF)
    mu8_PacketBuffer[3] = 0x01; // MxRtyPSL (default = 0x01)
    mu8_PacketBuffer[4] = 3;    // one retry is enough for Mifare Classic but Desfire is slower (if you modify this, you must also modify MFRC522_TIMEOUT!)
    
    if (!SendCommandCheckAck(mu8_PacketBuffer, 5))
        return false;
  
    byte len = ReadData(mu8_PacketBuffer, 9);
    if (len != 2 || mu8_PacketBuffer[1] != MFRC522_COMMAND_RFCONFIGURATION + 1)
    {
        Utils::Print("SetPassiveActivationRetries failed\r\n");
        return false;
    }
    return true;
}

/**************************************************************************
    Turns the RF field off.
    When the field is on, the MFRC522 consumes approx 110 mA
    When the field is off, the MFRC522 consumes approx 18 mA
    The RF field is turned on again by ReadPassiveTargetID().
**************************************************************************/
bool MFRC522::SwitchOffRfField() 
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** SwitchOffRfField()\r\n");
  
    mu8_PacketBuffer[0] = MFRC522_COMMAND_RFCONFIGURATION;
    mu8_PacketBuffer[1] = 1; // Config item 1 (RF Field)
    mu8_PacketBuffer[2] = 0; // Field Off
    
    if (!SendCommandCheckAck(mu8_PacketBuffer, 3))
        return false;
  
    byte len = ReadData(mu8_PacketBuffer, 9);
    if (len != 2 || mu8_PacketBuffer[1] != MFRC522_COMMAND_RFCONFIGURATION + 1)
    {
        Utils::Print("SwitchOffRfField failed\r\n");
        return false;
    }
    return true;
}

/**************************************************************************/
/*!
    Writes an 8-bit value that sets the state of the MFRC522's GPIO pins

    All pins that can not be used as GPIO should ALWAYS be left high
    (value = 1) or the system will become unstable and a HW reset
    will be required to recover the MFRC522.

    pinState[0] (01) = P30   Can be used as GPIO
    pinState[1] (02) = P31   Can be used as GPIO
    pinState[2] (04) = P32   *** RESERVED (Must be set) ***
    pinState[3] (08) = P33   Can be used as GPIO
    pinState[4] (10) = P34   *** RESERVED (Must be set) ***
    pinState[5] (20) = P35   Can be used as GPIO

    This function is not used. The original intention was to drive a LED that 
    is connected to the MFRC522 board. But the pins deliver so few current 
    that a connected LED is very dark. (even if connected without resistor!)
    Additionally the red LED cannot be connected to the MFRC522 because it should
    flash if there is a communication error with the MFRC522. But if there is a
    communication problem the command WRITEGPIO will never arrive at the MFRC522
    and the red LED would never flash.
*/
/**************************************************************************/
bool MFRC522::WriteGPIO(bool P30, bool P31, bool P33, bool P35)
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** WriteGPIO()\r\n");
  
    byte pinState = (P30 ? MFRC522_GPIO_P30 : 0) |
                    (P31 ? MFRC522_GPIO_P31 : 0) |
                           MFRC522_GPIO_P32      |
                    (P33 ? MFRC522_GPIO_P33 : 0) |
                           MFRC522_GPIO_P34      |
                    (P35 ? MFRC522_GPIO_P35 : 0);

    mu8_PacketBuffer[0] = MFRC522_COMMAND_WRITEGPIO;
    mu8_PacketBuffer[1] = MFRC522_GPIO_VALIDATIONBIT | pinState;  // P3 Pins
    mu8_PacketBuffer[2] = 0x00;                                 // P7 GPIO Pins (not used ... taken by SPI)
                    
    if (!SendCommandCheckAck(mu8_PacketBuffer, 3))
        return false;
  
    byte len = ReadData(mu8_PacketBuffer, 9);
    if (len != 2 || mu8_PacketBuffer[1] != MFRC522_COMMAND_WRITEGPIO + 1)
    {
        Utils::Print("WriteGPIO failed\r\n");
        return false;
    }
    return true;
}


/**************************************************************************
    Waits for an ISO14443A target to enter the field.
    If the RF field has been turned off before, this command switches it on.

    param u8_UidBuffer  Pointer to an 8 byte buffer that will be populated with the card's UID (4 or 7 bytes)
    param pu8_UidLength Pointer to the variable that will hold the length of the card's UID.
    param pe_CardType   Pointer to the variable that will hold if the card is a Desfire card
    
    returns false only on error!
    returns true and *UidLength = 0 if no card was found
    returns true and *UidLength > 0 if a card has been read successfully
**************************************************************************/
bool MFRC522::ReadPassiveTargetID(byte* u8_UidBuffer, byte* pu8_UidLength, eCardType* pe_CardType) 
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** ReadPassiveTargetID()\r\n");
      
    *pu8_UidLength = 0;
    *pe_CardType   = CARD_Unknown;
    memset(u8_UidBuffer, 0, 8);
      
    mu8_PacketBuffer[0] = MFRC522_COMMAND_INLISTPASSIVETARGET;
    mu8_PacketBuffer[1] = 1;  // read data of 1 card (The MFRC522 can read max 2 targets at the same time)
    mu8_PacketBuffer[2] = CARD_TYPE_106KB_ISO14443A; // This function currently does not support other card types.
  
    if (!SendCommandCheckAck(mu8_PacketBuffer, 3))
        return false; // Error (no valid ACK received or timeout)
  
    /* 
    ISO14443A card response:
    mu8_PacketBuffer Description
    -------------------------------------------------------
    b0               D5 (always) (MFRC522_MFRC522TOHOST)
    b1               4B (always) (MFRC522_COMMAND_INLISTPASSIVETARGET + 1)
    b2               Amount of cards found
    b3               Tag number (always 1)
    b4,5             SENS_RES (ATQA = Answer to Request Type A)
    b6               SEL_RES  (SAK  = Select Acknowledge)
    b7               UID Length
    b8..Length       UID (4 or 7 bytes)
    nn               ATS Length     (Desfire only)
    nn..Length-1     ATS data bytes (Desfire only)
    */ 
    byte len = ReadData(mu8_PacketBuffer, 28);
    if (len < 3 || mu8_PacketBuffer[1] != MFRC522_COMMAND_INLISTPASSIVETARGET + 1)
    {
        Utils::Print("ReadPassiveTargetID failed\r\n");
        return false;
    }   

    byte cardsFound = mu8_PacketBuffer[2]; 
    if (mu8_DebugLevel > 0)
    {
        Utils::Print("Cards found: "); 
        Utils::PrintDec(cardsFound, LF); 
    }
    if (cardsFound != 1)
        return true; // no card found -> this is not an error!

    byte u8_IdLength = mu8_PacketBuffer[7];
    if (u8_IdLength != 4 && u8_IdLength != 7)
    {
        Utils::Print("Card has unsupported UID length: ");
        Utils::PrintDec(u8_IdLength, LF); 
        return true; // unsupported card found -> this is not an error!
    }   

    memcpy(u8_UidBuffer, mu8_PacketBuffer + 8, u8_IdLength);    
    *pu8_UidLength = u8_IdLength;

    // See "Mifare Identification & Card Types.pdf" in the ZIP file
    uint16_t u16_ATQA = ((uint16_t)mu8_PacketBuffer[4] << 8) | mu8_PacketBuffer[5];
    byte     u8_SAK   = mu8_PacketBuffer[6];

    if (u8_IdLength == 7 && u8_UidBuffer[0] != 0x80 && u16_ATQA == 0x0344 && u8_SAK == 0x20) *pe_CardType = CARD_Desfire;
    if (u8_IdLength == 4 && u8_UidBuffer[0] == 0x80 && u16_ATQA == 0x0304 && u8_SAK == 0x20) *pe_CardType = CARD_DesRandom;
    
    if (mu8_DebugLevel > 0)
    {
        Utils::Print("Card UID:    ");
        Utils::PrintHexBuf(u8_UidBuffer, u8_IdLength, LF);

        // Examples:              ATQA    SAK  UID length
        // MIFARE Mini            00 04   09   4 bytes
        // MIFARE Mini            00 44   09   7 bytes
        // MIFARE Classic 1k      00 04   08   4 bytes
        // MIFARE Classic 4k      00 02   18   4 bytes
        // MIFARE Ultralight      00 44   00   7 bytes
        // MIFARE DESFire Default 03 44   20   7 bytes
        // MIFARE DESFire Random  03 04   20   4 bytes
        // See "Mifare Identification & Card Types.pdf"
        char s8_Buf[80];
        sprintf(s8_Buf, "Card Type:   ATQA= 0x%04X, SAK= 0x%02X", u16_ATQA, u8_SAK);

        if (*pe_CardType == CARD_Desfire)   strcat(s8_Buf, " (Desfire Default)");
        if (*pe_CardType == CARD_DesRandom) strcat(s8_Buf, " (Desfire RandomID)");
            
        Utils::Print(s8_Buf, LF);
    }
    return true;
}

/**************************************************************************
    The goal of this command is to select the target. (Initialization, anti-collision loop and Selection)
    If the target is already selected, no action is performed and Status OK is returned. 
**************************************************************************/
bool MFRC522::SelectCard()
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** SelectCard()\r\n");
  
    mu8_PacketBuffer[0] = MFRC522_COMMAND_INSELECT;
    mu8_PacketBuffer[1] = 1; // Target 1

    if (!SendCommandCheckAck(mu8_PacketBuffer, 2))
        return false;
  
    byte len = ReadData(mu8_PacketBuffer, 10);
    if (len < 3 || mu8_PacketBuffer[1] != MFRC522_COMMAND_INSELECT + 1)
    {
        Utils::Print("Select failed\r\n");
        return false;
    }

    return CheckMFRC522Status(mu8_PacketBuffer[2]);
}

/**************************************************************************
    The goal of this command is to deselect the target. 
    The _MFRC522_ keeps all the information relative to this target (also certain error status).  
    This function is required due to a stupid behaviour with Mifare Classic:
    When AuthenticateDataBlock() has failed for a sector, you also get an
    authentication error for the next sector although you have passed the correct key.
    So, after an authentication error you must first deselect the card before
    authenticating a new sector!
**************************************************************************/
bool MFRC522::DeselectCard()
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** DeselectCard()\r\n");
  
    mu8_PacketBuffer[0] = MFRC522_COMMAND_INDESELECT;
    mu8_PacketBuffer[1] = 0; // Deselect all cards

    if (!SendCommandCheckAck(mu8_PacketBuffer, 2))
        return false;
  
    byte len = ReadData(mu8_PacketBuffer, 10);
    if (len < 3 || mu8_PacketBuffer[1] != MFRC522_COMMAND_INDESELECT + 1)
    {
        Utils::Print("Deselect failed\r\n");
        return false;
    }

    return CheckMFRC522Status(mu8_PacketBuffer[2]);
}

/**************************************************************************
    The goal of this command is to release the target.
    Releasing a target means that the host controller has finished the communication with 
    the target, so the MFRC522 erases all the information relative to it. 
**************************************************************************/
bool MFRC522::ReleaseCard()
{
    if (mu8_DebugLevel > 0) Utils::Print("\r\n*** ReleaseCard()\r\n");
  
    mu8_PacketBuffer[0] = MFRC522_COMMAND_INRELEASE;
    mu8_PacketBuffer[1] = 0; // Deselect all cards

    if (!SendCommandCheckAck(mu8_PacketBuffer, 2))
        return false;
  
    byte len = ReadData(mu8_PacketBuffer, 10);
    if (len < 3 || mu8_PacketBuffer[1] != MFRC522_COMMAND_INRELEASE + 1)
    {
        Utils::Print("Release failed\r\n");
        return false;
    }

    return CheckMFRC522Status(mu8_PacketBuffer[2]);
}

/**************************************************************************
    This function is private
    It checks the status byte that is returned by some commands.
    See chapter 7.1 in the manual.
    u8_Status = the status byte
**************************************************************************/
bool MFRC522::CheckMFRC522Status(byte u8_Status)
{
    // Bits 0...5 contain the error code.
    u8_Status &= 0x3F;

    if (u8_Status == 0)
        return true;

    char s8_Buf[50];
    sprintf(s8_Buf, "MFRC522 Error 0x%02X: ", u8_Status);
    Utils::Print(s8_Buf);

    switch (u8_Status)
    {
        case 0x01: 
            Utils::Print("Timeout\r\n");
            return false;
        case 0x02: 
            Utils::Print("CRC error\r\n");
            return false;
        case 0x03: 
            Utils::Print("Parity error\r\n");
            return false;
        case 0x04: 
            Utils::Print("Wrong bit count during anti-collision\r\n");
            return false;
        case 0x05: 
            Utils::Print("Framing error\r\n");
            return false;
        case 0x06: 
            Utils::Print("Abnormal bit collision\r\n");
            return false;
        case 0x07: 
            Utils::Print("Insufficient communication buffer\r\n");
            return false;
        case 0x09: 
            Utils::Print("RF buffer overflow\r\n");
            return false;
        case 0x0A: 
            Utils::Print("RF field has not been switched on\r\n");
            return false;
        case 0x0B: 
            Utils::Print("RF protocol error\r\n");
            return false;
        case 0x0D: 
            Utils::Print("Overheating\r\n");
            return false;
        case 0x0E: 
            Utils::Print("Internal buffer overflow\r\n");
            return false;
        case 0x10: 
            Utils::Print("Invalid parameter\r\n");
            return false;
        case 0x12: 
            Utils::Print("Command not supported\r\n");
            return false;
        case 0x13: 
            Utils::Print("Wrong data format\r\n");
            return false;
        case 0x14:
            Utils::Print("Authentication error\r\n");
            return false;
        case 0x23:
            Utils::Print("Wrong UID check byte\r\n");
            return false;
        case 0x25:
            Utils::Print("Invalid device state\r\n");
            return false;
        case 0x26:
            Utils::Print("Operation not allowed\r\n");
            return false;
        case 0x27:
            Utils::Print("Command not acceptable\r\n");
            return false;
        case 0x29:
            Utils::Print("Target has been released\r\n");
            return false;
        case 0x2A:
            Utils::Print("Card has been exchanged\r\n");
            return false;
        case 0x2B:
            Utils::Print("Card has disappeared\r\n");
            return false;
        case 0x2C:
            Utils::Print("NFCID3 initiator/target mismatch\r\n");
            return false;
        case 0x2D:
            Utils::Print("Over-current\r\n");
            return false;
        case 0x2E:
            Utils::Print("NAD msssing\r\n");
            return false;
        default:
            Utils::Print("Undocumented error\r\n");
            return false;
    }
}

// ########################################################################
// ####                      LOW LEVEL FUNCTIONS                      #####
// ########################################################################


/**************************************************************************
    Return true if the MFRC522 is ready with a response.
**************************************************************************/
bool MFRC522::IsReady() 
{
    #if (USE_HARDWARE_SPI || USE_SOFTWARE_SPI) 
    {
        Utils::WritePin(mu8_SselPin, LOW);
        Utils::DelayMilli(2); // INDISPENSABLE!! Otherwise reads bullshit

        if (mu8_DebugLevel > 2) Utils::Print("IsReady(): write STATUSREAD\r\n");

        SpiWrite(MFRC522_SPI_STATUSREAD);
        byte u8_Ready = SpiRead();

        if (mu8_DebugLevel > 2)
        {
            Utils::Print("IsReady(): read ");
            Utils::PrintHex8(u8_Ready, LF);
        }
    
        Utils::WritePin(mu8_SselPin, HIGH);
        Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);
        
        return u8_Ready == MFRC522_SPI_READY; // 0x01
    }
    #elif USE_HARDWARE_I2C
    { 
        // After reading this byte, the bus must be released with a Stop condition
        I2cClass::RequestFrom((byte)MFRC522_I2C_ADDRESS, (byte)1);

        // MFRC522 Manual chapter 6.2.4: Before the data bytes the chip sends a Ready byte.
        byte u8_Ready = I2cClass::Read();
        if (mu8_DebugLevel > 2)
        {
            Utils::Print("IsReady(): read ");
            Utils::PrintHex8(u8_Ready, LF);
        }        
        
        return u8_Ready == MFRC522_I2C_READY; // 0x01
    }
    #endif
}

/**************************************************************************
    Waits until the MFRC522 is ready.
**************************************************************************/
bool MFRC522::WaitReady() 
{
    uint16_t timer = 0;
    while (!IsReady()) 
    {
        if (timer >= MFRC522_TIMEOUT) 
        {
            Utils::Print("WaitReady() -> TIMEOUT\r\n");
            return false;
        }
        Utils::DelayMilli(10);
        timer += 10;        
    }
    return true;
}

/**************************************************************************
    Sends a command and waits a specified period for the ACK
    param cmd       Pointer to the command buffer
    param cmdlen    The size of the command in bytes

    returns  true  if everything is OK, 
             false if timeout occured before an ACK was recieved
**************************************************************************/
bool MFRC522::SendCommandCheckAck(byte *cmd, byte cmdlen) 
{
    WriteCommand(cmd, cmdlen);
    return ReadAck();
}

/**************************************************************************
    Writes a command to the MFRC522, inserting the
    preamble and required frame details (checksum, len, etc.)

    param  cmd       Command buffer
    param  cmdlen    Command length in bytes
**************************************************************************/
void MFRC522::WriteCommand(byte* cmd, byte cmdlen)
{
    byte TxBuffer[MFRC522_PACKBUFFSIZE + 10];
    int P=0;
    TxBuffer[P++] = MFRC522_PREAMBLE;    // 00
    TxBuffer[P++] = MFRC522_STARTCODE1;  // 00
    TxBuffer[P++] = MFRC522_STARTCODE2;  // FF
    TxBuffer[P++] = cmdlen + 1;
    TxBuffer[P++] = 0xFF - cmdlen;
    TxBuffer[P++] = MFRC522_HOSTTOMFRC522; // D4
    
    for (byte i=0; i<cmdlen; i++) 
    {
        TxBuffer[P++] = cmd[i];
    }

    byte checksum = 0;
    for (byte i=0; i<P; i++) 
    {
       checksum += TxBuffer[i];
    }

    TxBuffer[P++] = ~checksum;
    TxBuffer[P++] = MFRC522_POSTAMBLE; // 00

    SendPacket(TxBuffer, P);
   
    if (mu8_DebugLevel > 1)
    {
        Utils::Print("Sending:  ");
        Utils::PrintHexBuf(TxBuffer, P, LF, 5, cmdlen + 6);
    }
}

/**************************************************************************
    Send a data packet
**************************************************************************/
void MFRC522::SendPacket(byte* buff, byte len)
{
    #if (USE_HARDWARE_SPI || USE_SOFTWARE_SPI) 
    {
        Utils::WritePin(mu8_SselPin, LOW);
        Utils::DelayMilli(2);  // INDISPENSABLE!!

        if (mu8_DebugLevel > 2) Utils::Print("WriteCommand(): write DATAWRITE\r\n");
        SpiWrite(MFRC522_SPI_DATAWRITE);

        for (byte i=0; i<len; i++) 
        {
            SpiWrite(buff[i]);
        }

        Utils::WritePin(mu8_SselPin, HIGH);
        Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);
    }
    #elif USE_HARDWARE_I2C
    {
        Utils::DelayMilli(2); // delay is for waking up the board
    
        I2cClass::BeginTransmission(MFRC522_I2C_ADDRESS);
        for (byte i=0; i<len; i++) 
        {
            I2cClass::Write(buff[i]);
        }   
        I2cClass::EndTransmission();
    }
    #endif
}

/**************************************************************************
    Read the ACK packet (acknowledge)
**************************************************************************/
bool MFRC522::ReadAck() 
{
    const byte Ack[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
    byte ackbuff[sizeof(Ack)];
    
    // ATTENTION: Never read more than 6 bytes here!
    // The MFRC522 has a bug in SPI mode which results in the first byte of the response missing if more than 6 bytes are read here!
    if (!ReadPacket(ackbuff, sizeof(ackbuff)))
        return false; // Timeout

    if (mu8_DebugLevel > 2)
    {
        Utils::Print("Read ACK: ");
        Utils::PrintHexBuf(ackbuff, sizeof(ackbuff), LF);
    }
    
    if (memcmp(ackbuff, Ack, sizeof(Ack)) != 0)
    {
        Utils::Print("*** No ACK frame received\r\n");
        return false;
    }
    return true;
}

/**************************************************************************
    Reads n bytes of data from the MFRC522 via SPI or I2C and checks for valid data.
    param  buff      Pointer to the buffer where data will be written
    param  len       Number of bytes to read
    returns the number of bytes that have been copied to buff (< len) or 0 on error
**************************************************************************/
byte MFRC522::ReadData(byte* buff, byte len) 
{ 
    byte RxBuffer[MFRC522_PACKBUFFSIZE];
        
    const byte MIN_PACK_LEN = 2 /*start bytes*/ + 2 /*length + length checksum */ + 1 /*checksum*/;
    if (len < MIN_PACK_LEN || len > MFRC522_PACKBUFFSIZE)
    {
        Utils::Print("ReadData(): len is invalid\r\n");
        return 0;
    }
    
    if (!ReadPacket(RxBuffer, len))
        return 0; // timeout

    // The following important validity check was completely missing in Adafruit code (added by Elmü)
    // MFRC522 documentation says (chapter 6.2.1.6): 
    // Before the start code (0x00 0xFF) there may be any number of additional bytes that must be ignored.
    // After the checksum there may be any number of additional bytes that must be ignored.
    // This function returns ONLY the pure data bytes:
    // any leading bytes -> skipped (never seen, but documentation says to ignore them)
    // preamble   0x00   -> skipped (optional, the MFRC522 does not send it always!!!!!)
    // start code 0x00   -> skipped
    // start code 0xFF   -> skipped
    // length            -> skipped
    // length checksum   -> skipped
    // data[0...n]       -> returned to the caller (first byte is always 0xD5)
    // checksum          -> skipped
    // postamble         -> skipped (optional, the MFRC522 may not send it!)
    // any bytes behind  -> skipped (never seen, but documentation says to ignore them)

    const char* Error = NULL;
    int Brace1 = -1;
    int Brace2 = -1;
    int dataLength = 0;
    do
    {
        int startCode = -1;
        for (int i=0; i<=len-MIN_PACK_LEN; i++)
        {
            if (RxBuffer[i]   == MFRC522_STARTCODE1 && 
                RxBuffer[i+1] == MFRC522_STARTCODE2)
            {
                startCode = i;
                break;
            }
        }

        if (startCode < 0)
        {
            Error = "ReadData() -> No Start Code\r\n";
            break;
        }
        
        int pos = startCode + 2;
        dataLength      = RxBuffer[pos++];
        int lengthCheck = RxBuffer[pos++];
        if ((dataLength + lengthCheck) != 0x100)
        {
            Error = "ReadData() -> Invalid length checksum\r\n";
            break;
        }
    
        if (len < startCode + MIN_PACK_LEN + dataLength)
        {
            Error = "ReadData() -> Packet is longer than requested length\r\n";
            break;
        }

        Brace1 = pos;
        for (int i=0; i<dataLength; i++)
        {
            buff[i] = RxBuffer[pos++]; // copy the pure data bytes in the packet
        }
        Brace2 = pos;

        // All returned data blocks must start with MFRC522TOHOST (0xD5)
        if (dataLength < 1 || buff[0] != MFRC522_MFRC522TOHOST) 
        {
            Error = "ReadData() -> Invalid data (no MFRC522TOHOST)\r\n";
            break;
        }
    
        byte checkSum = 0;
        for (int i=startCode; i<pos; i++)
        {
            checkSum += RxBuffer[i];
        }
    
        if (checkSum != (byte)(~RxBuffer[pos]))
        {
            Error = "ReadData() -> Invalid checksum\r\n";
            break;
        }
    }
    while(false); // This is not a loop. Avoids using goto by using break.

    // Always print the package, even if it was invalid.
    if (mu8_DebugLevel > 1)
    {
        Utils::Print("Response: ");
        Utils::PrintHexBuf(RxBuffer, len, LF, Brace1, Brace2);
    }
    
    if (Error)
    {
        Utils::Print(Error);
        return 0;
    }

    return dataLength;
}

/**************************************************************************
    Reads n bytes of data from the MFRC522 via SPI or I2C and does NOT check for valid data.
    param  buff      Pointer to the buffer where data will be written
    param  len       Number of bytes to read
**************************************************************************/
bool MFRC522::ReadPacket(byte* buff, byte len)
{ 
    if (!WaitReady())
        return false;
        
    #if (USE_HARDWARE_SPI || USE_SOFTWARE_SPI) 
    {
        Utils::WritePin(mu8_SselPin, LOW);
        Utils::DelayMilli(2); // INDISPENSABLE!! Otherwise reads bullshit

        if (mu8_DebugLevel > 2)  Utils::Print("ReadPacket(): write DATAREAD\r\n");
        SpiWrite(MFRC522_SPI_DATAREAD);
    
        for (byte i=0; i<len; i++) 
        {
            Utils::DelayMilli(1);
            buff[i] = SpiRead();
        }
    
        Utils::WritePin(mu8_SselPin, HIGH);
        Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);
        return true;
    }
    #elif USE_HARDWARE_I2C
    {
        Utils::DelayMilli(2);
    
        // read (n+1 to take into account leading Ready byte)
        I2cClass::RequestFrom((byte)MFRC522_I2C_ADDRESS, (byte)(len+1));

        // MFRC522 Manual chapter 6.2.4: Before the data bytes the chip sends a Ready byte.
        // It is ignored here because it has been checked already in isready()
        byte u8_Ready = I2cClass::Read();
        if (mu8_DebugLevel > 2)
        {
            Utils::Print("ReadPacket(): read ");
            Utils::PrintHex8(u8_Ready, LF);
        }        
        
        for (byte i=0; i<len; i++) 
        {
            Utils::DelayMilli(1);
            buff[i] = I2cClass::Read();
        }
        return true;
    }
    #endif
}

/**************************************************************************
    SPI write one byte
**************************************************************************/
void MFRC522::SpiWrite(byte c) 
{
    #if USE_HARDWARE_SPI
    {
        SpiClass::Transfer(c);
    }
    #elif USE_SOFTWARE_SPI
    {
        Utils::WritePin(mu8_ClkPin, HIGH);
        Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);
    
        for (int i=1; i<=128; i<<=1) 
        {
            Utils::WritePin(mu8_ClkPin, LOW);
            Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);
            
            byte level = (c & i) ? HIGH : LOW;
            Utils::WritePin(mu8_MosiPin, level);
            Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);        
      
            Utils::WritePin(mu8_ClkPin, HIGH);
            Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);
        }
    }
    #endif
}

/**************************************************************************
    SPI read one byte
**************************************************************************/
byte MFRC522::SpiRead(void) 
{
    #if USE_HARDWARE_SPI 
    {
        return SpiClass::Transfer(0x00);
    }
    #elif USE_SOFTWARE_SPI
    {
        Utils::WritePin(mu8_ClkPin, HIGH);
        Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);

        int x=0;    
        for (int i=1; i<=128; i<<=1) 
        {
            if (Utils::ReadPin(mu8_MisoPin)) 
            {
                x |= i;
            }
            Utils::WritePin(mu8_ClkPin, LOW);
            Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);
            Utils::WritePin(mu8_ClkPin, HIGH);
            Utils::DelayMicro(MFRC522_SOFT_SPI_DELAY);
        }
        return x;
    }
    #else
    {
        return 0; // This code will never execute. Just for the compiler not to complain.
    }
    #endif
}


