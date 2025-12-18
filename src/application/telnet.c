#include <endian.h>
#include <stdio.h>
#include <stdint.h>


void parse_telnet_options(const unsigned char* bytes, const unsigned char* end , ssize_t offset)
{
    if(bytes[offset]>*end)
    {
        return;
    }

    switch(bytes[offset])
    {
        case 0:
            printf("Binary transmission");
            break;

        case 1:
            printf("Echo");
            break;

        case 2:
            printf("Reconnection");
            break;

        case 3:
            printf("Suppress go ahead");
            break;

        case 4:
            printf("Approximative message size notification");
            break;

        case 5:
            printf("Status");
            break;

        case 6:
            printf("Timing mark");
            break;

        case 7:
            printf("Remote controlled trans and echo");
            break;

        case 8:
            printf("Output line width");
            break;

        case 9:
            printf("Output page size");
            break;

        case 10:
            printf("Output carriage-return disposition");
            break;

        case 11:
            printf("Output horizontal tab stops");
            break;

        case 12:
            printf("Output horizontal tab disposition");
            break;

        case 13:
            printf("Output formfeed disposition");
            break;

        case 14:
            printf("Output vertical tabstops");
            break;

        case 15:
            printf("Output vertical tab disposition");
            break;

        case 16:
            printf("Output linefeed disposition");
            break;

        case 17:
            printf("Extended ASCII");
            break;

        case 18:
            printf("Logout");
            break;

        case 19:
            printf("Byte macro");
            break;

        case 20:
            printf("Data entry terminal");
            break;

        case 21:
            printf("Supdup");
            break;

        case 22:
            printf("Supdup output");
            break;

        case 23:
            printf("Send location");
            break;

        case 24:
            printf("Terminal type");
            break;

        case 25:
            printf("End of record");
            break;

        case 26:
            printf("TACACS user identification");
            break;

        case 27:
            printf("Output marking");
            break;

        case 28:
            printf("Terminal location number");
            break;

        case 29:
            printf("Telnet 3270 regime");
            break;

        case 30:
            printf("X.3 pad");
            break;

        case 31:
            printf("Negociate about window size");
            break;

        case 32:
            printf("Terminal speed");
            break;

        case 33:
            printf("Remote flow control");
            break;

        case 34:
            printf("Linemode");
            break;

        case 35:
            printf("X display location");
            break;

        case 36:
            printf("Environment option");
            break;

        case 37:
            printf("Authentication option");
            break;

        case 38:
            printf("Encryption option");
            break;

        case 39:
            printf("New environment option");
            break;

        case 40:
            printf("TN3270E");
            break;

        case 41:
            printf("XAUTH");
            break;

        case 42:
            printf("Charset");
            break;

        case 43:
            printf("Telnet remote serial port");
            break;

        case 44:
            printf("Com port control option");
            break;

        case 45:
            printf("Telnet suppress local echo");
            break;

        case 46:
            printf("Telnet start TLS");
            break;

        case 47:
            printf("Kermit");
            break;

        case 48:
            printf("Send URL");
            break;

        case 49:
            printf("Forward-X");
            break;

        case 138:
            printf("Telopt pragma logon");
            break;

        case 139:
            printf("Telopt sspi logon");
            break;

        case 140:
            printf("Telopt pragma heartbeat");
            break;

        default:
            printf("Unknown");
            break;
    }
}
ssize_t parse_special_command(const unsigned char* bytes, const unsigned char* end,ssize_t offset)
{
    //ssize_t length = (ssize_t)end - (ssize_t)bytes; 
    ssize_t read= 1;
    
    switch (bytes[offset])
    {
        case 0xf0: 
            printf("SE (Subnegotiation End)");
            break;
        case 0xf1:
            printf("NOP");
            break;
        case 0xf2:
            printf("Data Mark");
            break;
        case 0xf3:
            printf("Break");
            break;
        case 0xf4:
            printf("Interrupt Process");
            break;
        case 0xf5:
            printf("Abort Output");
            break;
        case 0xf6:  
            printf("Are You There?");
            break;
        case 0xf7:
            printf("Erase character");
            break;
        case 0xf8:  
            printf("Erase Line");
            break;
        case 0xf9:
            printf("Go Ahead");
            break;
        case 0xfa:
            printf("SB (Subnegotiation begin)");
            break;
        case 0xfb:
            printf("WILL");
            parse_telnet_options(bytes,end,offset+1);
            read=2;
            break;
        case 0xfc:
            printf("WON'T");
            parse_telnet_options(bytes,end,offset+1);
            read=2;
            break;
        case 0xfd:  
            printf("DO");
            parse_telnet_options(bytes,end,offset+1);
            read=2;
            break;
        case 0xfe:
            printf("DON'T");
            parse_telnet_options(bytes,end,offset+1);
            read=2;
            break;
        case 0xff: 
            printf("IAC");
            break;
    }

    return  read;
    
}
const unsigned char* parse_telnet( const unsigned char* bytes, const unsigned char* end, int verbosity )
{
    ssize_t length = (ssize_t)end - (ssize_t)bytes; 
    //go through lines 
    printf("------------ MESSAGE ----------------\n");
    for (ssize_t i=0 ; i < length ; i++ )
    {
        if(bytes[i] == 0xff)
        {
            i+=parse_special_command(bytes,end,i+1);
            continue;
        }
        printf("%c" , bytes[i]);
    }
    printf("\n------------- End of Message --------------\n");
    return 0;
}