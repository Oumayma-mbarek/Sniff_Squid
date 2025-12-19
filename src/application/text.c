#include <endian.h>
#include <stdio.h>
#include <stdint.h>

const unsigned char* parse_text( const unsigned char* bytes, const unsigned char* end, int verbosity )
{
    ssize_t length = (ssize_t)end - (ssize_t)bytes; 
    //go through lines 
    if(verbosity==3)
    {
        printf("------------ MESSAGE ----------------\n");
        for (ssize_t i=0 ; i < length ; i+=16 )
        {
            //print line number (incremented by 16 each time)
            printf("%04lx ",i);
            //go through the bytes of a single line to print hexadecimal 
            for(uint8_t j = 0 ; j < 16 ; j++)
            {
                if ( i+j > length){
                    printf("  ");
                }
                else 
                {
                    printf("%02x ", bytes[i+j]);
                }
            }
            //print an additional space at the end of each 16 bytes 
            printf("  ");
    
            //go through the bytes of the same line to print binary equivalent 
            for(uint8_t j=0 ; j<16 && i+j <length ;j++)
            {
                if(bytes[i+j] >=32 && bytes[i+j]<=126)
                {
                    printf("%c", bytes[i+j]);
    
                }
                else
                {
                    printf(".");
                }
                //printf("\n");
            }
            printf("\n");
        }
        printf("----------- Message Done ------------\n");

    }
    else if(verbosity==2)
    {
        int to_display;
        to_display = (length<20?length:20);
        for(int i=0;i<to_display;i++)
        {   
            if(bytes[i]!= '\n')
                putchar(bytes[i]);
        }
        putchar('\n');
    }
    else if(verbosity==1)
    {
        printf(" ");
    }

    /*
    for (int i=0 ; i<length; i++)
    {
        putchar(bytes[i]);
    }
    putchar('\n');
    */
    return 0 ; 
}