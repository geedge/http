#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
/****************************************************************
20060905 lqy 
(1)mailsubject_base64_decode 函数中修正对于base64解码,'='在字符串末尾的
  情况的处理
*****************************************************************
20061130 LQY
mime_base64_decode 函数中修正对于base64解码,'='在字符串末尾的
  情况的处理

****************************************************************/
/* The following diagram shows the logical steps by which three octets
   get transformed into eight Base64 characters.  It helps understanding
   shifts and masks in the transformation functions.

		 .--------.  .--------.  .--------.
		 |aaaaaabb|  |bbbbcccc|  |ccdddddd|
		 `--------'  `--------'  `--------'
                    6   2      4   4       2   6
	       .--------+--------+--------+--------.
	       |00aaaaaa|00bbbbbb|00cccccc|00dddddd|
	       `--------+--------+--------+--------'

	       .--------+--------+--------+--------.
	       |AAAAAAAA|BBBBBBBB|CCCCCCCC|DDDDDDDD|
	       `--------+--------+--------+--------'

   The octets are divided into 6 bit chunks, which are then encoded into
   Base64 characters.  */

/* Table of characters coding the 64 values.  */
char httpproxy_base64_value_to_char[64] =
{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',	/*  0- 9 */
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',	/* 10-19 */
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',	/* 20-29 */
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',	/* 30-39 */
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',	/* 40-49 */
  'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',	/* 50-59 */
  '8', '9', '+', '/'					/* 60-63 */
};

/* Table of base64 values for first 128 characters.  */
#define z -1
int httpproxy_base64_char_to_value[128] =
{
  z,   z,   z,   z,   z,   z,   z,   z,   z,   z,	/*   0-  9 */
  z,   z,   z,   z,   z,   z,   z,   z,   z,   z,	/*  10- 19 */
  z,   z,   z,   z,   z,   z,   z,   z,   z,   z,	/*  20- 29 */
  z,   z,   z,   z,   z,   z,   z,   z,   z,   z,	/*  30- 39 */
  z,   z,   z,   62,  z,   z,   z,   63,  52,  53,	/*  40- 49 */
  54,  55,  56,  57,  58,  59,  60,  61,  z,   z,	/*  50- 59 */
  z,   z,   z,   z,   z,   0,   1,   2,   3,   4,	/*  60- 69 */
  5,   6,   7,   8,   9,   10,  11,  12,  13,  14,	/*  70- 79 */
  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,	/*  80- 89 */
  25,  z,   z,   z,   z,   z,   z,   26,  27,  28,	/*  90- 99 */
  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,	/* 100-109 */
  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,	/* 110-119 */
  49,  50,  51,  z,   z,   z,   z,   z			/* 120-127 */
};
#undef z

int http_proxy_base64_decode(int flag_quote,char *src_buf,int srclen, char *dest)
{
    unsigned long value=0;
    char *temp=NULL;
    char *inputend=NULL;
    int result=0;
    char *dst_buf=NULL;
    int dst_len=0;
	
    if(srclen==0)
    {
		return 0;
    }

	
    temp=src_buf;
	inputend=src_buf+srclen;
	dst_buf=dest;
	
    if(flag_quote==1)
    {
	
	   strcpy(dst_buf,"\"");
	   	dst_len++;
    }
	else
	{
		strcpy(dst_buf,"");
    }
    while(temp<inputend)
    {
	    if(*temp=='\n'||*temp=='\r')
	    {
	        temp=temp+1;
			continue;
	    }
	    // process first byte of a quadruplet.
	    if(IS_BASE64(*temp))
	         value=httpproxy_base64_char_to_value[(int)*temp]<<18;
	    else
	         value=0;
		temp=temp+1;
	    //process second byte of a quadruplet.
	    if(temp==inputend)
	    {
	         result=-1;
		 	 goto dowith;
	    }
		else
	    {
			if(IS_BASE64(*temp))
			{
				value|=httpproxy_base64_char_to_value[(int)*temp]<<12;
			}				
			dst_buf[dst_len++]=(unsigned char)(value>>16);
			dst_buf[dst_len]='\0';
		}
	    temp=temp+1;
        // process third byte of a quadruple
  	    if(temp==inputend)
	    {
	         result=-1;
		 	 goto dowith;
	    }
	    else
	    {
			if(*temp=='=')
			{
				temp=temp+1;
				//add by lqy 060905	
				if(temp==inputend)
				{
					goto dowith;
				}
				temp=temp+1;
				continue;
			}
			if(IS_BASE64(*temp))
			{
				value|=httpproxy_base64_char_to_value[(int)*temp]<<6;
			}
			dst_buf[dst_len++]=(unsigned char)(MASK(8)&(value>>8));
			dst_buf[dst_len]='\0';
		}
		temp=temp+1;
		if(temp==inputend)
	    {
	        result=-1;
			goto dowith;
	    }
		else
	    {
			if(*temp=='=')
			{
				temp=temp+1;
				continue;
			}
			if(IS_BASE64(*temp))
			{
		        value|=httpproxy_base64_char_to_value[(int)*temp];
			}
			dst_buf[dst_len++]=(unsigned char)(MASK(8)&value);
			dst_buf[dst_len]='\0';
		}
	    temp=temp+1;
    }

    if(flag_quote==1)
    {
		strcat(dst_buf," \"");
    }
    
dowith:
    
    return result;
}




