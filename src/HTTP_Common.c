#include <stdio.h>
//#define _GNU_SOURCE
#include <string.h> 
#include <ctype.h>
#include "HTTP_Common.h"
#include "HTTP_Message.h"


void http_freeBuf(int thread_seq, char **buf, uint32 *buflen)
{
	if(*buf!=NULL)
	{
		dictator_free(thread_seq,*buf);
		*buf = NULL;
		*buflen = 0;
	}	
	return;
}

char* double_memchr(const char* before, uint32 before_len, const char* this_data, uint32 this_len, char c)
{
	/*before only  find last two char*/
	if(before_len>=1)
	{
		if(*(before+(before_len-1))==c) return (char*)(before+(before_len-1));
	}
	if(before_len>=2)
	{
		if(*(before+(before_len-2))==c) return (char*)(before+(before_len-2));
	}
	return (char*)memchr(this_data,c,this_len);
}

/*
char* double_memchr(const char* before, uint32 before_len, const char* this_data, uint32 this_len, char c)
{
    char*pos=(char*)memchr(before,c,before_len);
    if(pos!=NULL)
    {   
        return pos;
    }   
    pos=(char*)memchr(this_data,c,this_len);
    return pos;
}
*/
char* double_memread(const char*before,uint32 before_len,const char* this_data,uint32 this_len,const char*pos,uint32 offset)
{
	const char* v_target=pos+offset;
	if((pos>=before&&pos<before+before_len)||(pos>=this_data&&pos<this_data+this_len))
	{
		if(before<=v_target&&v_target<before+before_len)
		{
			return (char*)v_target;
		}		
		if(this_data<=v_target&&v_target<this_data+this_len)
		{
			return (char*)v_target;
		}
		if(this_data<=(this_data+offset-(before+before_len-pos))&&(this_data+offset-(before+before_len-pos))<this_data+this_len)
		{
			return (char*)(this_data+offset-(before+before_len-pos));
		}		
	}	
	return NULL;
}

uint32 double_mem_offset(const char*before,uint32 before_len,const char* this_data,uint32 this_len,const char* p)
{
	if(p>=this_data&&p<this_data+this_len)
	{
		return before_len+(p-this_data);
	}
	if(p>=before&&p<before+before_len)
	{
		return p-before;
	}	
	return -1;
}

char A_to_a(char ch)
{
	if(ch>='A'&&ch<='Z') return ch+'a'-'A';
	return ch;
}

/**********************************************************
 * 功能：去掉data前面的空行，空格，制表符。
 * offset:返回值，第一个不是空行，空格，制表符数据在当前数据的偏移量。
 * data：当前数据。
 * data_len:当前数据的长度。
***********************************************************/
void http_deleteEmptyRow(uint32 *offset, char* data, uint32 data_len)
{		
	if(NULL==data||data_len==0)		return;
	while(*offset<data_len && *offset>=0)
	{
		if(HTTP_CR!=*(data+(*offset)) && HTTP_NULL!=*(data+(*offset)) && HTTP_LF!=*(data+(*offset)) && HTTP_SP!=*(data+(*offset)) && HTTP_HT!=*(data+(*offset)))
			break;
		if(HTTP_CR==*(data+(*offset)) || HTTP_NULL==*(data+(*offset)) || HTTP_LF==*(data+(*offset)) || HTTP_SP==*(data+(*offset)) || HTTP_HT==*(data+(*offset)))
			(*offset)++;
	}
}

void http_deleteEmptyRow_chunk(uint32 *offset, char* data, uint32 data_len)
{	
	if(NULL==data||data_len==0)		return;
	while(*offset<data_len && *offset>=0)
	{
		if(HTTP_CR!=*(data+(*offset)) && HTTP_LF!=*(data+(*offset))&& HTTP_SP!=*(data+(*offset)) && HTTP_HT!=*(data+(*offset)) && 0!=*(data+(*offset)))
			break;
		if(HTTP_CR==*(data+(*offset)) || HTTP_LF==*(data+(*offset))|| HTTP_SP==*(data+(*offset)) || HTTP_HT==*(data+(*offset)) || 0==*(data+(*offset)))
			(*offset)++;
	}
	return;
}

/**********************************************************
 * 功能：删除data前面的折叠符。
 * offset:返回值，第一个不是空行，空格，制表符数据在当前数据的偏移量。
 * data：当前数据。
 * data_len：当前数据的长度。
***********************************************************/
void http_deleteSPHT(uint32 *offset, char* data, uint32 data_len)
{
	while(*offset<data_len && *offset>=0)
	{
		if(HTTP_SP!=*(data+(*offset)) && HTTP_HT!=*(data+(*offset)))
			break;
		(*offset)++;
	}
}/*http_deleteSPHTCRLFAtLast*/

/**********************************************************
 * 功能：删除data后面的空格，空行，制表符。
 * del_data_len：删除后数据的长度。
 * data：当前数据。
 * data_len：当前数据的长度。
***********************************************************/
void http_deleteSPHTCRLFAtLast(uint32 *del_data_len, char* data, uint32 data_len)
{
	if(data==NULL||data_len==0) 		return ;
	*del_data_len = data_len - 1;
	if(0==*del_data_len)
	{
		if(HTTP_CR==*(data+*del_data_len) || HTTP_HT==*(data+*del_data_len) ||
			HTTP_SP==*(data+*del_data_len) || HTTP_LF==*(data+*del_data_len))
				return ;
	}
	while(*del_data_len>=0)
	{
		if(HTTP_CR!=*(data+*del_data_len) && HTTP_HT!=*(data+*del_data_len) &&
		   HTTP_SP!=*(data+*del_data_len) && HTTP_LF!=*(data+*del_data_len))
			break;
		if(HTTP_CR==*(data+*del_data_len) || HTTP_HT==*(data+*del_data_len) ||
		   HTTP_SP==*(data+*del_data_len) || HTTP_LF==*(data+*del_data_len))
			(*del_data_len)--;
		
		if((*del_data_len)<=0)
			break;
	}
	(*del_data_len)++;
}

/**********************************************************
 * 功能：寻找all_data缓存中CRLF的位置。
 * res:输出值，通过该参数判定是否读到\r\n
 * all_data:已有数据缓存区。
 **********************************************************/
char* http_findCRLF(char *all_data, uint32 len)
{
	if(NULL==all_data||0==len) return NULL;
	char *s_cr=NULL;
	s_cr=(char*)memchr(all_data,'\r',len);	
	/*读到\r*/
	if(NULL!=s_cr)
	{		
		return s_cr;
	}
	/*没读到\r*/	
	return NULL;
}

char* http_findCRLF_Chunk(char *all_data, uint32 len, uint32* end_flag_size)
{
	if(all_data==NULL || len==0) return NULL;

	char *s_cr=NULL;
	char *s_lf=NULL;
	char *p_ret=NULL;
	uint32	rf = 2;
	s_cr=(char*)memchr(all_data, '\r',len);
	s_lf=(char*)memmem(all_data, len, (void*)"\0\n", rf);	
	if(NULL!=s_cr && NULL!=s_lf)
	{
		p_ret = MIN(s_cr, s_lf);
		*end_flag_size = (p_ret == s_cr)? 1:2;
	}
	else if(NULL == s_cr && NULL == s_lf)
	{
	}
	else
	{
		p_ret = (s_lf != NULL)?s_lf:s_cr;
		*end_flag_size = (s_lf != NULL)? 2:1;
	}	
	return p_ret;
}

void stringA_to_stringa(char* str, uint32 l_str)
{
	uint16 m =0;
	for(m=0;m<l_str;m++)
	{
		str[m] = A_to_a(str[m]);
	}
}

/* this function is copy from other system. */
char *memcasemem(const char *strsrc,int len1,const char *substr,int len2)
{
		
	char *p1,*p2,*pend;
	char *p;
	char *substrS;
	int i,lenth;

	if((strsrc==NULL)||substr==NULL)
		return NULL;
	if(len1<len2) return NULL;

	lenth=len2;
	substrS=(char *)malloc(sizeof(char)*(lenth+1));
	if(substrS==NULL)
		return NULL;
	for(i=0;i<lenth;i++)
	{
		substrS[i]=tolower(*(substr+i));
	}
	substrS[lenth]=0;

	lenth=len1;
	pend =(char *)strsrc + lenth;
	for(p1 =(char *) strsrc; p1 != pend;p1++)
	{
		for(p2 = p1,p = substrS;*p != '\0'&& p2 != pend;p++,p2++)
		{
			if(tolower(*p2) != *p)
				break;
		}
		if(*p == '\0')
		{
			free(substrS);
			return p1;
		}
	}

	free(substrS);
	return NULL;
}	

long long rdtsc(void)
{
long long l;
long long h;
 
__asm__ volatile("rdtsc" : "=a"(l), "=d"(h));
return (long long )l | ((long long )h<<32);
}

