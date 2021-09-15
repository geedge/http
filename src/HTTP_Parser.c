#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <math.h>
#include <http.h>
#include <stream.h>
#include <http_parser.h>
#include "http.h"
#include "HTTP_Common.h"
#include "HTTP_Message_Header.h"

extern const char* g_http_method[];

typedef struct host_parser_t
{	
	char* host_value;		
	char is_http_flag;
	char get_host_flag;
	char host_field_flag;		
	char host_value_flag;
	uint32 host_valuelen;
}host_parser;

int http_parser_callback_on_headers_field(struct http_parser * parser, const char * at, size_t length)
{
	if(((host_parser*)(parser->data))->get_host_flag==0 || ((host_parser*)(parser->data))->host_field_flag==1) return 0;
	if(0==strncasecmp(at, "host",strlen("host")))
	{
		((host_parser*)(parser->data))->host_field_flag = 1;
	}
	return 0;
}

int http_parser_callback_on_headers_value(struct http_parser * parser, const char * at, size_t length)
{	
	if(((host_parser*)(parser->data))->get_host_flag==0 || ((host_parser*)(parser->data))->host_field_flag==0 || ((host_parser*)(parser->data))->host_value_flag==1) return 0;
	if(0<length)
	{
		((host_parser*)(parser->data))->host_value = (char*)malloc(length);
		memcpy(((host_parser*)(parser->data))->host_value, at, length);
		((host_parser*)(parser->data))->host_valuelen = length;
		((host_parser*)(parser->data))->host_value_flag = 1;
	}
	return 0;
}

int http_parser_callback_on_url(struct http_parser * parser, const char * at, size_t length)
{
	((host_parser*)(parser->data))->is_http_flag = 1;
	return 0;
}

int http_parser_callback_on_status(struct http_parser * parser, const char * at, size_t length)
{
	((host_parser*)(parser->data))->is_http_flag = 1;
	return 0;
}

static http_parser_settings http_setting =
{
		.on_message_begin = NULL,
		.on_url = http_parser_callback_on_url,
		.on_status = http_parser_callback_on_status,
		.on_header_field = http_parser_callback_on_headers_field,
		.on_header_value = http_parser_callback_on_headers_value,
		.on_headers_complete = NULL,
		.on_body = NULL,
		.on_message_complete = NULL,
		.on_chunk_header = NULL,
		.on_chunk_complete = NULL
};

int http_host_parser(const char* buf, uint32 buflen, int http_dir, char** host)
{
	//buf前面的空格进行删除处理	
	uint32 offset = 0;
	http_deleteEmptyRow(&offset, (char*)(buf), buflen);
	const char* pbuf = buf+offset;	
	uint32 pbuflen = buflen-offset;
	char* pbuf_temp = (char*)(buf+offset);
	uint32 pbuflen_temp = buflen-offset;
	char* new_pbuf = NULL;
	uint32 new_pbuflen = 0;
	uchar 	method = HTTP_METHOD_UNKNOWN;
	int method_idx = 1, new_flags=0;

	//printf("buf=====================================================\n");	
	//printf("%s\n", buf);
	
	// 为结构体申请内存
	http_parser *parser = (http_parser*)calloc(1, sizeof(http_parser));
	host_parser* host_field = (host_parser*)calloc(1, sizeof(host_parser));
	int rec = -1;
	
	// 初始化解析器
	if(http_dir==DIR_C2S)
	{
		http_parser_init(parser, HTTP_REQUEST);	
		/*如果检测到method往后移动一个空格，不是'/',也不是"http://"，就自动添加一个'/'*/
		if(buflen>HTTP_START_FLAGS_LEN+strlen("http://"))
		{		
			for(method_idx=1;method_idx<=HTTP_METHOD_TRACE;method_idx++)
			{
				if(0==strncasecmp(pbuf,g_http_method[method_idx],strlen(g_http_method[method_idx]))) 
				{
					method = method_idx;	
					break;
				}
			}
			if(method!=HTTP_METHOD_UNKNOWN)
			{
				pbuf_temp = pbuf_temp+strlen(g_http_method[method])+strlen(" ");
				pbuflen_temp -= strlen(g_http_method[method])+strlen(" ");
				if(*pbuf_temp!='/' && 0!=strncasecmp(pbuf_temp, "http://", strlen("http://")))
				{
					new_pbuflen = pbuflen+strlen("/");
					new_pbuf = (char*)malloc(new_pbuflen);
					memcpy(new_pbuf, pbuf, pbuflen-pbuflen_temp);
					memcpy(new_pbuf+pbuflen-pbuflen_temp, "/", strlen("/"));
					memcpy(new_pbuf+pbuflen-pbuflen_temp+strlen("/"), pbuf+pbuflen-pbuflen_temp, pbuflen_temp);
					//pbuf = new_pbuf;
					//pbuflen = new_pbuflen;
					new_flags=1;
				}
			}
		}		
	}
	else
	{
		http_parser_init(parser, HTTP_RESPONSE);	
	}
	parser->data = (void*)host_field;
	
	//获取host内容
	if(host!=NULL)
	{
		((host_parser*)(parser->data))->get_host_flag = 1;		
	}

	size_t parsed=0;
	//执行解析过程
	if(new_flags==0)
	{
		parsed=http_parser_execute(parser, &http_setting, pbuf, (size_t)pbuflen);
	}
	else
	{
		parsed=http_parser_execute(parser, &http_setting, new_pbuf, (size_t)new_pbuflen);
	}
	//printf("buflen: %d; parsed: %d\n", pbuflen, parsed);
	if(((host_parser*)(parser->data))->is_http_flag == 1) 
	{
		rec = 0;
		if(((host_parser*)(parser->data))->get_host_flag == 1)
		{
			if(0<host_field->host_valuelen)
			{
				rec = host_field->host_valuelen;
				*host = memcasemem(pbuf, pbuflen, (const char*)host_field->host_value, host_field->host_valuelen);	
			}						
		}
	}	
	else
	{
		rec = -1;
	}

	if(NULL!=host_field)
	{
		if(NULL!=host_field->host_value)
		{			
			free(host_field->host_value);
			host_field->host_value = NULL;
		}			
		free(host_field);
		host_field = NULL;
	}	
	if(NULL!=parser)
	{				
		free(parser);
		parser = NULL;
	}
	if(NULL!=new_pbuf)
	{				
		free(new_pbuf);
		new_pbuf = NULL;
	}
	return rec;
}

