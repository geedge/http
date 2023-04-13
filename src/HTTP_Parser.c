#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <math.h>
#include <http.h>
#include <stream.h>
#include "inc/http_parser.h"
#include "http.h"
#include "HTTP_Common.h"
#include "HTTP_Message_Header.h"

extern const char* g_http_method[];

struct http_header_field
{
	int field_flag;
	int length;
	char *value;
};

struct http_header_parse
{	
	char is_http_flag;
	char pad[7];
	long long http_field_flag;
	struct http_header_field host;
	struct http_header_field uri;	
	struct http_header_field url;
};


int http_parser_callback_on_headers_field(struct http_parser * parser, const char * at, size_t length)
{
	if(at==NULL || length==0 || parser==NULL || parser->data==NULL)
	{
		return 0;
	}

 	struct http_header_parse *header_parser=(struct http_header_parse *)(parser->data);
	header_parser->is_http_flag=1;

	if((header_parser->host.field_flag==0) && (length==4) &&  (0==strncasecmp(at, "host", 4)))
	{
		header_parser->host.field_flag=1;
		header_parser->http_field_flag=HTTP_HOST;
	}
	
	return 0;
}

int http_parser_callback_on_headers_value(struct http_parser * parser, const char * at, size_t length)
{
	if(at==NULL || length==0 || parser==NULL || parser->data==NULL)
	{
		return 0;
	}

 	struct http_header_parse *header_parser=(struct http_header_parse *)(parser->data);
	header_parser->is_http_flag=1;

	switch(header_parser->http_field_flag)
	{
		case	HTTP_HOST:
			header_parser->host.value=(char*)malloc(length);
			memcpy(header_parser->host.value, at, length);
			header_parser->host.length=length;
			header_parser->http_field_flag=HTTP_INTEREST_KEY;
			break;
		default:
			break;
	}

	return 0;
}

int http_parser_callback_on_url(struct http_parser * parser, const char * at, size_t length)
{
	if(at==NULL || length==0 || parser==NULL || parser->data==NULL)
	{
		return 0;
	}
	
 	struct http_header_parse *header_parser=(struct http_header_parse *)(parser->data);
	header_parser->is_http_flag=1;

	if(header_parser->uri.field_flag==0)
	{
		header_parser->uri.field_flag=1;
		header_parser->uri.value=(char*)malloc(length);
		memcpy(header_parser->uri.value, at, length);
		header_parser->uri.length=length;
		header_parser->http_field_flag=HTTP_INTEREST_KEY;
	}
	
	return 0;
}

int http_parser_callback_on_status(struct http_parser * parser, const char * at, size_t length)
{
	if(at==NULL || length<=0 || parser==NULL || parser->data==NULL)
	{
		return 0;
	}

 	struct http_header_parse *header_parser=(struct http_header_parse *)(parser->data);
	header_parser->is_http_flag=1;
	
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

void *http_field_parser(const char* buf, uint32 buflen, int http_dir)
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
	struct http_parser http_parse;
	memset(&http_parse, 0, sizeof(http_parse));
	
	if(pbuflen<4) //g_http_method min bytes=3; pbuflen_temp=pbuflen
	{
		return NULL;
	}
	
	// 初始化解析器
	if(http_dir==DIR_C2S)
	{
		http_parser_init(&http_parse, HTTP_REQUEST);	
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
		http_parser_init(&http_parse, HTTP_RESPONSE);	
	}

	struct http_header_parse *http_header=(struct http_header_parse *)calloc(1, sizeof(struct http_header_parse));
	http_parse.data=(void*)(http_header);

	//执行解析过程
	if(new_flags==0)
	{
		http_parser_execute(&http_parse, &http_setting, pbuf, (size_t)pbuflen);
	}
	else
	{
		http_parser_execute(&http_parse, &http_setting, new_pbuf, (size_t)new_pbuflen);
	}
	
	if(NULL!=new_pbuf)
	{				
		free(new_pbuf);
		new_pbuf = NULL;
	}

	if(http_header->is_http_flag==0) 
	{
		free(http_header);
		http_header=NULL;
		return NULL;
	}

	if(http_header->host.field_flag==1 && http_header->host.length>0 && http_header->host.value!=NULL)
	{
		char *p_host=memcasemem(pbuf, pbuflen, (const char*)http_header->host.value, http_header->host.length);
		free(http_header->host.value);
		http_header->host.value=p_host;
	}
	
	return (void *)(http_header);
}

void http_free_filed_result(void *result)
{
	if(result==NULL)
	{
		return ;
	}

	struct http_header_parse *http_header=(struct http_header_parse *)result;
	if(http_header->uri.value!=NULL)
	{
		free(http_header->uri.value);
		http_header->uri.value=NULL;
	}

	if(http_header->url.value!=NULL)
	{
		free(http_header->url.value);
		http_header->url.value=NULL;
	}

	free(result);
	result=NULL;
}

int http_get_filed_result(void *result, long long field_flag, char **field_value)
{
	if(result==NULL)
	{
		return 0;
	}
	
	struct http_header_parse *http_header=(struct http_header_parse *)result;
	
	switch(field_flag)
	{
		case	HTTP_HOST:
			if(http_header->host.field_flag==0 || http_header->host.value==NULL || http_header->host.length<=0)
			{
				break;
			}
			*field_value=http_header->host.value;
			return http_header->host.length;
		case	HTTP_MESSAGE_URL:
			if(http_header->host.field_flag==0 || http_header->host.value==NULL || http_header->host.length<=0)
			{
				break;
			}
			
			http_header->url.length=http_header->host.length;
			http_header->url.value=(char*)malloc(http_header->url.length);
			memcpy(http_header->url.value, http_header->host.value, http_header->host.length);

			if(http_header->uri.field_flag==0 || http_header->uri.value==NULL || http_header->uri.length<=0)
			{
				http_header->url.value=(char*)realloc(http_header->url.value, http_header->url.length+1);
				http_header->url.value[http_header->url.length]='/';
				http_header->url.length+=1;
			}
			else
			{
				if(http_header->uri.value[0]=='/')
				{				
					http_header->url.value=(char*)realloc(http_header->url.value, http_header->url.length+http_header->uri.length);
				}
				else
				{					
					http_header->url.value=(char*)realloc(http_header->url.value, http_header->url.length+http_header->uri.length+1);
					http_header->url.value[http_header->url.length]='/';
					http_header->url.length+=1;
				}
				
				memcpy(http_header->url.value+http_header->url.length, http_header->uri.value, http_header->uri.length);
				http_header->url.length+=http_header->uri.length;
			}
			
			*field_value=http_header->url.value;
			return http_header->url.length;
		default:
			break;
	}

	return 0;
}

int http_host_parser(const char* buf, uint32 buflen, int http_dir, char** host)
{
	struct http_header_parse *http_header=(struct http_header_parse *)http_field_parser(buf, buflen, http_dir);
	if(http_header==NULL)
	{
		return -1;
	}

	int length=0;
	
	if(http_header->is_http_flag==1) 
	{
		if(http_header->host.field_flag==1 && http_header->host.length>0 && http_header->host.value!=NULL)
		{
			*host=http_header->host.value;			
			length=http_header->host.length;
		}
	}

	http_free_filed_result((void *)http_header);  //no need free host, *host=buf+N

	return length;
}

