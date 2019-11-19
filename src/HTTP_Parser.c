#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <math.h>
#include <http.h>
#include <stream.h>
#include <http_parser.h>
#include "HTTP_Common.h"

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

	printf("buf=====================================================\n");	
	printf("%s\n", buf);
	
	// 为结构体申请内存
	http_parser *parser = (http_parser*)calloc(1, sizeof(http_parser));
	host_parser* host_field = (host_parser*)calloc(1, sizeof(host_parser));
	int rec = -1;
	
	// 初始化解析器
	if(http_dir==DIR_C2S)
	{
		http_parser_init(parser, HTTP_REQUEST);		
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
	
	//执行解析过程
	size_t parsed = http_parser_execute(parser, &http_setting, pbuf, (size_t)pbuflen);
	printf("buflen: %d; parsed: %d\n", pbuflen, parsed);
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
	return rec;
}

/*http_host_parser_test 协议识别正常,host解析正常*/
static const char * http_request =
	"POST /gen_204 HTTP/1.1\r\n"
	"Host: www.google.com\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"Origin: https://www.google.com\r\n"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\r\n"
	"Content-Type: text/plain;charset=UTF-8\r\n"
	"Accept: */*\r\n"
	"X-Client-Data: CJG2yQEIorbJAQjEtskBCKmdygEI2J3KAQjZncoBCKijygEY+aXKAQ==\r\n"
	"Referer: https://www.google.com/\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7\r\n";

/*http_host_parser_test 协议识别正常,无host字段*/
static const char * http_request_no_host =
	"POST /gen_204 HTTP/1.1\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"Origin: https://www.google.com\r\n"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\r\n"
	"Content-Type: text/plain;charset=UTF-8\r\n"
	"Accept: */*\r\n"
	"X-Client-Data: CJG2yQEIorbJAQjEtskBCKmdygEI2J3KAQjZncoBCKijygEY+aXKAQ==\r\n"
	"Referer: https://www.google.com/\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7\r\n";

/*http_host_parser_test 协议识别正常*/
static const char * http_response =	
	"HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nVary: Accept-Encoding\r\nContent-Type: text/javascript; charset=UTF-8\r\nContent-Length: 4064\r\nAge: 8963\r\n";

/*http_host_parser_test 协议识别正常，host解析失败，不支持\r*/
static const char * http_request_CR =
	"POST /gen_204 HTTP/1.1\r"
	"Host: www.google.com\r"
	"Connection: close\r"
	"Content-Length: 0\r"
	"Origin: https://www.google.com\r"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\r\n"
	"Content-Type: text/plain;charset=UTF-8\r";

/*http_host_parser_test 协议识别正常，解析失败*/
static const char * http_reponse_CR =
	"HTTP/1.1 200 OK\r"
	"Accept-Ranges: bytes\r"
	"Vary: Accept-Encoding\r\nContent-Type: text/javascript; charset=UTF-8\r\nContent-Length: 4064\r\nAge: 8963\r\n";
	
/*/*http_host_parser_test 协议识别情况正常，但是host为close，不支持此情况*/
static const char * http_request_LF =
	"POST /gen_204 HTTP/1.1\n"
	"host: \n"
	"Connection: close\n"
	"Content-Length: 0\n"
	"Origin: https://www.google.com\n";

/*http_host_parser_test 协议识别正常,host解析正常*/
static const char * http_request_SPACE =
	"POST /gen_204 HTTP/1.1\r\n"
	"HOST:          www.       google.com       \r\n";

/*http_host_parser_test 协议识别正常,host解析正常*/
static const char * http_request_incpomplete =
	"POST /gen_204 HTTP/1.1\n"
	"Host: www.googl";

/*http_host_parser_test 协议识别正常,host解析正常*/
static const char * http_request_with_body =
	"POST /gen_204 HTTP/1.1\r\n"
	"Host: www.google.com\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"Origin: https://www.google.com\r\n"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\r\n"
	"Content-Type: text/plain;charset=UTF-8\r\n"
	"Accept: */*\r\n"
	"X-Client-Data: CJG2yQEIorbJAQjEtskBCKmdygEI2J3KAQjZncoBCKijygEY+aXKAQ==\r\n"
	"Referer: https://www.google.com/\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
	"\r\n"
	"abcdjhjkhdlaks";

/*http_host_parser_test 协议识别正常,host解析正常*/
static const char * http_request_space_start =
	"\r \nPOST /gen_204 HTTP/1.1\r\n"
	"Host: www.google.com\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"Origin: https://www.google.com\r\n"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\r\n"
	"Content-Type: text/plain;charset=UTF-8\r\n"
	"Accept: */*\r\n"
	"X-Client-Data: CJG2yQEIorbJAQjEtskBCKmdygEI2J3KAQjZncoBCKijygEY+aXKAQ==\r\n"
	"Referer: https://www.google.com/\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
	"\r\n"
	"abcdjhjkhdlaks";


void http_host_parser_test(const char* test_buf, int test_buf_dir)
{
	char* host = NULL;
	uint32 hostlen = 0;
	int    rec = -1;

	/*判断是否是http协议数据*/	
	rec = http_host_parser((const char*)test_buf, (uint32)strlen(test_buf), test_buf_dir, NULL);
	if(-1==rec)
	{
		printf("not http data\n");
	}
	else if(0==rec)
	{
		printf("is http data\n");
	}

	/*判断是否是http协议数据，并获取host字段内容*/	
	rec = http_host_parser((const char*)test_buf, (uint32)strlen(test_buf), test_buf_dir, &host);
	if(-1==rec)
	{
		printf("not http data\n");
	}
	else if(0<=rec)
	{
		printf("is http data\n");
		if(0<rec)
		{
			printf("HOST: %.*s\n", (int)rec, host);
		}		
	}
	printf("http_host_parser_test end!!!!!!!!!!!!!!!!!!!!!!!!!\n\n"); 
}

void http_test()
{
	/*http_host_parser_test测试*/	
	/*
	http_host_parser_test(http_request, DIR_C2S);	
	http_host_parser_test(http_request_no_host, DIR_C2S);	
	http_host_parser_test(http_response, DIR_S2C);
	http_host_parser_test(http_request_CR, DIR_C2S);
	http_host_parser_test(http_reponse_CR, DIR_S2C);
	http_host_parser_test(http_request_LF, DIR_C2S);	
	http_host_parser_test(http_request_SPACE, DIR_C2S);
	http_host_parser_test(http_request_incpomplete, DIR_C2S);
	http_host_parser_test(http_request_with_body, DIR_C2S);
	http_host_parser_test(http_request_space_start, DIR_C2S);
	*/
}
