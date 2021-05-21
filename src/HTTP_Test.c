#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <math.h>
#include <stream.h>
#include <http_parser.h>
#include "HTTP_Common.h"
#include "http.h"


/*http_host_parser_test 协议识别正常,host解析正常*/
static const char * http_request =
	/*
	"POST /gen_204 HTTP/1.1\r\n"
	"Host: www.google.com\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"Origin: https://www.google.com\r\n"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\r\n"
	"Content-Type: text/plain;charset=UTF-8\r\n"
	"X-Client-Data: CJG2yQEIorbJAQjEtskBCKmdygEI2J3KAQjZncoBCKijygEY+aXKAQ==\r\n"
	"Referer: https://www.google.com/\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7\r\n";
	*/

	"GET sampleFile.html HTTP/1.1\r\nUser-Agent:xPTS/2.0\r\n"; //http_parser解析失败，uri以/开始


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
	//"HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nVary: Accept-Encoding\r\nContent-Type: text/javascript; charset=UTF-8\r\nContent-Length: 4064\r\nAge: 8963\r\n";
	"HTTP/1.1 200 OK\r\nDate: Mon, 25 Oct 2004 23:59:59 GMT\r\nContent-Type: text/html\r\nServer: xPTS/2.0 (Red.Hat.Linux)";

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
	//http_host_parser_test(http_request, DIR_C2S);		
	//http_host_parser_test(http_request_no_host, DIR_C2S);	
	//http_host_parser_test(http_response, DIR_S2C);
	//http_host_parser_test(http_request_CR, DIR_C2S);
	//http_host_parser_test(http_reponse_CR, DIR_S2C);
	//http_host_parser_test(http_request_LF, DIR_C2S);	
	//http_host_parser_test(http_request_SPACE, DIR_C2S);
	//http_host_parser_test(http_request_incpomplete, DIR_C2S);
	//http_host_parser_test(http_request_with_body, DIR_C2S);
	//http_host_parser_test(http_request_space_start, DIR_C2S);	
}
