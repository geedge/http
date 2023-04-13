#include <gtest/gtest.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "http.h"

TEST(url_decode, chinese)
{
	const char *input = "%A9%E4%B8%8B%E8%B6%B3%E7%90%83%2CRB%E8%8E%B1%E6%AF%94%E9%94%A1%2C%E5%BC%97%E8%B5%96%E5%A0%A1%2C%E6%96%AF%E6%89%98%E5%85%8B%E5%9F%8E%2C%E4%BC%AF%E6%81%A9%E8%8C%85%E6%96%AF%2C%E9%97%A8%E5%85%B4%2C%E8%90%A8%E7%B4%A2%E6%B4%9B%2C%E8%B6%B3%E7%90%83%2C%E7%9A%87%E5%AE%B6%E7%A4%BE%E4%BC%9A%2C%E8%8B%B1%E8%B6%85%2C%E6%9B%BC%E5%BD%BB%E6%96%AF%E7%89%B9%E8%81%94%2C%E5%9F%83%E7%93%A6%E5%B0%94%2C%E8%A5%BF%E4%B9%99%2C%E6%B3%95%E5%85%B0%E5%85%8B%E7%A6%8F%2C%E6%8B%89%E6%96%AF%E5%B8%95%E5%B0%94%E9%A9%AC%E6%96%AF%2C%E6%B2%99%E5%B0%94%E5%85%8B%2C%E7%9A%87%E5%AE%B6%E9%A9%AC%E5%BE%B7%E9%87%8C%2C%E7%83%AD%E9%82%A3%E4%BA%9A%2C%E7%BE%8E%E5%9B%A0%E8%8C%A8%2C%E5%B7%B4%E8%90%A8%2C%E8%8E%B1%E6%AF%94%E9%94%A1%E7%BA%A2%E7%89%9B%2C%E6%96%AF%E5%9B%BE%E5%8A%A0%E7%89%B9%2CCBA%2C%E5%A5%A5%E8%90%A8%E8%8B%8F%E7%BA%B3%2C%E6%8B%9C%E4%BB%81%E6%85%95%E5%B0%BC%E9%BB%91%2C%E8%B5%AB%E7%BD%97%E7%BA%B3%2C%E6%81%A9%E6%B3%A2%E5%88%A9%2C%E6%AF%95%E5%B0%94%E5%B7%B4%E9%84%82%2C%E5%A1%9E%E5%B0%94%E5%A1%94%2C%E7%9A%87%E5%AE%B6%E8%B4%9D%E8%92%82%E6%96%AF%2C%E6%B2%8";
    int len = strlen(input);
    char *output = (char*)calloc(strlen(input)+1, 1);
    memcpy(output, input, strlen(input));

	http_url_decode(output, &len);
	
	EXPECT_EQ(len, 347);
	EXPECT_EQ(strlen(output), 346);
	
	free(output);

}

TEST(url_decode, no_result)
{
	const char *input = "76%253AB%257C1811%253AD%257C1875%253AB%257C1876%253AB%257C1877%253AB%257C1879%253AB%257C2041%253AA%257C2074%253AB%257C2075%253AB%257C2122%253AB%257C2176%253AB%257C2287%253AC%257C2319%253AB%257C2906%253AB%257C3025%253AP%257C3200%253AG%257C3201%253AD%257C3204%253AC%257C3205%253AB%257C3256%253AD%257C3270%253AB%257C3502%253AR%257C3600%253AB%257C3661%253AA%257C3759%253AC%257C3853%253AC%257C3879%253AK%257C3906%253AD%257C3940%253AD%257C4030%253AB%257C4072%253AC%257C4079%253AB%257C4081%253AC%257C4099%253AC%257C4105%253AL%257C4163%253AC%257C4320%253AA%257C4328%253AE%257C4330%253AD%257C4357%253AC%257C4361%253AB%257C4428%253AA%257C4447%253AC%257C4449%253AB%257C4450%253AB%257C4453%253AE%257C4454%253AD%257C4531%253AA%257C4551%253AF%257C4576%253AH%257C4577%253AD%257C4589%253AB%257C4612%253AE%257C4669%253AB%257C4702%253AB%257C4773%253AB%257C4827%253AA%257C4887%253AC%257C4920%253AC%257C4921%253AA%257C4935%253AB%257C4937%253AC%257C4957%253AA%257C5001%253AB%257C5020%253AC%257C5183%253AB%257C5547%253AB%257C5643%253AA%257C5889%2";
    int len = strlen(input);
    char *output = (char*)calloc(strlen(input)+1, 1);
    memcpy(output, input, strlen(input));

	http_url_decode(output, &len);
	
	EXPECT_EQ(len, 753);
	EXPECT_EQ(strlen(output), 752);
	
	free(output);

}

#define DIR_C2S 			0x01
#define DIR_S2C 			0x02

TEST(http_host_parser, http_request)
{

/*http_host_parser_test 协议识别正常,host解析正常*/
	const char * test_buff =
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

	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_C2S, &host);
	EXPECT_EQ(rec,0);
	EXPECT_TRUE(host==NULL);
}

TEST(http_host_parser, http_request_no_host)
{
/*http_host_parser_test 协议识别正常,无host字段*/
	const char * test_buff =
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

	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_C2S, &host);
	EXPECT_EQ(rec,0);
	EXPECT_TRUE(host==NULL);
}


TEST(http_host_parser, http_response)
{
/*http_host_parser_test 协议识别正常*/
    const char * test_buff =	
	//"HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nVary: Accept-Encoding\r\nContent-Type: text/javascript; charset=UTF-8\r\nContent-Length: 4064\r\nAge: 8963\r\n";
	"HTTP/1.1 200 OK\r\nDate: Mon, 25 Oct 2004 23:59:59 GMT\r\nContent-Type: text/html\r\nServer: xPTS/2.0 (Red.Hat.Linux)";
	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_S2C, &host);
	EXPECT_EQ(rec,0);
	EXPECT_TRUE(host==NULL);
}

TEST(http_host_parser, http_request_CR)
{
/*http_host_parser_test 协议识别正常，host解析失败，不支持\r*/
static const char * test_buff =
	"POST /gen_204 HTTP/1.1\r"
	"Host: www.google.com\r"
	"Connection: close\r"
	"Content-Length: 0\r"
	"Origin: https://www.google.com\r"
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36\r\n"
	"Content-Type: text/plain;charset=UTF-8\r";
	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_C2S, &host);
	EXPECT_EQ(rec,0);
	EXPECT_TRUE(host==NULL);
}

TEST(http_host_parser, http_reponse_CR)
{
/*http_host_parser_test 协议识别正常，解析失败*/
 const char * test_buff =
	"HTTP/1.1 200 OK\r"
	"Accept-Ranges: bytes\r"
	"Vary: Accept-Encoding\r\nContent-Type: text/javascript; charset=UTF-8\r\nContent-Length: 4064\r\nAge: 8963\r\n";

	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_S2C, &host);
	EXPECT_EQ(rec,0);
	EXPECT_TRUE(host==NULL);
}

TEST(http_host_parser, http_request_LF)
{
/*/*http_host_parser_test 协议识别情况正常，但是host为close，不支持此情况*/
	const char * test_buff =
	"POST /gen_204 HTTP/1.1\n"
	"host: \n"
	"Connection: close\n"
	"Content-Length: 0\n"
	"Origin: https://www.google.com\n";
	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_C2S, &host);
	EXPECT_EQ(rec,5);
	EXPECT_EQ(memcmp(host, "close", rec),0);
}



TEST(http_host_parser, http_request_SPACE)
{
/*http_host_parser_test 协议识别正常,host解析正常*/
const char * test_buff =
	"POST /gen_204 HTTP/1.1\r\n"
	"HOST:          www.       google.com       \r\n";
	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_C2S, &host);
	EXPECT_EQ(rec,28);
	EXPECT_EQ(memcmp(host, "www.       google.com       \r\n", rec),0);
}

TEST(http_host_parser, http_request_incpomplete)
{
/*http_host_parser_test 协议识别正常,host解析正常*/
  const char * test_buff =
	"POST /gen_204 HTTP/1.1\n"
	"Host: www.googl";
	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_C2S, &host);
	EXPECT_EQ(rec,9);
	EXPECT_EQ(memcmp(host, "www.googl", rec),0);
}

TEST(http_host_parser, http_request_with_body)
{
/*http_host_parser_test 协议识别正常,host解析正常*/
 	const char * test_buff =
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
	
	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_C2S, &host);
	EXPECT_EQ(rec,14);
	EXPECT_EQ(memcmp(host, "www.google.com\r\n", rec),0);
}

TEST(http_host_parser, http_request_space_start)
{
/*http_host_parser_test 协议识别正常,host解析正常*/
	 const char * test_buff =
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

	char* host = NULL;
	int rec = http_host_parser((const char*)test_buff, (uint32)strlen(test_buff), DIR_C2S, &host);
	EXPECT_EQ(rec,14);
	EXPECT_EQ(memcmp(host, "www.google.com\r\n", rec),0);
}



int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}
