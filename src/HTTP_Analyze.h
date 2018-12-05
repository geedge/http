#ifndef HTTP_ANALYZE_H_
#define HTTP_ANALYZE_H_

#include "HTTP_Message.h"

#define MAX_UNCOMPLETE_COUNT 		256

typedef struct http_stream
{
	uint32 				create_infor_num;	//data for tcp create stream, not for syn
	int 				http_session_num;
	
	http_parser_t* 		first_link_node;		//主要用于处理流式请求/响应对的响应消息
	http_parser_t*		last_link_node;		//主要用于处理流式请求/响应对的请求消息

	uint32 				uncomplete_count;	//记录当前需要处理的请求/响应的数量
	uint32 				packet_offset;		//已处理数据在当前包的偏移量,毎处理完一个包都要清零

	char*				pbuf;	
	uint32				buflen;
	uint32				reset_count;
#if HTTP_PROXY
	struct streaminfo* p_stream_proxy;
	uchar 				is_proxy;			//callback set_proxy_fstream	
#endif
	uchar 				maybe_http_stream;
	uchar 				res_req;				//正需处理的是请求还是响应
	uchar 				dir;					//单双向标记
	uchar 				is_http_falgs;	
	uchar 				proc_pkt_continue;	
}http_stream;

/*string map func*/
typedef uchar (*STRING_MAP_FUNC)(http_parser_t* a_http, http_stream* a_http_stream, char* value, uint32 valuelen, struct streaminfo *a_tcp,int thread_seq, void *a_packet);
typedef struct string_map_s
{
	const char* 				string;
	uint32 						stringid;
	STRING_MAP_FUNC 			handler;	
}string_map_t;

#ifdef __cplusplus
extern "C" {
#endif

void http_initHttpStream(http_stream**pme, int thread_seq);
void http_releaseHttpStream(http_stream **a_http_stream,struct streaminfo *a_tcp, int thread_seq, void *a_packet);
void http_resetHttpStream(http_stream **ppa_http_stream,struct streaminfo *a_tcp, int thread_seq, void *a_packet);
void http_callPlugin(http_parser_t* cur_http_node, struct streaminfo *a_tcp, int thread_seq, void *a_packet);
int http_getLinkState(http_parser_t *cur_http_node);
void http_resetHttpLinkNode(http_parser_t *cur_node,struct streaminfo *a_tcp, int thread_seq, void *a_packet);
void http_releaseHttpLinkNode(http_stream *a_http_stream,struct streaminfo *a_tcp, int thread_seq, void *a_packet);
uchar http_analyseHttpConnection(http_stream* a_http_stream,struct streaminfo *a_tcp, int thread_seq, void *a_packet);
void http_updatePktOffset(http_parser_t *a_http, http_stream* a_http_stream, struct streaminfo *a_tcp);

#ifdef __cplusplus
}
#endif

#endif 
