#ifndef HTTP_MESSAGE_REGION_H_
#define HTTP_MESSAGE_REGION_H_

#include "HTTP_Message.h"
#include "HTTP_Analyze.h"

#define HTTP_MAX_UINT64_LEN 			64

#ifdef __cplusplus
extern "C" {
#endif

uchar http_findAndDoWithRegion(http_parser_t* a_http, http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet);
uchar http_doWithDefaultRegion(http_parser_t* a_http, http_stream *a_http_stream,char* value, uint32 valuelen, 
									struct streaminfo *a_tcp, int thread_seq, void *a_packet);
uchar http_outPutUrl(http_parser_t *cur_http_node, struct streaminfo *a_tcp, int thread_seq, void *a_packet);


#ifdef __cplusplus
}
#endif

#endif 
