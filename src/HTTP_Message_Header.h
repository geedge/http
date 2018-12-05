#ifndef HTTP_MESSAGE_HEADER_H_
#define HTTP_MESSAGE_HEADER_H_

#include "HTTP_Message.h"
#include "HTTP_Analyze.h"

#define HTTP_START_FLAGS_LEN 			9
#define HTTP_RESPONSE_CODE_LEN 		3
#define HTTP_VERSIONS_LEN 				8

/*positioning a completeLine*/
#define	HTTP_OLD_MEM					0
#define	HTTP_MALLOC_MEM				1
#define	HTTP_NO_MEM					2

typedef enum
{
	HTTP_VERSIONS_UNKNOWN=9,
	HTTP_09,
	HTTP_10,
	HTTP_11
}http_versions;


#ifdef __cplusplus
extern "C" {
#endif

void http_resetResponseSpace(http_parser_t *a_http, int thread_seq);
char http_judgeHttpMethod(uchar *method, char *data, uchar curdir);
void http_initHttpConnection(http_stream *a_http_stream, int thread_seq, struct streaminfo *a_tcp, void *a_packet);
uchar http_analyseHttpReqResHeader(http_parser_t*a_http, http_stream *a_http_stream,
										  struct streaminfo *a_tcp, int thread_seq, void *a_packet);
void http_inintRegionParam(http_parser_t *cur_node, int thread_seq);
void http_reseaseHttpInfor(http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq,  void *a_packet);
uchar http_analyseHttpProxy(http_parser_t *a_http,  http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet);
uchar http_processHttpProxy(http_parser_t *a_http, http_stream *a_http_stream, struct streaminfo *a_tcp,int thread_seq,void *a_packet);


#ifdef __cplusplus
}
#endif

#endif /* HTTP_HEADER_H_ */
