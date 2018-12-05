#ifndef HTTP_MESSAGE_ENTRY_H_
#define HTTP_MESSAGE_ENTRY_H_

#include "HTTP_Analyze.h"
#include "HTTP_Message.h"

#ifdef __cplusplus
extern "C" {
#endif


uchar http_findAndDoWithEntity(uchar *mgs_status, http_parser_t* a_http, http_stream* a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet);
#ifdef __cplusplus
}
#endif

#endif
