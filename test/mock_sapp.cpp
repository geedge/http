#include <stdlib.h>

#include "stream.h"

void free_tcp_proxy_stream(struct streaminfo *pstream,struct streaminfo *pProxy)
{
	return;
}

void set_proxy_fstream(struct streaminfo *pstream,struct streaminfo *pProxy)
{
	return;
}
void *dictator_malloc(int thread_seq,size_t size)
{
	return malloc(size);
}
void dictator_free(int thread_seq,void *pbuf)
{
	free(pbuf);
}

void *dictator_realloc(int thread_seq, void* pbuf, size_t size)
{
	return realloc(pbuf, size);
}

char PROT_PROCESS(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	return 0;
}

int get_thread_count(void)
{
	return 0;
}

const void *project_req_get_struct(const struct streaminfo *stream, int project_req_id)
{
	return NULL;
}

const char *printaddr (const struct layer_addr *paddrinfo, int threadindex)
{
	return NULL;
}

int project_producer_register(const char *project_req_name, const char *project_req_val_type, project_req_free_t *free_cb)
{
	return 0;
}

int project_req_add_struct(struct streaminfo *stream, int project_req_id, const void *project_req_value)
{
	return 0;
}

int deal_tcp_in_proxy_stream(struct streaminfo *a_tcp,void * a_packet,struct streaminfo *pProxy)
{
	return 0;
}