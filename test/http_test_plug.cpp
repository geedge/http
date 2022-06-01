#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "cJSON.h"
#include "http.h"
#include "MESA_prof_load.h"
#include <MESA/stream.h>

extern "C" int commit_test_result_json(cJSON *node, const char *name);

static int g_result_count = 1;

int check_field(char *src, int src_len, char *dst, int dst_len)
{
	if(src==NULL || dst==NULL || src_len==0 || dst_len==0 || src_len!=dst_len)
	{
		assert(0);
	}

	assert(!memcmp(src, dst, src_len));

	return 0;
}

int http_field_add_to_json(cJSON *object, const char *name, char *value, char length)
{
	if(value!=NULL && length>0)
	{
		char *tmp=(char *)calloc(1, length+1);
		memcpy(tmp, value, length);
		cJSON_AddStringToObject(object, name, tmp);
		free(tmp);
		tmp=NULL;
	}
	
	return 0;
}
	
extern "C" unsigned char HTTP_TEST_PLUG_ENTRY(stSessionInfo *session_info, void **pme, int thread_seq, struct streaminfo *a_tcp, void *a_packet)
{
    assert(NULL != session_info || pme != NULL);

    cJSON *ctx = (cJSON *)*pme;

    if (session_info->session_state & SESSION_STATE_PENDING)
    {
        if (*pme == NULL)
        {
            ctx = cJSON_CreateObject();
            *pme = (void *)ctx;
            cJSON_AddStringToObject(ctx, "Tuple4", printaddr(&a_tcp->addr, a_tcp->threadnum));
        }
    }

	int length=0;
	char *url=NULL, *host=NULL;
	void *parser_result=NULL;
	
    switch (session_info->prot_flag)
    {
    	case	HTTP_URI:
			http_field_add_to_json(ctx, "http_uri", (char *)session_info->buf, session_info->buflen);
			break;
    	case	HTTP_HOST:
			length=http_host_parser((const char *)a_tcp->ptcpdetail->pdata, a_tcp->ptcpdetail->datalen, a_tcp->curdir, &host);
			check_field((char *)session_info->buf, session_info->buflen, host, length);

			parser_result=http_field_parser((const char *)a_tcp->ptcpdetail->pdata, a_tcp->ptcpdetail->datalen, a_tcp->curdir);
			length=http_get_filed_result(parser_result, HTTP_HOST, &host);
			check_field((char *)session_info->buf, session_info->buflen, host, length);
			
			http_field_add_to_json(ctx, "http_host", host, length);			
			http_free_filed_result(parser_result);
			break;
		case	HTTP_MESSAGE_URL:
			parser_result=http_field_parser((const char *)a_tcp->ptcpdetail->pdata, a_tcp->ptcpdetail->datalen, a_tcp->curdir);
			length=http_get_filed_result(parser_result, HTTP_MESSAGE_URL, &url);
			check_field((char *)session_info->buf, session_info->buflen, url, length);
				
			http_field_add_to_json(ctx, "http_url", url, length);			
			http_free_filed_result(parser_result);
			break;
	    default:
	        break;
    }

    if(session_info->session_state&SESSION_STATE_CLOSE)
    {
            if(ctx)
            {
                char result_name[16]="";
                sprintf(result_name,"HTTP_RESULT_%d", g_result_count);
                commit_test_result_json(ctx, result_name);
                g_result_count+=1;
            }
            *pme = NULL;
            return PROT_STATE_DROPME;

    }

    return PROT_STATE_GIVEME;

}

extern "C" int HTTP_TEST_PLUG_INIT()
{
    return 0;
}

extern "C" void HTTP_TEST_PLUG_DESTROY(void)
{
    return ;
}/*CHAR_DESTRORY*/



