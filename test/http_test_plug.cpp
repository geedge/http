#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "cJSON.h"
#include "http.h"
#include "MESA_prof_load.h"
#include <MESA/stream.h>
#include "md5.h"

extern "C" int commit_test_result_json(cJSON *node, const char *name);

static int g_dump_unzip_payload = 0; // make manual check result simpler
static int g_result_count = 1;

struct http_test_ctx
{
	cJSON *json_ctx;
	char *unzip_payload_data;
	long unzip_payload_datalen;
};

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

static void http_test_plug_append_payload(struct http_test_ctx *hplug_ctx, stSessionInfo *session_info)
{
	int append_datalen = hplug_ctx->unzip_payload_datalen + session_info->buflen;
	hplug_ctx->unzip_payload_data = (char *)realloc(hplug_ctx->unzip_payload_data, append_datalen);
	memcpy(hplug_ctx->unzip_payload_data + hplug_ctx->unzip_payload_datalen, session_info->buf, session_info->buflen);
	hplug_ctx->unzip_payload_datalen = append_datalen;
}

static void http_test_plug_commit_payload_md5(struct http_test_ctx *hplug_ctx)
{
	char payload_md5str[33] = {};
	char payload_lenstr[32] = {};

	if ((hplug_ctx->unzip_payload_data != NULL) && (hplug_ctx->unzip_payload_datalen > 0))
	{
		snprintf(payload_lenstr, sizeof(payload_lenstr), "%ld", hplug_ctx->unzip_payload_datalen);
		http_field_add_to_json(hplug_ctx->json_ctx, "unzip_payload_len", payload_lenstr, strlen(payload_lenstr));

		MESA_MD5_sum_str((unsigned char *)hplug_ctx->unzip_payload_data, (unsigned int)hplug_ctx->unzip_payload_datalen, payload_md5str);
		http_field_add_to_json(hplug_ctx->json_ctx, "unzip_payload_md5", payload_md5str, strlen(payload_md5str));

		if (g_dump_unzip_payload)
		{
			FILE *fp = fopen(payload_md5str, "w+");
			if (fp)
			{
				fwrite(hplug_ctx->unzip_payload_data, hplug_ctx->unzip_payload_datalen, 1, fp);
				fclose(fp);
			}
		}
	}
}

extern "C" unsigned char HTTP_TEST_PLUG_ENTRY(stSessionInfo *session_info, void **pme, int thread_seq, struct streaminfo *a_tcp, void *a_packet)
{
    assert(NULL != session_info || pme != NULL);    


	struct http_test_ctx *hplug_ctx;
    if (session_info->session_state & SESSION_STATE_PENDING)
    {
        if (*pme == NULL)
        {
			hplug_ctx = (struct http_test_ctx *)calloc(1, sizeof(struct http_test_ctx));
            hplug_ctx->json_ctx = cJSON_CreateObject( );
            cJSON_AddStringToObject(hplug_ctx->json_ctx, "Tuple4", printaddr(&a_tcp->addr, a_tcp->threadnum));
			*pme = (void *)hplug_ctx;
        }
    }

	hplug_ctx = (struct http_test_ctx *)(*pme);
	cJSON *ctx = hplug_ctx->json_ctx;

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
		case HTTP_UNGZIP_CONTENT:
			http_test_plug_append_payload(hplug_ctx, session_info);
			break;
		default:
			break;
	}

    if(session_info->session_state&SESSION_STATE_CLOSE)
    {
            if(hplug_ctx)
            {
				http_test_plug_commit_payload_md5(hplug_ctx);
				char result_name[16] = "";
				sprintf(result_name, "HTTP_RESULT_%d", g_result_count);
				commit_test_result_json(hplug_ctx->json_ctx, result_name);
				g_result_count += 1;
				if (hplug_ctx->unzip_payload_data)
				{
					free(hplug_ctx->unzip_payload_data);
				}
				free(hplug_ctx);
			}
            *pme = NULL;
            return PROT_STATE_DROPME;

    }

    return PROT_STATE_GIVEME;

}

extern "C" int HTTP_TEST_PLUG_INIT()
{
	MESA_load_profile_int_def("./conf/http/http_test_plug.conf", "main", "dump_unzip_payload", &g_dump_unzip_payload, 0);
	return 0;
}

extern "C" void HTTP_TEST_PLUG_DESTROY(void)
{
    return ;
}/*CHAR_DESTRORY*/



