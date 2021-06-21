#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "HTTP_Message.h"
#include "HTTP_Message_Header.h"
#include "HTTP_Common.h"
#include "HTTP_Message_Region.h"
#include "HTTP_Message_Entry.h"
#include "HTTP_Analyze.h"
#include "MESA_handle_logger.h"
#include "base64.h"
#include "field_stat.h"


extern http_prog_runtime_parameter_t g_http_prog_para;

/**********************************************************
 * ¹¦ÄÜ£º³õÊ¼»¯Óò´¦Àí²ÎÊý¡£
 * a_http:httpÁ÷»·¾³¡£
***********************************************************/
void http_inintRegionParam(http_parser_t *cur_node, int thread_seq)
{	
	cur_node->poneline_data = NULL;
	cur_node->poneline_datalen = 0;
	http_freeBuf(thread_seq, &(cur_node->pbuf), &(cur_node->buflen));	
}

void http_initHttpCommonInfor( http_parser_t *a_http, int thread_seq)
{
	if(NULL==a_http)		return;
	
	http_inintRegionParam(a_http, thread_seq);
	FLAG_CLEAR(a_http->flag, HTTP_FLAG_CONNECT_CLOSE);
	a_http->chunk_state = HTTP_CHUNK_STATE_UNKONWN;
	FLAG_CLEAR(a_http->flag, HTTP_FLAG_TRANS_LEN);
	a_http->mgs_status = HTTP_RETURN_GIVEME;	
	a_http->interested_reg_mask = HTTP_INTEREST_KEY_MASK;	
	//a_http->processed_offset = 0;	
	a_http->packet_entity_len = 0;
	a_http->acc_cont_length = 0;

	if(a_http->ungzip_handle!=NULL)
	{
		docanalyze_endstream(a_http->ungzip_handle);
		a_http->ungzip_handle = NULL;
	}
	
	/*http_parser*/
	a_http->parser.http_state = HTTP_STATE_UNKNOWN;		
	a_http->parser.cont_encoding = HTTP_CONT_ENCOD_UNKNOWN;
	a_http->parser.trans_encoding = HTTP_TRANS_ENCOD_UNKNOWN;	
	a_http->parser.cont_length = 0;  	
	if(a_http->parser.cont_range!=NULL)
	{
		dictator_free(thread_seq, a_http->parser.cont_range);
		a_http->parser.cont_range = NULL;
	}	
	return;
}
 
 /**********************************************************
  * ¹¦ÄÜ£ºÏìÓ¦ÏûÏ¢µ½À´Ê±£¬Çå³ý¶ÔÓ¦µÄÇëÇóÏûÏ¢ÐÅÏ¢¡£
  * a_http:µ±Ç°½Úµã¡£
  **********************************************************/
 void http_resetResponseSpace(http_parser_t *a_http, int thread_seq)
 {	 
	 if(NULL==a_http)	 return;	 
	 http_initHttpCommonInfor(a_http, thread_seq);
	 return;
 }/*http_clearHttpInfor*/
 
 void http_setSessionSeq(http_parser_t *cur_http_node,	http_stream* a_http_stream)
 {
	 /*20160527 cal http session seq only when http session ok*/
	 if(cur_http_node->parser.http_session_seq==0)
	 {
		 if(-1!=a_http_stream->http_session_num)
		 {
			 a_http_stream->http_session_num++;
		 }	 
		 cur_http_node->parser.http_session_seq = a_http_stream->http_session_num;
	 }	 
 }
 /**********************************************************
  * ¹¦ÄÜ£º³õÊ¼»¯µÚÒ»¸öhttp ½Úµã¡£
  **********************************************************/
 http_parser_t *http_initHttpLinkInfor(http_stream *a_http_stream, int thread_seq,	struct streaminfo *a_tcp, void *a_packet)
 {	 
 	/* create tcpdatalen>0 after tcpdata delete special */
	uint32 offset = 0;
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;		
	http_deleteEmptyRow(&offset,(char*)tcp_detail->pdata+a_http_stream->packet_offset, tcp_detail->datalen-a_http_stream->packet_offset);	
	if(tcp_detail->datalen - a_http_stream->packet_offset - offset <=0) 
	{
		a_http_stream->packet_offset += offset ;
		return NULL;
	}
	 if(g_http_prog_para.http_log_level<=RLOG_LV_DEBUG)
	 {
		 MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_DEBUG, HTTP_PLUGIN_NAME, "%s-pending", printaddr(&a_tcp->addr,thread_seq));
	 }	 
	 if(g_http_prog_para.http_stat_cycle)
	 {
		 stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CREATE], FS_OP_TYPE_ADD, 1);
	 }
	 http_parser_t *a_http = (http_parser_t*)dictator_malloc(thread_seq, sizeof(http_parser_t));
	 memset(a_http, 0, sizeof(http_parser_t));	  
	 a_http->business.return_value = PROT_STATE_GIVEME; 
	 a_http_stream->uncomplete_count++;
	 a_http_stream->create_infor_num++;
	 http_initHttpCommonInfor(a_http, thread_seq);		 
	 FLAG_CLEAR(a_http->flag, HTTP_FLAG_NO_UNGZIP);
	 http_setSessionSeq(a_http,a_http_stream);
	 /*http batch*/
	 if(HTTP_CALLBACK_MODE_BATCH == g_http_prog_para.callback_mode)
	 {
	 	a_http->parser.batch_infor = (batch_infor_t*)dictator_malloc(thread_seq, sizeof(batch_infor_t));
		a_http->parser.batch_infor->field_cnt = 0;
		a_http->parser.batch_infor->field = (field_infor_t*)dictator_malloc(thread_seq, g_http_prog_para.batch_field_maxnum*sizeof(field_infor_t));
		memset(a_http->parser.batch_infor->field, 0, g_http_prog_para.batch_field_maxnum*sizeof(field_infor_t));		
	}
	return a_http;
 }

 /**********************************************************
  * ¹¦ÄÜ£º½¨Á¢HTTPÁ¬½ÓÁ´±í¡£
  * a_http£ºµ±Ç°Á÷»·¾³¡£
  * curdir:tcpÊý¾Ý°üµÄ·½Ïò£¬±íÃ÷µ¥Ë«Ïò°ü¡£
  * dir£ºµ±Ç°°üµÄ·½Ïò¡£
 *********************************************************/
 void http_buildHttpInforLink(http_stream *a_http_stream, int thread_seq, struct streaminfo *a_tcp, void *a_packet)
 { 	
 	http_parser_t *new_node=NULL;
	http_parser_t *prev_http_node = (a_http_stream->res_req==DIR_C2S)? a_http_stream->last_link_node:a_http_stream->first_link_node;

	/*http proxy and switch protocol, not change http_infor*/
	if(HTTP_DATA_END==prev_http_node->parser.http_state || a_http_stream->res_req != a_tcp->curdir)
	{
		 /*20150601 20150917*/
		 if(a_tcp->curdir==DIR_C2S)
		 {			 	
			if(a_http_stream->is_proxy || prev_http_node->parser.res_code==101) 
			{
				a_http_stream->res_req = a_tcp->curdir;
				return ;
			}
			 new_node=http_initHttpLinkInfor(a_http_stream,thread_seq, a_tcp, a_packet);
			 if(NULL!=new_node)
			 {
				 new_node->next = NULL;
				 new_node->prev = a_http_stream->last_link_node;
				 a_http_stream->last_link_node->next = new_node;
				 a_http_stream->last_link_node = new_node;
			 }			 
		 }
		 else
		 {		
			 if(DIR_DOUBLE!=a_tcp->dir)
			 {			 
				 if(a_http_stream->is_proxy || prev_http_node->parser.res_code==101) 
				 {
					 a_http_stream->res_req = a_tcp->curdir;
					 return ;
				 }
				 new_node=http_initHttpLinkInfor(a_http_stream,thread_seq, a_tcp, a_packet);
				 if(NULL!=new_node)
				 {
					 a_http_stream->first_link_node->prev = new_node;
					 new_node->next = a_http_stream->first_link_node;
					 new_node->prev = NULL;
					 a_http_stream->first_link_node = new_node;
				 }				
			 }
			 else
			 {	
			 	/*20160528 response come, clear*/
			 	//if(a_http_stream->first_link_node->packet_entity_len==0)
			 	{			 	
					if((a_http_stream->is_proxy && prev_http_node->parser.res_code!=0)|| prev_http_node->parser.res_code==101) 
					{
						a_http_stream->res_req = a_tcp->curdir;
						return ;
					}
					/*20170425 response_line span*/
					if(HTTP_START_LINE!=a_http_stream->first_link_node->parser.http_state)
					{
						http_resetResponseSpace((a_http_stream->first_link_node), thread_seq);
					}
				}
			 }			
		 }		
	 }
	 
	 /*20160601 S2C come but C2S not over, clear c2s*/	 
	 if(NULL!=prev_http_node) 
	 {
		 if(HTTP_DATA_END!=prev_http_node->parser.http_state && DIR_C2S==prev_http_node->parser.curdir && DIR_S2C == a_tcp->curdir)
		 {
			 if(HTTP_START_LINE!=a_http_stream->first_link_node->parser.http_state)
			 {
			 	http_resetResponseSpace((a_http_stream->first_link_node), thread_seq);
			 }
		 }
	 }	
	 a_http_stream->res_req = a_tcp->curdir;
 }
 
/**********************************************************
 * ¹¦ÄÜ£º³õÊ¼»¯HTTPÁ¬½Ó¡£
 * curdir:tcpÊý¾Ý°üµÄ·½Ïò£¬±íÃ÷µ¥Ë«Ïò°ü¡£
 * dir£ºµ±Ç°°üµÄ·½Ïò¡£
 * pme£ºÉÏÏÂÎÄ»·¾³¡£
***********************************************************/
void http_initHttpConnection(http_stream *a_http_stream, int thread_seq, struct streaminfo *a_tcp, void *a_packet)
{ 
	//Á÷½¨Á¢µÄÊ±ºò£¬µÚÒ»¸öÁ¬½Ó
	if(0==a_http_stream->uncomplete_count)
	{
		a_http_stream->res_req = a_tcp->curdir;
		a_http_stream->last_link_node = http_initHttpLinkInfor(a_http_stream, thread_seq, a_tcp, a_packet);
		a_http_stream->first_link_node = a_http_stream->last_link_node;
	}
	else
	{
		http_buildHttpInforLink(a_http_stream, thread_seq, a_tcp, a_packet);	
	}
	/*set one-way or two-way*/
	if(a_http_stream->dir==0)
	{
		if(DIR_DOUBLE==a_tcp->dir) 
		{
			a_http_stream->dir = a_tcp->dir;
		}
		else
		{
			if(a_tcp->curdir==DIR_C2S)
			{
				if(DIR_DOUBLE!=a_tcp->dir &&  (g_http_prog_para.singleway_seq ==0 || (g_http_prog_para.singleway_seq >0 && a_http_stream->create_infor_num > g_http_prog_para.singleway_seq)))
				{
					a_http_stream->dir = DIR_C2S;
				}				
			}
			else
			{				
				if(DIR_DOUBLE!=a_tcp->dir && (g_http_prog_para.singleway_seq ==0 || (g_http_prog_para.singleway_seq >0 && a_http_stream->create_infor_num > g_http_prog_para.singleway_seq)))
				{
					a_http_stream->dir = DIR_S2C;
				}				
			}			
		}		
	}
	
	/*http have set one-way traffic, but sapp become two-way traffic*/
	if(a_tcp->dir==DIR_DOUBLE && (a_http_stream->dir==DIR_S2C||a_http_stream->dir==DIR_C2S))
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http set single, but sapp become double, addr:%s.", 
								printaddr(&a_tcp->addr,thread_seq));
	}		
}

/**********************************************************

 **********************************************************/
static void http_reseaseHttpInforList(http_parser_t**a_http, UINT16 uncomplete_count,
									     uchar curdir, int thread_seq)
{
	http_parser_t *cur = NULL;
	if(NULL==*a_http)		return;
	if(uncomplete_count==1 || (NULL==(*a_http)->prev && NULL==(*a_http)->next))
	{
		(*a_http)->next = NULL;
		(*a_http)->prev = NULL;
		dictator_free(thread_seq,*a_http);
		(*a_http)=NULL;
		return;
	}
	cur = *a_http;
	if(DIR_C2S==curdir)
	{
		if(NULL!=(*a_http)->prev)
		{
			(*a_http)->prev->next = (*a_http)->next;
		}
		*a_http = (*a_http)->prev;
	}
	else
	{
		if(NULL!=(*a_http)->next)
		{
			(*a_http)->next->prev = (*a_http)->prev;
		}
		*a_http = (*a_http)->next;
	}
	dictator_free(thread_seq,cur);
	cur = NULL;
	return;
}/*http_ReseaseHttpInforList*/

/**********************************************************
 * ¹¦ÄÜ£ºÊÍ·Å½Úµã¡£
 * a_http:µ±Ç°½Úµã¡£
 * curdir£ºµ±Ç°Êý¾ÝµÄ·½Ïò¡
 * delete cur_node when http_infor be proccessd over
 * the different with http_releaseHttpLinkNode:http_reseaseHttpInfor is delete cur_node,and proc prev and next
 **********************************************************/
 void http_reseaseHttpInfor(http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq,  void *a_packet)
{
	http_parser_t *cur_http_node = (DIR_C2S==a_http_stream->res_req)? a_http_stream->last_link_node: a_http_stream->first_link_node;
	if(g_http_prog_para.http_log_level<=RLOG_LV_DEBUG)
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_DEBUG, HTTP_PLUGIN_NAME, "%s-close", printaddr(&a_tcp->addr,thread_seq));
	}	
	if(g_http_prog_para.http_stat_cycle)
	{
		 stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_RELEASE], FS_OP_TYPE_ADD, 1);
	}
	if(cur_http_node->ungzip_handle!=NULL)
	{	
		docanalyze_endstream(cur_http_node->ungzip_handle);
	}
	if(cur_http_node->parser.cont_range!=NULL)
	{
		dictator_free(thread_seq, cur_http_node->parser.cont_range);
		cur_http_node->parser.cont_range = NULL;
	}

	http_freeBuf(thread_seq,&(cur_http_node->url_buf), &(cur_http_node->url_buflen));	
	cur_http_node->parser.p_url = NULL;
	cur_http_node->parser.url_len = 0;
	http_freeBuf(thread_seq,&(cur_http_node->pbuf), &(cur_http_node->buflen));	
	/*batch free*/
	if(HTTP_CALLBACK_MODE_BATCH==g_http_prog_para.callback_mode)
	{		
		/*clear fold buf*/
		if(NULL!=cur_http_node->pbuf_fold)
		{
			int j=0;
			for(j=0;j<cur_http_node->pbuf_fold->cnt;j++)
			{
				if(NULL!=cur_http_node->pbuf_fold->fold[j].buf)
				{
					dictator_free(thread_seq, cur_http_node->pbuf_fold->fold[j].buf);
				}
			}
			if(NULL!=cur_http_node->pbuf_fold->fold)
			{
				dictator_free(thread_seq, cur_http_node->pbuf_fold->fold);
			}
			dictator_free(thread_seq, cur_http_node->pbuf_fold);
		}	
		/*clear batch infor*/			
		if(NULL!=cur_http_node->parser.batch_infor)
		{
			if(NULL!=cur_http_node->parser.batch_infor->field)
			{
				dictator_free(thread_seq, cur_http_node->parser.batch_infor->field);
			}
			dictator_free(thread_seq, cur_http_node->parser.batch_infor);
		}		
	}
	
	http_reseaseHttpInforList(&cur_http_node, a_http_stream->uncomplete_count, a_http_stream->res_req, thread_seq);
	a_http_stream->uncomplete_count--;
	
	if(a_http_stream->uncomplete_count<=1)
	{
		a_http_stream->last_link_node = cur_http_node;
		a_http_stream->first_link_node = cur_http_node;
		return;
	}
	else
	{
		if(DIR_C2S==a_http_stream->res_req)
		{
			a_http_stream->last_link_node = cur_http_node;
		}
		else
		{
			a_http_stream->first_link_node = cur_http_node;
		}
	}	
	return;
}

/*cording with http_method*/
const char* g_http_method[] = 
{	
	"unkonw",
	"get",
	"post",	
	"connect",
	"head",
	"put",
	"options",
	"delete",
	"trace",
};

char http_judgeHttpMethod(uchar *method, char *data, uchar curdir)
{	
	int i=0;
	if(curdir==DIR_C2S)
	{
		for(i=1;i<=HTTP_METHOD_TRACE;i++)
		{
			if(0==strncasecmp(data,g_http_method[i],strlen(g_http_method[i]))) 
			{
				*method = i;
				return OK;
			}
		}		
	}
	else
	{		
		/*content maybe have http, so set http/*/
		if(strncasecmp(data,"HTTP/",5)==0) return OK;

	}
	if(g_http_prog_para.http_log_level<=RLOG_LV_DEBUG)
	{
		/*log*/
		char buf[HTTP_START_FLAGS_LEN+1] = {0};
		memcpy(buf, data, HTTP_START_FLAGS_LEN);
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "http_judgeHttpMethod error, data=%s.",buf);
	}
	return ERROR;
}

/**********************************************************
return :
error 
ok
***********************************************************/
uchar http_tripleMatching(http_parser_t *cur_http_node, http_stream* a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	char*	frist_pos=NULL;
	char*	last_pos=NULL;
	char*	last_http_pos=NULL;
	uchar 	curdir = a_http_stream->res_req;
	uint16*	res_code = &(cur_http_node->parser.res_code);
	char*	oneline = cur_http_node->poneline_data;
	uint32 	oneline_len = cur_http_node->poneline_datalen;	
	char 	dig[4]={0} ;
	char*	http_flag = NULL;

	frist_pos = (char*)memchr(oneline, HTTP_SP, oneline_len);	
	if(NULL==frist_pos)	
	{	
		char* buf = (char*)calloc(1, oneline_len+1);
		memcpy(buf, oneline, oneline_len);
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_tripleMatching frist_space error: addr:%s, oneline:%s", 
								printaddr(&a_tcp->addr,thread_seq), buf);
		free(buf);
		return ERROR;
	}
	/*20161219*/
	if(DIR_C2S==curdir)
	{
		if(cur_http_node->parser.method==0)
		{
			char* buf = (char*)calloc(1, oneline_len+1);
			memcpy(buf, oneline, oneline_len);
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_tripleMatching C2S method==0: addr:%s, oneline:%s", 
									printaddr(&a_tcp->addr,thread_seq), buf);
			return ERROR;
		}
		/*POST http://web.superhub.sandai.net:80/HTTP/1.1*/
		last_http_pos = (char*)memcasemem(oneline, oneline_len, "HTTP/", 5); 			
		if(NULL!=last_http_pos) 
		{
			http_flag = (char*)(last_http_pos);
			/* HTTP/  HTTP1.1*/
			if(oneline+oneline_len-http_flag < HTTP_VERSIONS_LEN)	
			{
				MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_tripleMatching HTTP_C2S version len error: addr:%s, version_len=%d", 
										printaddr(&a_tcp->addr,thread_seq), oneline+oneline_len-http_flag);
				return ERROR;
			}
		}
		else if(NULL!=(last_http_pos = (char*)memcasemem(oneline, oneline_len, "HTTP1", 5)))
		{		
			http_flag = (char*)(last_http_pos);
			/* HTTP/  HTTP1.1*/
			if(oneline+oneline_len-http_flag < 7)	
			{
				MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_tripleMatching HTTP_C2S version len error: addr:%s, version_len=%d", 
										printaddr(&a_tcp->addr,thread_seq), oneline+oneline_len-http_flag);
				return ERROR;
			}			
		}
		else
		{
			char* buf = (char*)calloc(1, oneline_len+1);
			memcpy(buf, oneline, oneline_len);
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_tripleMatching HTTP_C2S last_space NULL: addr:%s, oneline:%s", 
									printaddr(&a_tcp->addr,thread_seq), buf);
			free(buf);
			return ERROR;
		}
		

		last_pos = last_http_pos-1;
		while(*last_pos==HTTP_SP && last_pos>frist_pos)
		{
			last_pos--;
		}			

		/*last_pos-first_pos to make sure url != NULL*/
		if(last_pos-frist_pos>0)
		{
			cur_http_node->url_buflen =  last_pos-frist_pos;
			cur_http_node->url_buf = (char*)dictator_malloc(thread_seq, cur_http_node->url_buflen);
			memcpy(cur_http_node->url_buf ,  frist_pos+1, cur_http_node->url_buflen);
		}

		cur_http_node->parser.curdir = DIR_C2S;		
		/*output uri*/
		if(last_pos-frist_pos>0)
		{
			cur_http_node->interested_reg_mask = HTTP_URI_MASK;		
			cur_http_node->session.buf =cur_http_node->url_buf;
			cur_http_node->session.buflen = cur_http_node->url_buflen;
			http_callPlugin(cur_http_node, a_tcp, thread_seq, a_packet);	
		}			
		cur_http_node->interested_reg_mask = HTTP_REQ_LINE_MASK;

		/*http proxy*/
#if HTTP_PROXY
		if(g_http_prog_para.proxy_switch)
		{
			if(cur_http_node->parser.method==HTTP_METHOD_CONNECT)
			{			
				cur_http_node->proxy_flag = DIR_C2S;	
			}
		}		
#endif

		/*http stat*/
		if(g_http_prog_para.http_stat_cycle)
		{
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_REQ], FS_OP_TYPE_ADD,1);
			if(DIR_C2S==a_http_stream->dir)
			{
				stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_C2S], FS_OP_TYPE_ADD, 1);
			}
		}

		/*http log*/
		if(g_http_prog_para.http_log_level<=RLOG_LV_DEBUG)
		{
			char url[64] = {0};
			memcpy(url, cur_http_node->url_buf, MIN(sizeof(url)-1, cur_http_node->url_buflen));
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_DEBUG, HTTP_PLUGIN_NAME, "%s:%lu URI:%s", 
									printaddr(&a_tcp->addr,thread_seq),cur_http_node->parser.http_session_seq,url);
		}		
	}
	else
	{			
		last_pos = (char*)memchr((frist_pos)+1, HTTP_SP, oneline_len-(frist_pos-oneline+1));		
		if(NULL==last_pos) 
		{
			last_pos = oneline + oneline_len;				
		}
		if(HTTP_RESPONSE_CODE_LEN!=(last_pos-frist_pos-1))	
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_tripleMatching HTTP_S2C code_len error: addr:%s, code_len=%d", 
									printaddr(&a_tcp->addr,thread_seq), last_pos-frist_pos-1);
			return ERROR;
		}

		/*proc res code*/
		memcpy(dig,frist_pos+1,HTTP_RESPONSE_CODE_LEN);
		*res_code = strtoul(dig, NULL, 10);

		/*HTTP/1.1 999 Unable to process request at this time -- error 999*/
		if((*res_code<100) || (*res_code>600 && *res_code!=999)) 
		{			
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_tripleMatching HTTP_S2C code error: addr:%s, code=%hu", 
									printaddr(&a_tcp->addr,thread_seq), *res_code);
			return ERROR;
		}

		/*http proxy*/
#if HTTP_PROXY
		if(g_http_prog_para.proxy_switch)
		{
			if(*res_code==200 && NULL!=memcasemem(oneline, oneline_len, PROXY_CONNECTION_SUCC, sizeof(PROXY_CONNECTION_SUCC)))
			{			
				cur_http_node->proxy_flag = DIR_S2C;	
			}
		}		
#endif

		/*http stat*/
		if(g_http_prog_para.http_stat_cycle)
		{
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_RES], FS_OP_TYPE_ADD,1);
			if(DIR_S2C==a_http_stream->dir)
			{
				stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_S2C], FS_OP_TYPE_ADD, 1);
			}
		}	
		
		cur_http_node->parser.curdir = DIR_S2C;
		cur_http_node->interested_reg_mask = HTTP_RES_LINE_MASK;
	}
	return OK;
}

/**********************************************************
 * ¹¦ÄÜ£ºÊ¶±ð¿ªÊ¼ÐÐ£¬´¦Àí¿ªÊ¼ÐÐ¡£
 * cur_http_node£ºµ±Ç°´¦Àí½Úµã¡£
 * curdir£ºµ±Ç°Êý¾Ý·½Ïò¡£
 * is_http£ºhttp¿ªÊ¼±êÖ¾Î»¡£
 * cur_halfstream£ºµ±Ç°°ëÁ÷Êý¾Ý¡£
 * return :	HTTP_RETURN_SPAN_PACKET
***********************************************************/
uchar http_doWithStartLine(http_parser_t*cur_http_node, http_stream* a_http_stream, struct streaminfo *a_tcp, int thread_seq, void* a_packet)
{	
	uchar rec = 0;
	
	rec = http_positioningACompleteLine(0, cur_http_node, a_tcp, thread_seq);	
	if(rec!=OK) return rec;

	/*get three tuple*/
	rec = http_tripleMatching(cur_http_node, a_http_stream, a_tcp, thread_seq, a_packet);
	if(rec!=OK)
	{
		cur_http_node->mgs_status = HTTP_RETURN_RESET;
		return rec;
	}
	
	/*20150603*/
	a_http_stream->is_http_falgs = HTTP_TRUE;
	
	/*output : req line and res line*/
	cur_http_node->session.buf = cur_http_node->poneline_data;
	cur_http_node->session.buflen = cur_http_node->poneline_datalen;	
	http_callPlugin(cur_http_node, a_tcp, thread_seq, a_packet);		
			
	http_inintRegionParam(cur_http_node, thread_seq);
	
	cur_http_node->parser.http_state = HTTP_REGION;			
	return OK;
}

#if HTTP_PROXY
uchar http_processHttpProxy(http_parser_t *a_http, http_stream *a_http_stream, struct streaminfo *a_tcp,int thread_seq,void *a_packet)
{	
	if(a_http->proxy_flag==0 || NULL==a_http_stream->p_stream_proxy) return ERROR;
	
	struct streaminfo *pProxy = a_http_stream->p_stream_proxy;
	char* 	user_pos = NULL;
	char* 	pwd_pos = NULL;
	int 	user_len = 0;
	char  	user_ped_decode[512] = {0};
	
	struct proxydetail*pProxydetail=NULL;
	pProxydetail=(struct proxydetail *)(pProxy->pdetail);

	a_http_stream->is_proxy = 1;
	
	if(pProxydetail->dealstate==PROXY_STATE_SEL)
	{	
		/*not add host url*/
		if(a_http->url_buf!=NULL&&pProxydetail->append==NULL)
		{
			pProxydetail->append = (uchar*)dictator_malloc(thread_seq,a_http->url_buflen);
			memcpy(pProxydetail->append,a_http->url_buf,a_http->url_buflen);
			pProxydetail->uiApendLen = a_http->url_buflen;	
		}
			
		//´¦ÀíÍê³É×ÔÉíµÄÐÅÏ¢ºó 
		/*user and passwd in C2S*/
		if(a_http->parser.curdir==DIR_C2S)
		{			
			//process http_proxy infor: base 64
			if(pProxydetail->pUser!=NULL)
			{
				user_pos = memcasemem((const char*)pProxydetail->pUser, pProxydetail->uiUserLen, "Basic ", sizeof("Basic"));
				if(user_pos!=NULL)
				{
					user_pos += sizeof("Basic");
				}
				else
				{
					user_pos = (char*)pProxydetail->pUser;
				}
				user_len = pProxydetail->uiUserLen-(user_pos-(char*)pProxydetail->pUser);
				http_proxy_base64_decode(0, user_pos, user_len, user_ped_decode);	
				pwd_pos = (char*)memchr(user_ped_decode, ':', strlen(user_ped_decode));	
				dictator_free(thread_seq, pProxydetail->pUser);
				if(pwd_pos==NULL)
				{
					pProxydetail->uiUserLen = strlen(user_ped_decode);
					pProxydetail->pUser = (uchar*)dictator_malloc(thread_seq, pProxydetail->uiUserLen);
					memcpy(pProxydetail->pUser, user_ped_decode, pProxydetail->uiUserLen);
				}
				else
				{
					pProxydetail->uiUserLen = pwd_pos - user_ped_decode;
					pProxydetail->pUser = (uchar*)dictator_malloc(thread_seq, pProxydetail->uiUserLen);
					memcpy(pProxydetail->pUser, user_ped_decode, pProxydetail->uiUserLen);

					pProxydetail->uiPwdLen = strlen(user_ped_decode) - (pwd_pos - user_ped_decode+1);
					pProxydetail->pPwd = (uchar*)dictator_malloc(thread_seq, pProxydetail->uiPwdLen);
					memcpy(pProxydetail->pPwd, pwd_pos+1, pProxydetail->uiPwdLen);		
				}									
			}			
		}		
		pProxydetail->dealstate = PROXY_STATE_LINK_IN;
		set_proxy_fstream(a_tcp, pProxy);
	}
	return OK;			
}	

uchar http_analyseHttpProxy(http_parser_t *a_http,  http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	/*not repeat*/
	if(a_http->proxy_flag==0 || NULL!=a_http_stream->p_stream_proxy) return OK;
	
	/*log*/
	if(g_http_prog_para.http_log_level<=RLOG_LV_INFO)
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "HTTP_PROXY:%s:%lu", 
								printaddr(&a_tcp->addr,thread_seq), a_http->parser.http_session_seq);
	}
	/*http_proxy capfile*/
#if HTTP_PROXY_CAPFILE
	project_req_add_char(a_tcp, g_http_prog_para.capfile_project_id, 1);
#endif			
	a_http_stream->p_stream_proxy = (struct streaminfo*)dictator_malloc(thread_seq,sizeof(struct streaminfo));
	memset(a_http_stream->p_stream_proxy,0,sizeof(struct streaminfo));	
	a_http_stream->p_stream_proxy->type = STREAM_TYPE_HTTP_PROXY;

	struct proxydetail* pProxydetail = (struct proxydetail *)(a_http_stream->p_stream_proxy->pdetail);
	//Èç¹ûÊÇÊ×´Î½øÈë
	if(pProxydetail==NULL)
	{
		pProxydetail=(struct proxydetail*)dictator_malloc(thread_seq,sizeof(struct proxydetail));
		memset(pProxydetail,0,sizeof(struct proxydetail));		
		pProxydetail->iType = STREAM_TYPE_HTTP_PROXY;
		a_http_stream->p_stream_proxy->pdetail=pProxydetail;	
		/*IP and PORT*/
		if(a_tcp->addr.addrtype==ADDR_TYPE_IPV4)
		{
			pProxydetail->uiIP = a_tcp->addr.tuple4_v4->daddr;
			pProxydetail->uiPort = a_tcp->addr.tuple4_v4->dest;   
		}
		if(a_tcp->addr.addrtype==ADDR_TYPE_IPV6)
		{
			pProxydetail->pIpv6 = (uchar*)dictator_malloc(thread_seq, sizeof(a_tcp->addr.tuple4_v6->daddr));
			memcpy(pProxydetail->pIpv6,a_tcp->addr.tuple4_v6->daddr,sizeof(a_tcp->addr.tuple4_v6->daddr));
			pProxydetail->uiPort = a_tcp->addr.tuple4_v6->dest; 
		}
	}	
	return OK;
}

#endif

/**********************************************************
 * ¹¦ÄÜ£ºÌáÈ¡http±êÖ¾£¬ÎªÈ·¶¨¿ªÊ¼±êÖ¾×ö×¼±¸¡£
 * buffer:Æ´´Õ¿ªÊ¼Ç°HTTP_START_FLAGS_LEN¸ö×Ö½ÚµÄÁÙÊ±»º´æÇø¡£
 * offset£ºµ±Ç°Êý¾ÝÁ÷ÒÑ´¦ÀíÊý¾ÝµÄÆ«ÒÆÁ¿¡£
 * method£ºÇëÇóÏûÏ¢µÄÇëÇó·½Ê½¡£
 * is_http:httpÈ·¶¨±êÖ¾Î»¡£
 * dir£ºµ±Ç°Êý¾ÝµÄ·½Ïò¡£
 * data£ºµ±Ç°Êý¾Ý¡£
 * data_len£ºµ±Ç°Êý¾Ý³¤¶È¡£
 return : OK GO_BACK ERROR
***********************************************************/
uchar http_findtStartFlag(http_parser_t *cur_node, uchar curdir,struct tcpdetail *tcp_detail, int thread_seq)
{ 
	uint32 *buflen = &(cur_node->buflen);
	uint32 *offset = &(cur_node->processed_offset);
	uchar *method = &(cur_node->parser.method);
	//µÚÒ»Êý¾ÝÁ÷È¥µô¿ÕÐÐ£¬¿Õ¸ñ£¬ÖÆ±í·û²»¹»HTTP_START_FLAGS_LEN×Ö½Ú
	if(0==*buflen)
	{
		if(tcp_detail->datalen < HTTP_START_FLAGS_LEN+*offset)
		{
			if(tcp_detail->datalen-*offset > 0)
			{
				cur_node->pbuf = (char*)dictator_malloc(thread_seq, tcp_detail->datalen-*offset);
				memcpy((void*)(cur_node->pbuf), (void*)((uchar*)tcp_detail->pdata+*offset),tcp_detail->datalen-*offset);
				*buflen = tcp_detail->datalen-*offset;
			}			
			return GO_BACK;
		}
		return http_judgeHttpMethod(method, (char*)tcp_detail->pdata+*offset, curdir);			
	}
	
	//Ò»Ö±µÈ¹»HTTP_START_FLAGS_LEN×Ö½Ú
	if(0<*buflen)
	{
		if(tcp_detail->datalen+*buflen < HTTP_START_FLAGS_LEN+*offset && tcp_detail->datalen-*offset>0)
		{			
			if(tcp_detail->datalen-*offset > 0)
			{
				cur_node->pbuf = (char*)dictator_realloc(thread_seq, cur_node->pbuf, (*buflen)+ tcp_detail->datalen-*offset);
				memcpy((void*)(cur_node->pbuf+(*buflen)), (void*)((uchar*)tcp_detail->pdata+*offset),tcp_detail->datalen-*offset);
				*buflen += tcp_detail->datalen-*offset;
			}			
			return GO_BACK;			
		}
		//±êÖ¾Ò»²¿·ÖÔÚbufferÀïÃæ£¬Ò»²¿·ÖÔÚdataÀïÃæ
		cur_node->pbuf = (char*)dictator_realloc(thread_seq, cur_node->pbuf, HTTP_START_FLAGS_LEN);
		memcpy((void*)(cur_node->pbuf+(*buflen)), (void*)((uchar*)tcp_detail->pdata+*offset),HTTP_START_FLAGS_LEN-*buflen);
		*offset += HTTP_START_FLAGS_LEN-*buflen;
		*buflen = HTTP_START_FLAGS_LEN;
		return http_judgeHttpMethod(method, cur_node->pbuf, curdir);			
	}
	return ERROR;
}

/**********************************************************
 * ¹¦ÄÜ£º·ÖÎöHTTPÁ¬½Ó,¸ù¾Ý²»Í¬µÄÏûÏ¢£¬Ö´ÐÐ²»Í¬µÄ²Ù×÷¡£
 * a_http:httpÁ÷»·¾³¡£
 * tcp_detail£ºµ±Ç°tcpÊý¾Ý¡£
***********************************************************/
uchar http_analyseHttpReqResHeader(http_parser_t* a_http, http_stream* a_http_stream, struct streaminfo* a_tcp, int thread_seq, void *a_packet)
{	
	uchar rec = OK;
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;		
	//¿ªÊ¼ÐÐ·ÖÎö	
	if(HTTP_STATE_UNKNOWN==a_http->parser.http_state)
	{	
		/*20170207 POSTÔÚÉÏÃæ Ò»¸ö °ü £¬ SP+URIÔÚÏÂÃæÒ»¸ö°ü */
		if(a_http->pbuf==NULL)
		{
			/*delete \r\n \0 ...... GETÖ®Ç°ÓÐ¿Õ¸ñ*/
			http_deleteEmptyRow(&(a_http->processed_offset),(char*)(tcp_detail->pdata), tcp_detail->datalen);		
		}
		rec = http_findtStartFlag(a_http, a_http_stream->res_req, tcp_detail, thread_seq);
		if(rec==ERROR)
		{
			a_http->mgs_status = HTTP_RETURN_RESET;
			return ERROR;
		}
		else if(rec==GO_BACK)
		{
			return GO_BACK;
		}
		a_http->parser.http_state = HTTP_START_LINE;
		/*20150603 set http_begin*/
		a_http->phttp_begin = (char*)(tcp_detail->pdata)+a_http->processed_offset;		
	}	
	if(HTTP_START_LINE==a_http->parser.http_state)
	{	
		rec = http_doWithStartLine(a_http, a_http_stream, a_tcp, thread_seq, a_packet);
		if(rec!=OK) return rec; 
		/*proxy proc : malloc proxy region*/
#if HTTP_PROXY
		if(g_http_prog_para.proxy_switch)
		{
			http_analyseHttpProxy(a_http, a_http_stream, a_tcp, thread_seq, a_packet);		
		//	http_processHttpProxy(a_http,a_http_stream,a_tcp,thread_seq,a_packet);				
		}		
#endif			
	}

	//Í·²¿·ÖÎö
	if(HTTP_REGION==a_http->parser.http_state) 
	{
		rec = http_findAndDoWithRegion(a_http, a_http_stream, a_tcp, thread_seq, a_packet);
		if(rec!=OK) return rec; 
	}
	return OK;
}
