/**********************************************************
 *
 * by lishu
 **********************************************************/

 
#include <assert.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/time.h>     
#include <math.h>
#include "HTTP_Message.h"
#include "HTTP_Analyze.h"
#include "HTTP_Common.h"
#include "HTTP_Message_Region.h"
#include "HTTP_Message_Header.h"
#include "HTTP_Message_Entry.h"
#include "MESA_handle_logger.h"
#include "field_stat.h"

http_prog_runtime_parameter_t g_http_prog_para;

int G_HTTP_H_VERSION_3_20150320 = 0;
int G_HTTP_VERSION_4_20181113 = 0;
void history()
{
	//2014-12-09 V3.0 new documentAnalyze lib ;    http.h add and delete ;     
	//2015-01-05 V3.0 conf to ./conf/http/     
	//2015-01-14 V3.0 support http_method to string funcition
	//2015-01-16 V3.0 change function name
	//2015-01-26 V3.0 add url_decode; other_region(http.conf); session; http_proxy; DROPPKT to platform
	//2015-02-02 V3.0 http_stream pbuf to free;   ungzip session_buf not ==NULL because ungzip free; ungzip free_result; host memcheck; chunklen memcheck;thread_safe=0
	//2015-03-18 V3.0 when tcp_lostlen>0
	//2015-03-20 V3.0 entity proc end, http_infor maybe release, so can not use mgs_status
	//2015-03-23 V3.0 content-length==-1
	//2015-03-26 V3.0 not return  APP_STATE_GIVEME and curdir
	//2015-03-30 V3.0 if lost
	//2015-04-03 V3.0 bug in 	
	//2015-04-20 V3.0 http_tripleMatching dig[3] -> dig[4]
	//2015-06-01 V3.0 1. add pending and close. 2. when lost ,pend!=close	
	//2015-06-02 V3.0 1. add fault log when chunk_len < 0
	//2015-06-03 V3.0 1. get http header to service plugin. 
	//2015-06-09 V3.0 1. memcheck http_doWithGzipData 2. check session->buf=NULL
	//2015-07-23 V3.0 1. lost proc
	//2015-08-18 V3.0 1. http_url_decode error
	//2015-09-17 V3.0 1. build http first node
	//2015-11-03 V3.0 1. http_region2proto_flag A->a	
	//2016-01-22 V3.0 1. C2S lost bug, cur_http_node->parser.http_state = HTTP_DATA_END; when  http_clearHttpInfor
	//2016-01-28 V3.0 1. support deflate. 2. add COMPLETE_BUFLEN to limit  the size of complete line
	//2016-03-02 V3.0 1. relative URL and absolute URL 
				   //2. not joint URL when proxy 
				   //3. proc proxy 
				   //4. add proxt capture				   
	//2016-04-05 V3.0  http_free_proxy_stream free bug : free_tcp_proxy_stream free proxy
	//2016-04-29 V4.0 
				   //1. http batch :  no do
				   //2. free http_infor when single-way
				   //3. http_seq_session=-1 when lost
	//2016-05-26 V4.0 
				   //1. curdir=0
				   //2. proxy loop
				   //3. tcpdata is GET+URI , but bizplug get content
				   //4. proxy add switch				   
	//2016-06-01 V4.0 
				   //http_findFristAndLastSPPos depend on spcae is wrong;  http_judgeHttpMethod(method, (char*)tcp_detail->pdata, curdir), tcp_detail->pdata is wrong
	//2016-06-12 V4.0 			  
					//\n as one complete line
	//2016-06-17 V4.0
					//expend head, >=HTTP_REGION_NUM	
					//add static	
					
	//2016-07-01 V4.0
					//expand use hash
	//2016-07-15 V4.0
					//http proxy when reset
					//g_http_prog_para.batch_field_maxnum bug
	//2016-08-19 V4.0 
					//add static: header span cache byte	
	//2016-08-19 V4.0 
					//standard region : support append 
	//2016-09-22 V4.0 
					//malloc->dictator_malloc 
	//2016-11-21 V4.0 
					//support 101 Switching Protocols
					//modify proxy, process same with websocket
	//2016-12-12 V4.0 //region is NULL, not callback 	
	//2016-12-13 V4.0 //dictator_malloc, http_saveToBuf	
	//2016-12-19 V4.0 //C2S method==0	
	//2016-12-24 V4.0 //http_url_decode
	//2017-02-07 V4.0 //serverIP + URI = URL when without host ; purl not cache uri before set url	
	//2017-03-30 V4.0 //HTTP_MAX_UINT64_LEN 32->64
	//2017-04-25 V4.0 //response_line  \r\n span, but http_resetResponseSpace
	//2017-09-18 V4.0 //batch info when callback, not to do
	//2017-11-03 V4.0 //proc absolute URI without host
	//2018-09-07 V4.0 //http_line2region:region name is raw pkt 	
	//2018-11-13 V4.0 //special http pkt, proc span 
}
	
/*
int get_bitnum(int64 prot_flag)
{
	int i=-1;
	while(prot_flag)
	{
		prot_flag>>=2;
		i++;
	}
	return i;
}
*/

/* not use because need plugin_manager support
uchar http_getSessionState(http_parser_t *cur_http_node)
{
	uchar state = 0;	
	if(HTTP_FLASE==cur_http_node->session_flag)
	{
		if(HTTP_INTEREST_KEY_MASK!=cur_http_node->interested_reg_mask)
		{
			state = SESSION_STATE_DATA;
		}
		if(HTTP_TRUE==cur_http_node->over_flag)
		{
			state |= SESSION_STATE_PENDING | SESSION_STATE_CLOSE;
		}		
		else
		{
			state |= SESSION_STATE_PENDING;
		}
	}
	else
	{	
		if(HTTP_INTEREST_KEY_MASK!=cur_http_node->interested_reg_mask)
		{
			state = SESSION_STATE_DATA;
		}
		if(HTTP_TRUE==cur_http_node->over_flag)
		{
			state |= SESSION_STATE_CLOSE;
		}			
	}
	cur_http_node->session_flag = HTTP_TRUE;
	return state;
}
*/

uchar http_getSessionState(http_parser_t *cur_http_node)
{
    uchar state = 0;    
    if(!FLAG_TEST(cur_http_node->flag, HTTP_FLAG_SESSION))
    {
		if(FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER))
            state = SESSION_STATE_CLOSE | SESSION_STATE_PENDING;
        else
            state = SESSION_STATE_PENDING;
    }
    else
    {
		if(FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER))
            state = SESSION_STATE_CLOSE;
        else
            state = SESSION_STATE_DATA;
    }
	FLAG_SET(cur_http_node->flag, HTTP_FLAG_SESSION);
    return state;
}

void http_callPluginField(http_parser_t* cur_http_node,struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{		
	int state = 0;
	stSessionInfo session_info;

	state = http_getSessionState(cur_http_node);
	session_info.plugid = g_http_prog_para.http_plugid;
	session_info.prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
	session_info.session_state = state;
	session_info._pad_ = 0;
	session_info.app_info = (void*)(&(cur_http_node->parser));
	session_info.buf = (void*)(cur_http_node->session.buf);
	session_info.buflen = cur_http_node->session.buflen;			
	cur_http_node->business.return_value = PROT_PROCESS(&session_info,
													     &(cur_http_node->business.param),
													     thread_seq,a_tcp, a_packet);
	if(cur_http_node->business.return_value&PROT_STATE_DROPPKT)
	{
		cur_http_node->mgs_status = HTTP_RETURN_DROPPKT;
	}
	if(cur_http_node->business.return_value&PROT_STATE_DROPME)
	{
		FLAG_SET(cur_http_node->flag, HTTP_FLAG_NO_UNGZIP);
	}
	return ;
}

void http_callPluginBatch(http_parser_t* cur_http_node,struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{		
	int state = 0;
	stSessionInfo session_info;

	if(!(PROT_STATE_DROPME&cur_http_node->business.return_value))
	{
		state = http_getSessionState(cur_http_node);
		session_info.plugid = g_http_prog_para.http_plugid;
		session_info._pad_ = 1;
		session_info.prot_flag = cur_http_node->batch_prot_flag;
		session_info.session_state = state;
		session_info.app_info = (void*)(&(cur_http_node->parser));
		session_info.buf = NULL;
		session_info.buflen = 0;			
		cur_http_node->business.return_value = PROT_PROCESS(&session_info,
														     &(cur_http_node->business.param),
														     thread_seq,a_tcp, a_packet);
		if(cur_http_node->business.return_value&PROT_STATE_DROPPKT)
		{
			cur_http_node->mgs_status = HTTP_RETURN_DROPPKT;
		}
		if(cur_http_node->business.return_value&PROT_STATE_DROPME)
		{
			FLAG_SET(cur_http_node->flag, HTTP_FLAG_NO_UNGZIP);
		}
	}
	/*clear*/
	/*clear batch*/
	for(int i=0;i<cur_http_node->parser.batch_infor->field_cnt;i++)
	{
		cur_http_node->parser.batch_infor->field[i].prot_flag = 0;
		cur_http_node->parser.batch_infor->field[i].buf = NULL;
		cur_http_node->parser.batch_infor->field[i].buflen = 0;
		//cur_http_node->parser.batch_infor->field[i].src_buf = NULL;
		//cur_http_node->parser.batch_infor->field[i].src_buflen = 0;
	}
	cur_http_node->parser.batch_infor->field_cnt = 0;		
	/*clear fold buf*/
	if(NULL!=cur_http_node->pbuf_fold)
	{	
		for(int j=0;j<cur_http_node->pbuf_fold->cnt;j++)
		{
			if(NULL!=cur_http_node->pbuf_fold->fold[j].buf)
			{
				dictator_free(thread_seq, cur_http_node->pbuf_fold->fold[j].buf);
				cur_http_node->pbuf_fold->fold[j].buf = NULL;
				cur_http_node->pbuf_fold->fold[j].buflen = 0;
			}
		}
		cur_http_node->pbuf_fold->cnt = 0 ;
	}
	cur_http_node->batch_prot_flag = 0;
	FLAG_CLEAR(cur_http_node->flag, HTTP_FLAG_BATCH_CALLBACK);
	FLAG_CLEAR(cur_http_node->flag, HTTP_FLAG_SPAN);
	return ;
}


/*字段回调的同时批处理赋值*/
void http_callPluginPreFieldBatch(http_parser_t* cur_http_node, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	if(HTTP_INTEREST_KEY_MASK!=cur_http_node->interested_reg_mask && 
		HTTP_CONTENT_MASK!=cur_http_node->interested_reg_mask &&
		HTTP_UNGZIP_CONTENT_MASK!=cur_http_node->interested_reg_mask &&
		HTTP_STATE_MASK!=cur_http_node->interested_reg_mask) 
	{
		/*excess, callback*/
		if(cur_http_node->parser.batch_infor->field_cnt>=g_http_prog_para.batch_field_maxnum)
		{				
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "batch field more than %d, callback.",g_http_prog_para.batch_field_maxnum);
			return;
		}
		int j = cur_http_node->parser.batch_infor->field_cnt;	
		/*url need not copy because p_url*/
		/*other not fold line*/
		if(HTTP_MESSAGE_URL_MASK==cur_http_node->interested_reg_mask||			
			NULL==cur_http_node->pbuf)
		{
			cur_http_node->parser.batch_infor->field[j].prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
			cur_http_node->parser.batch_infor->field[j].buf = cur_http_node->session.buf;
			cur_http_node->parser.batch_infor->field[j].buflen = cur_http_node->session.buflen;
			//cur_http_node->parser.batch_infor->field[j].src_buf = cur_http_node->parser.append_infor.content;
			//cur_http_node->parser.batch_infor->field[j].src_buflen = cur_http_node->parser.append_infor.contlen;
			cur_http_node->parser.batch_infor->field_cnt++;				
		}
		else
		{
			/*malloc when first time*/
			if(NULL==cur_http_node->pbuf_fold)
			{
				cur_http_node->pbuf_fold = (fold_buf_t*)dictator_malloc(thread_seq, sizeof(fold_buf_t));
				cur_http_node->pbuf_fold->cnt = 0;
				cur_http_node->pbuf_fold->fold = (fold_infor_t*)dictator_malloc(thread_seq, g_http_prog_para.batch_field_maxnum*sizeof(fold_infor_t));
				memset(cur_http_node->pbuf_fold->fold, 0, g_http_prog_para.batch_field_maxnum*sizeof(fold_infor_t));		
			}
			int i = cur_http_node->pbuf_fold->cnt;
			/*copy to fold_buf*/
			cur_http_node->pbuf_fold->fold[i].buf = (char*)dictator_malloc(thread_seq, cur_http_node->buflen);
			memcpy(cur_http_node->pbuf_fold->fold[i].buf, cur_http_node->pbuf, cur_http_node->buflen);
			cur_http_node->pbuf_fold->fold[i].buflen = cur_http_node->buflen;
		
			/*set batch field*/
			cur_http_node->parser.batch_infor->field[j].prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
			cur_http_node->parser.batch_infor->field[j].buf = (void*)((char*)cur_http_node->pbuf_fold->fold[i].buf + (cur_http_node->session.buf - cur_http_node->pbuf));
			cur_http_node->parser.batch_infor->field[j].buflen = cur_http_node->session.buflen;
			//cur_http_node->parser.batch_infor->field[j].src_buf = (void*)((char*)cur_http_node->pbuf_fold->fold[i].buf + (cur_http_node->parser.append_infor.content - cur_http_node->pbuf));
			//cur_http_node->parser.batch_infor->field[j].src_buflen = cur_http_node->parser.append_infor.contlen;
			cur_http_node->parser.batch_infor->field_cnt++;
			cur_http_node->pbuf_fold->cnt++;	
		}		
	}		
}

/*批处理回调*/
void http_callPluginPreBatch(http_parser_t* cur_http_node, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	if(HTTP_INTEREST_KEY_MASK!=cur_http_node->interested_reg_mask) 
	{
		/*excess, callback*/
		if(cur_http_node->parser.batch_infor->field_cnt>=g_http_prog_para.batch_field_maxnum)
		{				
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "batch field more than %d, callback.",g_http_prog_para.batch_field_maxnum);
			http_callPluginBatch(cur_http_node, a_tcp, thread_seq, a_packet);
		}
		int j = cur_http_node->parser.batch_infor->field_cnt;	
		/*url need not because p_url*/
		/*content need not copy*/
		/*other not fold line*/
		if(HTTP_MESSAGE_URL_MASK==cur_http_node->interested_reg_mask||
			HTTP_CONTENT_MASK==cur_http_node->interested_reg_mask || 
			HTTP_UNGZIP_CONTENT_MASK==cur_http_node->interested_reg_mask || 
			HTTP_STATE_MASK==cur_http_node->interested_reg_mask||
			NULL==cur_http_node->pbuf)
		{
			cur_http_node->parser.batch_infor->field[j].prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
			cur_http_node->parser.batch_infor->field[j].buf = cur_http_node->session.buf;
			cur_http_node->parser.batch_infor->field[j].buflen = cur_http_node->session.buflen;
			//cur_http_node->parser.batch_infor->field[j].src_buf = cur_http_node->parser.append_infor.content;
			//cur_http_node->parser.batch_infor->field[j].src_buflen = cur_http_node->parser.append_infor.contlen;
			cur_http_node->parser.batch_infor->field_cnt++;				
		}
		else
		{
			/*malloc when first time*/
			if(NULL==cur_http_node->pbuf_fold)
			{
				cur_http_node->pbuf_fold = (fold_buf_t*)dictator_malloc(thread_seq, sizeof(fold_buf_t));
				cur_http_node->pbuf_fold->cnt = 0;
				cur_http_node->pbuf_fold->fold = (fold_infor_t*)dictator_malloc(thread_seq, g_http_prog_para.batch_field_maxnum*sizeof(fold_infor_t));
				memset(cur_http_node->pbuf_fold->fold, 0, g_http_prog_para.batch_field_maxnum*sizeof(fold_infor_t));		
			}
			int i = cur_http_node->pbuf_fold->cnt;
			/*copy to fold_buf*/
			cur_http_node->pbuf_fold->fold[i].buf = (char*)dictator_malloc(thread_seq, cur_http_node->buflen);
			memcpy(cur_http_node->pbuf_fold->fold[i].buf, cur_http_node->pbuf, cur_http_node->buflen);
			cur_http_node->pbuf_fold->fold[i].buflen = cur_http_node->buflen;
		
			/*set batch field*/
			cur_http_node->parser.batch_infor->field[j].prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
			cur_http_node->parser.batch_infor->field[j].buf = (void*)((char*)cur_http_node->pbuf_fold->fold[i].buf + (cur_http_node->session.buf - cur_http_node->pbuf));
			cur_http_node->parser.batch_infor->field[j].buflen = cur_http_node->session.buflen;
			//cur_http_node->parser.batch_infor->field[j].src_buf = (void*)((char*)cur_http_node->pbuf_fold->fold[i].buf + (cur_http_node->parser.append_infor.content - cur_http_node->pbuf));
			//cur_http_node->parser.batch_infor->field[j].src_buflen = cur_http_node->parser.append_infor.contlen;
			cur_http_node->parser.batch_infor->field_cnt++;
				cur_http_node->pbuf_fold->cnt++;	
		}
		/*set callback by parser*/
		/*http session over callback*/
		/*pkt span callback*/
		if(FLAG_TEST(cur_http_node->flag, HTTP_FLAG_BATCH_CALLBACK)||
		    FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER) ||
		    FLAG_TEST(cur_http_node->flag, HTTP_FLAG_SPAN))
		{
			if(cur_http_node->parser.batch_infor->field_cnt>0)
			{
				http_callPluginBatch(cur_http_node, a_tcp, thread_seq, a_packet);
			}
		}		
	}		
}

/*字段回调的同时批处理赋值*/
void http_callPlugin(http_parser_t* cur_http_node, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	int64 	prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);	
	uint64 	region_flag  = g_http_prog_para.http_interested_region_flag&prot_flag;	

	if((!region_flag && !FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER)) || PROT_STATE_DROPME & cur_http_node->business.return_value) 
	{
		/*clear*/
		/*20150603 maybe memleak,because http_doWithGzipData:106*/
		if(cur_http_node->interested_reg_mask!=HTTP_UNGZIP_CONTENT_MASK)
		{
			cur_http_node->session.buf = NULL;
			cur_http_node->session.buflen = 0;	
		}	
		cur_http_node->interested_reg_mask = HTTP_INTEREST_KEY_MASK;	
		return;
	}

#if HTTP_STATIC
	long long before = 0;
	long long after = 0;
	long long dealtime = 0;
	/*static pkt dealtime*/
	if(g_http_prog_para.http_stat_cycle)
	{
		before = rdtsc();
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CBPLUGIN], FS_OP_TYPE_ADD, 1);
	}
#endif
	
	if(HTTP_CALLBACK_MODE_BATCH==g_http_prog_para.callback_mode)
	{			
		http_callPluginPreBatch(cur_http_node, a_tcp, thread_seq, a_packet);			
	}
	else if(HTTP_CALLBACK_MODE_FIELD==g_http_prog_para.callback_mode && !(PROT_STATE_DROPME&cur_http_node->business.return_value))
	{		
		http_callPluginField(cur_http_node, a_tcp, thread_seq, a_packet);		
	}
	else if(HTTP_CALLBACK_MODE_FIELD_BATCH==g_http_prog_para.callback_mode && !(PROT_STATE_DROPME&cur_http_node->business.return_value))
	{		
		http_callPluginPreFieldBatch(cur_http_node, a_tcp, thread_seq, a_packet);		
		http_callPluginField(cur_http_node, a_tcp, thread_seq, a_packet);		
	}

	/*clear*/
	/*20150603 maybe memleak,because http_doWithGzipData:106*/
	if(cur_http_node->interested_reg_mask!=HTTP_UNGZIP_CONTENT_MASK)
	{
		cur_http_node->session.buf = NULL;
		cur_http_node->session.buflen = 0;	
	}	
	cur_http_node->interested_reg_mask = HTTP_INTEREST_KEY_MASK;	

#if HTTP_STATIC
	/*static pkt dealtime*/
	if(g_http_prog_para.http_stat_cycle)
	{
		after = rdtsc();
		dealtime = after-before;
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CBPLUGIN_PROC_TIME], FS_OP_TYPE_ADD, dealtime);
	}
#endif
}

/*字段回调和批处理回调分开，备份*/
void http_callPlugin_field_or_batch(http_parser_t* cur_http_node, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	int64 	prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);	
	uint64 	region_flag  = g_http_prog_para.http_interested_region_flag&prot_flag;	

	if((!region_flag && !FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER)) || PROT_STATE_DROPME & cur_http_node->business.return_value) 
	{
		/*clear*/
		/*20150603 maybe memleak,because http_doWithGzipData:106*/
		if(cur_http_node->interested_reg_mask!=HTTP_UNGZIP_CONTENT_MASK)
		{
			cur_http_node->session.buf = NULL;
			cur_http_node->session.buflen = 0;	
		}	
		cur_http_node->interested_reg_mask = HTTP_INTEREST_KEY_MASK;	
		return;
	}

#if HTTP_STATIC
	long long before = 0;
	long long after = 0;
	long long dealtime = 0;

	/*static pkt dealtime*/
	if(g_http_prog_para.http_stat_cycle)
	{
		before = rdtsc();
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CBPLUGIN], FS_OP_TYPE_ADD, 1);
	}
#endif
	
	if(HTTP_CALLBACK_MODE_BATCH==g_http_prog_para.callback_mode)
	{			
		if(HTTP_INTEREST_KEY_MASK!=cur_http_node->interested_reg_mask) 
		{			
			cur_http_node->batch_prot_flag |= region_flag;		
			/*excess, callback*/
			if(cur_http_node->parser.batch_infor->field_cnt>=g_http_prog_para.batch_field_maxnum)
			{				
				MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "batch field more than %d, callback.",g_http_prog_para.batch_field_maxnum);
				http_callPluginBatch(cur_http_node, a_tcp, thread_seq, a_packet);
			}
			int j = cur_http_node->parser.batch_infor->field_cnt;	
			/*url need not because p_url*/
			/*content need not copy*/
			/*other not fold line*/
			if(HTTP_MESSAGE_URL_MASK==cur_http_node->interested_reg_mask||
				HTTP_CONTENT_MASK==cur_http_node->interested_reg_mask || 
				HTTP_UNGZIP_CONTENT_MASK==cur_http_node->interested_reg_mask || 
				HTTP_STATE_MASK==cur_http_node->interested_reg_mask||
				NULL==cur_http_node->pbuf)
			{
				cur_http_node->parser.batch_infor->field[j].prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
				cur_http_node->parser.batch_infor->field[j].buf = cur_http_node->session.buf;
				cur_http_node->parser.batch_infor->field[j].buflen = cur_http_node->session.buflen;
				//cur_http_node->parser.batch_infor->field[j].src_buf = cur_http_node->parser.append_infor.content;
				//cur_http_node->parser.batch_infor->field[j].src_buflen = cur_http_node->parser.append_infor.contlen;
				cur_http_node->parser.batch_infor->field_cnt++;				
			}
			else
			{
				/*malloc when first time*/
				if(NULL==cur_http_node->pbuf_fold)
				{
					cur_http_node->pbuf_fold = (fold_buf_t*)dictator_malloc(thread_seq, sizeof(fold_buf_t));
					cur_http_node->pbuf_fold->cnt = 0;
					cur_http_node->pbuf_fold->fold = (fold_infor_t*)dictator_malloc(thread_seq, g_http_prog_para.batch_field_maxnum*sizeof(fold_infor_t));
					memset(cur_http_node->pbuf_fold->fold, 0, g_http_prog_para.batch_field_maxnum*sizeof(fold_infor_t));		
				}
				int i = cur_http_node->pbuf_fold->cnt;
				/*copy to fold_buf*/
				cur_http_node->pbuf_fold->fold[i].buf = (char*)dictator_malloc(thread_seq, cur_http_node->buflen);
				memcpy(cur_http_node->pbuf_fold->fold[i].buf, cur_http_node->pbuf, cur_http_node->buflen);
				cur_http_node->pbuf_fold->fold[i].buflen = cur_http_node->buflen;
			
				/*set batch field*/
				cur_http_node->parser.batch_infor->field[j].prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
				cur_http_node->parser.batch_infor->field[j].buf = (void*)((char*)cur_http_node->pbuf_fold->fold[i].buf + (cur_http_node->session.buf - cur_http_node->pbuf));
				cur_http_node->parser.batch_infor->field[j].buflen = cur_http_node->session.buflen;
				//cur_http_node->parser.batch_infor->field[j].src_buf = (void*)((char*)cur_http_node->pbuf_fold->fold[i].buf + (cur_http_node->parser.append_infor.content - cur_http_node->pbuf));
				//cur_http_node->parser.batch_infor->field[j].src_buflen = cur_http_node->parser.append_infor.contlen;
				cur_http_node->parser.batch_infor->field_cnt++;

				cur_http_node->pbuf_fold->cnt++;	
			}
			/*set callback by parser*/
			/*http session over callback*/
			/*pkt span callback*/
			if(FLAG_TEST(cur_http_node->flag, HTTP_FLAG_BATCH_CALLBACK)||
			    FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER) ||
			    FLAG_TEST(cur_http_node->flag, HTTP_FLAG_SPAN))
			{
				if(cur_http_node->parser.batch_infor->field_cnt>0)
				{
					http_callPluginBatch(cur_http_node, a_tcp, thread_seq, a_packet);
				}
			}		
		}	
	}
	else if(HTTP_CALLBACK_MODE_FIELD==g_http_prog_para.callback_mode && !(PROT_STATE_DROPME&cur_http_node->business.return_value))
	{		
		http_callPluginField(cur_http_node, a_tcp, thread_seq, a_packet);		
	}

	/*clear*/
	/*20150603 maybe memleak,because http_doWithGzipData:106*/
	if(cur_http_node->interested_reg_mask!=HTTP_UNGZIP_CONTENT_MASK)
	{
		cur_http_node->session.buf = NULL;
		cur_http_node->session.buflen = 0;	
	}	
	cur_http_node->interested_reg_mask = HTTP_INTEREST_KEY_MASK;	

#if HTTP_STATIC
	/*static pkt dealtime*/
	if(g_http_prog_para.http_stat_cycle)
	{
		after = rdtsc();
		dealtime = after-before;
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CBPLUGIN_PROC_TIME], FS_OP_TYPE_ADD, dealtime);
	}
#endif
}

/*
* release and delete the first node from http_link, use when release http_stream
*/
void http_releaseHttpLinkNode(http_stream *a_http_stream,struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	http_parser_t *cur_node = NULL;
	cur_node = a_http_stream->first_link_node;	
	if(g_http_prog_para.http_log_level<=RLOG_LV_DEBUG)
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_DEBUG, HTTP_PLUGIN_NAME, "%s-close", printaddr(&a_tcp->addr,thread_seq));
	}
	if(g_http_prog_para.http_stat_cycle)
	{
		 stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_RELEASE], FS_OP_TYPE_ADD, 1);
	}
	if(NULL!=a_http_stream->first_link_node->next)
	{
		a_http_stream->first_link_node->next->prev = NULL;
	}		
	a_http_stream->first_link_node = a_http_stream->first_link_node->next;

	/*call http business plugin*/
	FLAG_SET(cur_node->flag, HTTP_FLAG_OVER);
	cur_node->parser.http_state = HTTP_DATA_END;	
	cur_node->interested_reg_mask = HTTP_INTEREST_KEY_MASK;
	if(g_http_prog_para.need_http_state)
	{
		cur_node->interested_reg_mask = HTTP_STATE_MASK;
	}
	/*may not call biz plugin*/
	cur_node->session.buf = NULL;
	cur_node->session.buflen = 0;	

	/*if not http, not callback , because startline maybe span pkt*/
	if(a_http_stream->is_http_falgs && cur_node->parser.curdir!=0)
	//if(a_http_stream->is_http_falgs)
	{
		http_callPlugin(cur_node, a_tcp, thread_seq, a_packet);		
	}
			
	http_freeBuf(thread_seq,&cur_node->url_buf, &cur_node->url_buflen);
	cur_node->parser.p_url = NULL;
	cur_node->parser.url_len = 0;
	
	http_freeBuf(thread_seq,&cur_node->pbuf, &cur_node->buflen);

	/*batch free*/
	if(HTTP_CALLBACK_MODE_BATCH==g_http_prog_para.callback_mode)
	{		
		/*clear fold buf*/
		if(NULL!=cur_node->pbuf_fold)
		{
			for(int j=0;j<cur_node->pbuf_fold->cnt;j++)
			{
				if(NULL!=cur_node->pbuf_fold->fold[j].buf)
				{
					dictator_free(thread_seq, cur_node->pbuf_fold->fold[j].buf);
				}
			}
			if(NULL!=cur_node->pbuf_fold->fold)
			{
				dictator_free(thread_seq, cur_node->pbuf_fold->fold);
			}
			dictator_free(thread_seq, cur_node->pbuf_fold);
		}	
		/*clear batch infor*/
		if(NULL!=cur_node->parser.batch_infor)
		{
			if(NULL!=cur_node->parser.batch_infor->field)
			{
				dictator_free(thread_seq, cur_node->parser.batch_infor->field);
			}
			dictator_free(thread_seq, cur_node->parser.batch_infor);
		}	
	}
		
	if(cur_node->ungzip_handle!=NULL)
	{	
		docanalyze_endstream(cur_node->ungzip_handle);
	}
	if(cur_node->parser.cont_range!=NULL)
	{
		dictator_free(thread_seq,cur_node->parser.cont_range);
		cur_node->parser.cont_range = NULL;
	}	
	dictator_free(thread_seq, cur_node);
	cur_node = NULL;
	a_http_stream->uncomplete_count--;
	return ;
}

void http_free_proxy_stream(int thread_seq, struct streaminfo *pProxy)
{ 
	struct proxydetail *pProxydetail = NULL;
	if(pProxy != NULL)
    {
		pProxydetail = (struct proxydetail*)pProxy->pdetail;
		if(pProxydetail->pUser)
		{
			dictator_free(thread_seq,pProxydetail->pUser);
			pProxydetail->pUser = NULL;
		}
		if(pProxydetail->pPwd)
		{
			dictator_free(thread_seq,pProxydetail->pPwd);
			pProxydetail->pPwd = NULL;
		}
		if(pProxydetail->pIpv6)
		{
			dictator_free(thread_seq,pProxydetail->pIpv6);
			pProxydetail->pIpv6 = NULL;
		}
		if(pProxydetail->append)
		{
			dictator_free(thread_seq,pProxydetail->append);
			pProxydetail->append = NULL;
		}	
		if(pProxy->pdetail != NULL)
		{
			dictator_free(thread_seq,pProxy->pdetail);
			pProxy->pdetail=NULL;
		}
		dictator_free(thread_seq,pProxy);
		pProxy = NULL;
	}	
}

/*
* reset  http_stream when lost packet 
*/
void http_resetHttpStream(http_stream **ppa_http_stream,	struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	http_stream *a_http_stream = *ppa_http_stream;
	if(NULL==(a_http_stream))		return ;		
	if(g_http_prog_para.http_stat_cycle)
	{
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_RESET], FS_OP_TYPE_ADD, 1);
	}	
	a_http_stream->reset_count ++;
	while(NULL!=(a_http_stream)->first_link_node)
	{
		http_releaseHttpLinkNode(a_http_stream, a_tcp, thread_seq, a_packet);
	}
	a_http_stream->res_req = 0;
	a_http_stream->dir = 0;
	a_http_stream->uncomplete_count = 0;
	a_http_stream->first_link_node = NULL;
	a_http_stream->last_link_node = NULL;
#if HTTP_PROXY	
	if(g_http_prog_para.proxy_switch)
	{
		/*have set proxy and deal_tcp_in_proxy_stream , not free, otherwise free*/
		if(NULL!=(a_http_stream)->p_stream_proxy && 0==a_http_stream->is_proxy)
		{				
			free_tcp_proxy_stream(a_tcp,a_http_stream->p_stream_proxy); 
			a_http_stream->p_stream_proxy = NULL;			
			a_http_stream->is_proxy = 0;
			/*log*/
			if(g_http_prog_para.http_log_level<=RLOG_LV_INFO)
			{
				MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "FREE_HTTP_PROXY:%s", 
										printaddr(&a_tcp->addr,thread_seq));
			}		
		}
	}
#endif	
	return;
}
/*
* release http_link all infor, and release http_stream
*/
void http_releaseHttpStream(http_stream **a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	if(g_http_prog_para.http_stat_cycle && (*a_http_stream)->is_http_falgs)
	{		
		struct tcpdetail*	tcp_detail = (struct tcpdetail*)a_tcp->pdetail; 
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CLIENT_PKT], FS_OP_TYPE_ADD, tcp_detail->clientpktnum);
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CLIENT_BYTE], FS_OP_TYPE_ADD, tcp_detail->clientbytes);
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_SERVER_PKT], FS_OP_TYPE_ADD, tcp_detail->serverpktnum);
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_SERVER_BYTE], FS_OP_TYPE_ADD, tcp_detail->serverbytes);

	}
	if(NULL==(*a_http_stream))		return ;
	
	while(NULL!=(*a_http_stream)->first_link_node)
	{
		http_releaseHttpLinkNode(*a_http_stream, a_tcp, thread_seq, a_packet);
	}
	(*a_http_stream)->first_link_node = NULL;
	(*a_http_stream)->last_link_node = NULL;
	
#if HTTP_PROXY	
	if(g_http_prog_para.proxy_switch)
	{
		if(NULL!=(*a_http_stream)->p_stream_proxy)
		{				
			free_tcp_proxy_stream(a_tcp,(*a_http_stream)->p_stream_proxy);
			/*log*/
			if(g_http_prog_para.http_log_level<=RLOG_LV_INFO)
			{
				MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "FREE_HTTP_PROXY:%s", 
										printaddr(&a_tcp->addr,thread_seq));
			}
		}
	}
#endif	
	if(NULL!=(*a_http_stream)->pbuf)
	{		
		dictator_free(thread_seq, (*a_http_stream)->pbuf);
	}
	dictator_free(thread_seq, *a_http_stream);
	*a_http_stream = NULL;
}

void http_initHttpStream(http_stream**pme, int thread_seq)
{
	http_stream *a_http_stream = *pme;
	if(NULL!=a_http_stream)	return;   
	a_http_stream = (http_stream *)dictator_malloc(thread_seq, sizeof(http_stream));
	memset(a_http_stream,0,sizeof(http_stream));	
	*pme = a_http_stream;
	return;
}

/*two session in one pakcet*/
void http_prevAnylse(http_parser_t* cur_node, http_stream* a_http_stream, int thread_seq)
{
	cur_node->processed_offset = a_http_stream->packet_offset;	
	/*20181228 上个流的buf传递给本http_info*/
	if(a_http_stream->buflen>0)
	{
		if(NULL==cur_node->pbuf)
		{
			cur_node->pbuf = (char*)dictator_malloc(thread_seq, a_http_stream->buflen);
		}
		else
		{
			cur_node->pbuf = (char*)dictator_realloc(thread_seq, cur_node->pbuf, cur_node->buflen+a_http_stream->buflen);
		}
		memcpy(cur_node->pbuf+cur_node->buflen, a_http_stream->pbuf, a_http_stream->buflen);
		cur_node->buflen += a_http_stream->buflen;
		http_freeBuf(thread_seq, &a_http_stream->pbuf, &a_http_stream->buflen);	
	}
	a_http_stream->packet_offset = 0;
}

uchar http_procLost(http_stream* a_http_stream, struct streaminfo* a_tcp, int thread_seq, void* a_packet)
{
	http_parser_t*		cur_http_node = NULL;	
	struct tcpdetail*	tcp_detail = (struct tcpdetail*)a_tcp->pdetail;	
	uchar				res_req_temp = a_http_stream->res_req;

	//20160526 get cur_http_node according to 
	a_http_stream->res_req = a_tcp->curdir;

	//20150326 according a_tcp->curdir
	//20150318 20150723 
	cur_http_node = (a_http_stream->res_req==DIR_C2S) ? a_http_stream->last_link_node:a_http_stream->first_link_node;
	if( NULL!=cur_http_node &&
	    (cur_http_node->parser.http_state==HTTP_DATA_BEGIN || cur_http_node->parser.http_state==HTTP_DATA )&&
		 cur_http_node->packet_entity_len>=tcp_detail->lostlen)
	{			
		(cur_http_node)->packet_entity_len -= tcp_detail->lostlen;
		//20150330
		if((cur_http_node)->packet_entity_len==0)
		{
			cur_http_node->parser.http_state = HTTP_DATA_END;
			if(a_tcp->curdir==DIR_S2C)
			{
				FLAG_SET(cur_http_node->flag, HTTP_FLAG_OVER);
				if(g_http_prog_para.need_http_state|| FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER))
				{
					cur_http_node->interested_reg_mask = HTTP_STATE_MASK;
					http_callPlugin(cur_http_node, a_tcp, thread_seq, a_packet);
				}			
				http_reseaseHttpInfor(a_http_stream, a_tcp, thread_seq, a_packet);								
			}	
			else
			{					
				http_resetResponseSpace(cur_http_node, thread_seq);
				/*20160122*/
				cur_http_node->parser.http_state = HTTP_DATA_END;
			}
		}
	}
	else 
	{
		//a_http_stream->http_session_num = -1;
		http_resetHttpStream(&a_http_stream, a_tcp, thread_seq, a_packet);
	}
	a_http_stream->res_req = res_req_temp;
	return OK;
}
	
/*
1. return value
   OK, is http
   NO,is not http
   GO_BACK, data is not enough
*/
uchar http_judgeHttpProtocol(http_stream *a_http_stream, uchar curdir, struct tcpdetail *tcp_detail, int thread_seq)
{ 
	uint32*	buflen = &(a_http_stream->buflen);
	uint32*	offset = &(a_http_stream->packet_offset);
	uchar 	method = HTTP_METHOD_UNKNOWN;
	uchar  	buf[HTTP_START_FLAGS_LEN] = {0};
	
	//第一数据流去掉空行，空格，制表符不够HTTP_START_FLAGS_LEN字节
	if(0==*buflen)
	{
		if(tcp_detail->datalen < HTTP_START_FLAGS_LEN+*offset)
		{
			if(tcp_detail->datalen-*offset > 0)
			{
				a_http_stream->pbuf = (char*)dictator_malloc(thread_seq, tcp_detail->datalen-*offset);
				memcpy((void*)(a_http_stream->pbuf), (void*)((uchar*)tcp_detail->pdata+*offset), tcp_detail->datalen-*offset);
				*buflen = tcp_detail->datalen-*offset;
			}			
			return GO_BACK;
		}		
		return http_judgeHttpMethod(&method, (char*)tcp_detail->pdata+*offset, curdir); 	
	}
	
	//一直等够HTTP_START_FLAGS_LEN字节
	if(0<*buflen)
	{
		if(tcp_detail->datalen+*buflen < HTTP_START_FLAGS_LEN+*offset && tcp_detail->datalen-*offset>0)
		{			
			if(tcp_detail->datalen-*offset > 0)
			{
				a_http_stream->pbuf = (char*)dictator_realloc(thread_seq,a_http_stream->pbuf, (*buflen)+ tcp_detail->datalen-*offset);
				memcpy((void*)(a_http_stream->pbuf+(*buflen)), (void*)((uchar*)tcp_detail->pdata+*offset),tcp_detail->datalen-*offset);
				*buflen += tcp_detail->datalen-*offset;
			}			
			return GO_BACK;			
		}
		//标志一部分在buffer里面，一部分在data里面		
		/*20181113*/		
		//a_http_stream->pbuf = (char*)dictator_realloc(thread_seq, a_http_stream->pbuf, HTTP_START_FLAGS_LEN);
		//memcpy((void*)(a_http_stream->pbuf+(*buflen)), (void*)((uchar*)tcp_detail->pdata+*offset),HTTP_START_FLAGS_LEN-*buflen);
		//*buflen = HTTP_START_FLAGS_LEN;			
		memcpy(buf, (void*)a_http_stream->pbuf, *buflen);		
		memcpy(buf+*buflen, (void*)((uchar*)tcp_detail->pdata+*offset), HTTP_START_FLAGS_LEN-*buflen);		
		return http_judgeHttpMethod(&method, (char*)buf, curdir); 	
	}
	
	return ERROR; 	
}

uchar http_analyseHttpConnection(http_stream* a_http_stream,struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	struct tcpdetail*	tcp_detail = (struct tcpdetail*)a_tcp->pdetail;	
	http_parser_t*		cur_http_node = NULL;	
	uchar				rec = OK;
	uchar				return_value = APP_STATE_GIVEME;

	assert(tcp_detail);
	assert(a_http_stream);
	
	if(0==tcp_detail->datalen||a_http_stream->uncomplete_count>=MAX_UNCOMPLETE_COUNT)
	{		
		return APP_STATE_DROPME;
	}

	/*http identify : v3 judge is http stream or not firstly*/
	if(HTTP_FLASE==a_http_stream->maybe_http_stream)
	{
		http_deleteEmptyRow(&(a_http_stream->packet_offset), (char*)(tcp_detail->pdata), tcp_detail->datalen);		
		uchar rec = http_judgeHttpProtocol(a_http_stream, a_tcp->curdir, tcp_detail, thread_seq);		
		if(rec==ERROR)
		{
			return APP_STATE_DROPME;
		}
		/*buf is not enough*/
		if(rec==GO_BACK)
		{
			a_http_stream->packet_offset = 0;
			return APP_STATE_GIVEME;	
		}			
		a_http_stream->maybe_http_stream = HTTP_TRUE;
		/*20181228*/
		//http_freeBuf(thread_seq,&a_http_stream->pbuf, &a_http_stream->buflen);	
	} 
	
	/*http_stat : packet_offset=0 for the same pkt is not stated twice*/
	if(g_http_prog_para.http_stat_cycle&&a_http_stream->maybe_http_stream==HTTP_TRUE&&a_http_stream->packet_offset==0)
	{
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_PKTS], FS_OP_TYPE_ADD, 1);
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_BITS], FS_OP_TYPE_ADD,tcp_detail->datalen);
	}

	/*http proxy*/
/*
#if HTTP_PROXY
	if(g_http_prog_para.proxy_switch)
	{
		if(a_http_stream->http_proxy!=0)
		{			
			if((a_http_stream->http_proxy&DIR_C2S && a_tcp->curdir==DIR_C2S) ||
				(a_http_stream->http_proxy&DIR_S2C && a_tcp->curdir==DIR_S2C))
			{
				return deal_tcp_in_proxy_stream(a_tcp,a_packet,a_http_stream->p_stream_proxy);
			}				
		}
	}	
#endif
*/

	/*http lost : lostlen must be proc befor http_initHttpConnection，相当于之前处理了*/
	if(tcp_detail->lostlen>0)
	{			
		if(g_http_prog_para.http_stat_cycle)
		{
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_LOST], FS_OP_TYPE_ADD, 1);
		}
		if(RLOG_LV_INFO>=g_http_prog_para.http_log_level)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "http lostlen : %s:%u", 
									printaddr(&a_tcp->addr,thread_seq), tcp_detail->lostlen);
		}		
		http_procLost(a_http_stream, a_tcp, thread_seq, a_packet);
	}

	/*init http session*/
	http_initHttpConnection(a_http_stream, thread_seq, a_tcp, a_packet);	
	/*packet process*/
	cur_http_node = (a_http_stream->res_req==DIR_C2S)?a_http_stream->last_link_node:a_http_stream->first_link_node;
	/*because maybe more \r\n...*/
	if(cur_http_node==NULL || tcp_detail->datalen-a_http_stream->packet_offset<=0) return APP_STATE_GIVEME;
	http_prevAnylse(cur_http_node, a_http_stream, thread_seq);
	
	/*avoid  keep HTTP_RETURN_DROPPKT*/
	cur_http_node->phttp_begin = (char*)tcp_detail->pdata+cur_http_node->processed_offset;

	//头部分析
	rec = http_analyseHttpReqResHeader(cur_http_node, a_http_stream, a_tcp, thread_seq, a_packet);
	switch(cur_http_node->mgs_status)
	{
		case HTTP_RETURN_RESET:
			if(a_http_stream->is_http_falgs==HTTP_FLASE)//确定不是http协议
			{					
				return APP_STATE_DROPME;
			}
			else
			{
				http_resetHttpStream(&a_http_stream, a_tcp, thread_seq, a_packet);					
				return APP_STATE_GIVEME;
			}					
			break;	

		case HTTP_RETURN_DROPPKT:
			cur_http_node->mgs_status = HTTP_RETURN_GIVEME;
			return_value |=  APP_STATE_DROPPKT;
			break;
			
		default:				
			break;
	}		
	
	/*main : go back*/
	if(rec!=OK&&a_http_stream->is_http_falgs==HTTP_TRUE) 
	{
		/*span pkt*/
		FLAG_SET(cur_http_node->flag, HTTP_FLAG_SPAN);
		if(g_http_prog_para.http_stat_cycle)
		{	
			if(!cur_http_node->header_span_flag)
			{
				stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_HEADER_SPAN_CNT], FS_OP_TYPE_ADD, 1);
				cur_http_node->header_span_flag = 1;
			}
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_HEADER_SPAN_PKT], FS_OP_TYPE_ADD, 1);
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_HEADER_SPAN_BYTE], FS_OP_TYPE_ADD, (char*)(tcp_detail->pdata)+cur_http_node->processed_offset-cur_http_node->phttp_begin);
		}
		if(g_http_prog_para.need_http_state)
		{	
			cur_http_node->interested_reg_mask = HTTP_STATE_MASK;	
			/*http state only keep 2 state*/
			if(cur_http_node->parser.http_state>=HTTP_REGION && cur_http_node->parser.http_state<HTTP_DATA_BEGIN)
			{
				cur_http_node->session.buf = cur_http_node->phttp_begin;	
				cur_http_node->session.buflen = (char*)(tcp_detail->pdata)+cur_http_node->processed_offset-cur_http_node->phttp_begin;
			}
		}
		/*batch mode, callback, span pkt ,callback.   cur_http_node->parser.curdir!=0 when start line*/
		/*批处理只处理*/
		//if(HTTP_CALLBACK_MODE_BATCH==g_http_prog_para.callback_mode || g_http_prog_para.need_http_state )
		if((HTTP_CALLBACK_MODE_BATCH==g_http_prog_para.callback_mode || g_http_prog_para.need_http_state)&& cur_http_node->parser.curdir!=0 )
		{
			http_callPlugin(cur_http_node, a_tcp, thread_seq, a_packet);
		}	
		return return_value|APP_STATE_GIVEME;	
	}

	/*more content in one pcaket*/
/*
#if HTTP_PROXY	
	if(g_http_prog_para.proxy_switch)
	{
		if(a_http_stream->is_proxy!=0)
		{				
			http_updatePktOffset(cur_http_node, a_http_stream, a_tcp);		
			if(a_http_stream->proc_pkt_continue)
			{	 
				a_http_stream->proc_pkt_continue = 0;
				return	return_value|http_analyseHttpConnection(a_http_stream, a_tcp, thread_seq, a_packet);	
			}	 
			return return_value;
		}	
	}
#endif
*/

	//消息体分析
	/*set mgs_status because cur_http_node maybe release*/
	uchar mgs_status = HTTP_RETURN_GIVEME;
	rec = http_findAndDoWithEntity(&mgs_status, cur_http_node, a_http_stream, a_tcp, thread_seq, a_packet);
	switch(mgs_status)
	{		
		case HTTP_RETURN_RESET:	
			http_resetHttpStream(&a_http_stream, a_tcp, thread_seq, a_packet);					
			return return_value|APP_STATE_GIVEME;
			break;	
			
		case HTTP_RETURN_DROPPKT:			
			return return_value|APP_STATE_DROPPKT;
			
		default:	
			break;				
	}
	if(rec!=OK) return return_value|APP_STATE_GIVEME;	
	
	/*session over, analyze again*/
	if(a_http_stream->proc_pkt_continue)
	{		
		/*clear*/
		a_http_stream->proc_pkt_continue = 0;
		return  return_value|http_analyseHttpConnection(a_http_stream, a_tcp, thread_seq, a_packet);				
	}	
	return return_value|APP_STATE_GIVEME;
}

#if DEBUG_TEST_DEAL_TIME	
#define LEVEL_INTERVAL 20
#define LEVEL_INTERVAL_NUM 11
void  http_stat_report(unsigned long long dealtime)
{		
	pthread_mutex_lock(&g_http_prog_para.stat_lock);
	struct timeval tv;
	unsigned long level = 0;
	gettimeofday(&tv, 0);
	
	unsigned long long now_time = tv.tv_sec* 1000*1000 + tv.tv_usec;
	static unsigned long long last_time = tv.tv_sec* 1000*1000 + tv.tv_usec;
	//unsigned long  pps = 0;
	/*interval stat*/
	level = dealtime/LEVEL_INTERVAL;
	if(level<LEVEL_INTERVAL_NUM-1)
	{
		g_http_prog_para.dealtime_level[level]++;
	}
	else
	{
		g_http_prog_para.dealtime_level[MAX_DEALTIME_LEVEL-1]++;
	}
		

	if(now_time-last_time<1000*1000)
	{		
		pthread_mutex_unlock(&g_http_prog_para.stat_lock);
		return;
	}

	/*output*/
	g_http_prog_para.pkt_dealtime_arv = g_http_prog_para.pkt_dealtime_total/g_http_prog_para.pkt_num;	
	fprintf(stdout,"------------------------------------------------------------------------\n");
	fprintf(stdout,"%15s%15s%15s%15s%15s\n", "pkt_deaitime", "MAX", "TOTAL","PKT_NUM", "ARV");
	fprintf(stdout,"%15s%15lu%15lu%15lu%15lu\n", "acc", g_http_prog_para.pkt_dealtime_max, g_http_prog_para.pkt_dealtime_total, g_http_prog_para.pkt_num, g_http_prog_para.pkt_dealtime_arv);

	for(unsigned long i=0;i<LEVEL_INTERVAL_NUM-1;i++)
	{
		fprintf(stdout,"[%lu-%lu]:%lu   %f \n", i*LEVEL_INTERVAL, (i+1)*LEVEL_INTERVAL,
												 g_http_prog_para.dealtime_level[i],
												 (float)((float)g_http_prog_para.dealtime_level[i]/(float)g_http_prog_para.pkt_num));
	}
	fprintf(stdout,"[%lu-]:%lu    %f\n", (unsigned long)(LEVEL_INTERVAL_NUM-1)*LEVEL_INTERVAL,
												 g_http_prog_para.dealtime_level[MAX_DEALTIME_LEVEL-1],
												  (float)((float)g_http_prog_para.dealtime_level[MAX_DEALTIME_LEVEL-1]/(float)g_http_prog_para.pkt_num));
	fprintf(stdout,"\n\n\n");
	last_time = now_time;	
	pthread_mutex_unlock(&g_http_prog_para.stat_lock);
}
#endif

char HTTP_ENTRY(struct streaminfo *a_tcp, void**pme, int thread_seq, void *a_packet)
{
#if DEBUG_TEST_DEAL_TIME	
	struct timeval tv;
	unsigned long long bgn_time = 0;
	unsigned long long end_time = 0;
	unsigned long long pkt_dealtime = 0;
	gettimeofday(&tv, 0);
	bgn_time = tv.tv_sec* 1000*1000 + tv.tv_usec;
    g_http_prog_para.pkt_num++;
#endif

	/*no biz*/
	if(g_http_prog_para.not_proc) return APP_STATE_DROPME;	

#if HTTP_STATIC
	long long before = 0;
	long long after = 0;
	long long dealtime = 0;

	/*static pkt dealtime*/
	if(g_http_prog_para.http_stat_cycle)
	{
		before = rdtsc();
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_TCP_PKT_CALLBACK], FS_OP_TYPE_ADD, 1);
	}
#endif

	uchar rec = APP_STATE_GIVEME;
	http_stream *a_http_stream = (http_stream *)*pme;

	switch(a_tcp->opstate)
	{
		case OP_STATE_PENDING:
			 http_initHttpStream(&a_http_stream, thread_seq);
			 *pme = a_http_stream;			  
		case OP_STATE_DATA:
		case OP_STATE_CLOSE:
#if HTTP_PROXY	
			if(g_http_prog_para.proxy_switch)
			{
				if(a_http_stream->p_stream_proxy!=NULL)
				{
					a_http_stream->p_stream_proxy->opstate = OP_STATE_CLOSE;
				}
			}
#endif		
			rec = http_analyseHttpConnection(a_http_stream, a_tcp, thread_seq, a_packet);			
			a_http_stream->packet_offset = 0;			
			break;
		default:
			break;
	}

	if(OP_STATE_CLOSE==a_tcp->opstate||APP_STATE_DROPME&rec)
	{
		http_releaseHttpStream(&a_http_stream, a_tcp, thread_seq, a_packet);			
		*pme = NULL;
	}

#if HTTP_STATIC
	/*static pkt dealtime*/
	if(g_http_prog_para.http_stat_cycle)
	{
		after = rdtsc();
		dealtime = after-before;
		g_http_prog_para.tcppkt_dealtime_max = MAX(dealtime, g_http_prog_para.tcppkt_dealtime_max);
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_TCP_PKT_PROC_TIME], FS_OP_TYPE_ADD, dealtime);
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_TCP_PKT_PROC_MAXTIME], FS_OP_TYPE_SET, g_http_prog_para.tcppkt_dealtime_max);
	}
#endif

#if DEBUG_TEST_DEAL_TIME	
	gettimeofday(&tv, 0);
	end_time = tv.tv_sec*1000*1000 + tv.tv_usec;
	pkt_dealtime = end_time-bgn_time;
	g_http_prog_para.pkt_dealtime_total += pkt_dealtime;
	g_http_prog_para.pkt_dealtime_max = MAX(pkt_dealtime, g_http_prog_para.pkt_dealtime_max);	
	http_stat_report(pkt_dealtime);
#endif
	return rec;
}
