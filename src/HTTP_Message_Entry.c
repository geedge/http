#include <stdio.h>
#include <ctype.h>
#include "HTTP_Message_Entry.h"
#include "HTTP_Message_Header.h"
#include "MESA_handle_logger.h"
#include "HTTP_Common.h"
#include "field_stat.h"

extern http_prog_runtime_parameter_t g_http_prog_para;

/**********************************************************
 *entity is over
 **********************************************************/
static void http_clearSpace(http_stream *a_http_stream, struct streaminfo *a_tcp,
							int thread_seq, void *a_packet)
{	
	if(DIR_C2S == a_http_stream->res_req)
	{
		/*one-way traffic*/
		if(DIR_C2S==a_http_stream->dir)
		{
			//http_reseaseHttpInfor(a_http_stream,a_tcp, thread_seq, a_packet);
			while(NULL!=(a_http_stream)->first_link_node)
			{
				http_releaseHttpLinkNode(a_http_stream, a_tcp, thread_seq, a_packet);
				a_http_stream->last_link_node = NULL;
			}
		}
		else
		{
			http_resetResponseSpace(a_http_stream->last_link_node, thread_seq);
			a_http_stream->last_link_node->parser.http_state = HTTP_DATA_END;			
		}
	}
	else
	{		
		http_reseaseHttpInfor(a_http_stream,a_tcp, thread_seq, a_packet);
	}
	return;
}

void http_doWithGzipData(http_parser_t *cur_http_node, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	int		ret = 0;
	result_array_t *result_array = (result_array_t*)dictator_malloc(thread_seq, sizeof(result_array_t));
	memset(result_array, 0, sizeof(result_array_t));
	if(cur_http_node->ungzip_handle==NULL)
	{
		//20160128
		switch(cur_http_node->parser.cont_encoding)
		{
			case HTTP_CONT_ENCOD_GZIP:				
				cur_http_node->ungzip_handle=docanalyze_startstream(DOC_GZIP_TYPE, g_http_prog_para.docanly_handler, thread_seq);
				break;
				
			case HTTP_CONT_ENCOD_DEFLATE:				
				cur_http_node->ungzip_handle=docanalyze_startstream(DOC_DEFLATE_TYPE, g_http_prog_para.docanly_handler, thread_seq);
				break;
				
			default:
				break;
		}	
	}

	if(cur_http_node->ungzip_handle==NULL)
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "docanalyze_startstream error!");
		dictator_free(thread_seq, result_array);
		return ;
	}
	ret = docanalyze_parsestream(cur_http_node->ungzip_handle,
								(const char*)cur_http_node->session.buf, 
								cur_http_node->session.buflen,
								result_array);
	if(ret==DOC_PRO_OK)
	{
		cur_http_node->parser.append_infor.content = cur_http_node->session.buf;
		cur_http_node->parser.append_infor.contlen = cur_http_node->session.buflen;
		cur_http_node->session.buf =NULL;
		cur_http_node->session.buflen = 0;
		for (int k=0; k < result_array->result_num; k++)
		{
			cur_http_node->session.buf = (char*)dictator_realloc(thread_seq, cur_http_node->session.buf,cur_http_node->session.buflen+result_array->result_buff->size);
			memcpy(cur_http_node->session.buf+cur_http_node->session.buflen,
				     result_array->result_buff->presult,
				     result_array->result_buff->size);
			cur_http_node->session.buflen += result_array->result_buff->size;     		 	
		}
		FLAG_SET(cur_http_node->flag, HTTP_FLAG_BATCH_CALLBACK);
		http_callPlugin(cur_http_node, a_tcp, thread_seq, a_packet);
		if(cur_http_node->session.buf!=NULL)
		{
			dictator_free(thread_seq, cur_http_node->session.buf);
			cur_http_node->session.buf = NULL;	
			cur_http_node->session.buflen = 0;			
		}
		cur_http_node->parser.append_infor.content = NULL;
		cur_http_node->parser.append_infor.contlen = 0;
	}
	else if(ret==DOC_PRO_ERR)
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "docanalyze_parsestream return DOC_PRO_ERR!");
	}
	docanalyze_freeresult(result_array);
	dictator_free(thread_seq, result_array);
	return ;
}

void http_judgeContentEncoding(http_parser_t *a_http, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	char* entity_data = a_http->session.buf;
	uint32 entity_datalen = a_http->session.buflen;
	unsigned long long region_flag_ungzip = g_http_prog_para.http_interested_region_flag;	
	unsigned long long region_flag = g_http_prog_para.http_interested_region_flag;
    region_flag_ungzip &= HTTP_UNGZIP_CONTENT;   	
	region_flag &= HTTP_CONTENT;

	/*static*/
	if(g_http_prog_para.http_stat_cycle)
	{
		if(DIR_C2S==a_http->parser.curdir)
		{
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CONTENT_C2S], FS_OP_TYPE_ADD,entity_datalen);
		}
		else
		{
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_CONTENT_S2C], FS_OP_TYPE_ADD,entity_datalen);
		}		
	}		

	if(region_flag_ungzip && g_http_prog_para.ungzip_switch && !FLAG_TEST(a_http->flag, HTTP_FLAG_NO_UNGZIP))
	{		
		a_http->interested_reg_mask = HTTP_UNGZIP_CONTENT_MASK;
		//20160128
		if(HTTP_CONT_ENCOD_GZIP==a_http->parser.cont_encoding||HTTP_CONT_ENCOD_DEFLATE==a_http->parser.cont_encoding)	
		{	
			http_doWithGzipData(a_http, a_tcp, thread_seq, a_packet);
		}
		else				
		{			
			FLAG_SET(a_http->flag, HTTP_FLAG_BATCH_CALLBACK);
			http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
		}			
	}
	if(region_flag)
	{	
		a_http->session.buf = entity_data;
		a_http->session.buflen = entity_datalen;	
		a_http->interested_reg_mask = HTTP_CONTENT_MASK; 
		FLAG_SET(a_http->flag, HTTP_FLAG_BATCH_CALLBACK);
		http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	}	
		
	a_http->interested_reg_mask = HTTP_CONTENT_MASK;	
	/*may not call biz plugin*/
	a_http->session.buf = NULL;
	a_http->session.buflen = 0;	
	return ;
}

uchar http_doWithDefaultData(http_parser_t *a_http, http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	uchar rec = OK;
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;
	uint32*	offset = &(a_http->processed_offset);
	char*	cur_data = (char*)(tcp_detail->pdata);		
	uint32	len = tcp_detail->datalen - *offset;
	
	if(tcp_detail->datalen >= a_http->packet_entity_len + a_http->processed_offset)
	{		
		a_http->parser.http_state = HTTP_DATA_END;
		a_http->session.buflen = a_http->packet_entity_len;	
		if(a_http->session.buflen > 0)
		{
			a_http->session.buf = cur_data+*offset;
		}	
		*offset += a_http->packet_entity_len;	
		a_http->packet_entity_len = 0;		
		a_http->acc_cont_length += a_http->packet_entity_len;
	}
	else
	{
		a_http->session.buflen = len;	
		if(a_http->session.buflen > 0)
		{
			a_http->session.buf = cur_data+*offset;
		}				
		*offset += len;	
		a_http->packet_entity_len -= len;
		a_http->acc_cont_length += len;
		rec = GO_BACK;
	}	
	
	http_judgeContentEncoding(a_http, a_tcp, thread_seq, a_packet);
	
	return rec;
}

uchar http_doWithCnntcloseData(http_parser_t *a_http, http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	uchar rec = OK;
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;
	uint32 *offset = &(a_http->processed_offset);
	char *cur_data = (char*)(tcp_detail->pdata);		
	uint32 len = tcp_detail->datalen - *offset;
	
	if(a_tcp->opstate==OP_STATE_CLOSE)
	{
		a_http->parser.http_state = HTTP_DATA_END;
		a_http->session.buflen = len;	
		if(a_http->session.buflen > 0)
		{
			a_http->session.buf = cur_data+*offset;
		}			
		a_http->acc_cont_length += len;
		*offset += len;			
		a_http->parser.cont_length = a_http->acc_cont_length;
	}
	else
	{
		a_http->session.buflen = len;	
		if(a_http->session.buflen > 0)
		{
			a_http->session.buf = cur_data+*offset;
		}				
		a_http->acc_cont_length += len;
		*offset += len;			
		rec = GO_BACK;
	}
		
	http_judgeContentEncoding(a_http, a_tcp, thread_seq, a_packet);
	
	return rec;
}

uchar http_doWithProxyData(http_parser_t *a_http, http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	uchar rec = OK;
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;
	uint32 *offset = &(a_http->processed_offset);
	uint32 len = tcp_detail->datalen - *offset;
	
	if(a_tcp->opstate==OP_STATE_CLOSE)
	{
		a_http->parser.http_state = HTTP_DATA_END;			
		*offset += len;			
	}
	else
	{	
		*offset += len;			
		rec = GO_BACK;
	}	
	/*从下一个pkt开始回调，否则如果代理里面是HTTP，会造成无限循环*/
	if(len==0)
	{
		a_http->proxy_cb_flag = 1;
	}
	if(len>0 && a_http->proxy_cb_flag)
	{
		deal_tcp_in_proxy_stream(a_tcp,a_packet,a_http_stream->p_stream_proxy); 
	}
	return rec;
}


/**********************************************************
 * 功能：寻找chunked的数据开始位置.
 * a_http_node:消息节点,既是输入参数，也是返回参数。
 * cur_half：当前数据。
 * 注：after_cr_data_len<1表明没找到开始位置
 *   		 (*a_http_node)->crlf_offset<1表明没得到长度。
 **********************************************************/
uchar http_findChunkedDataStartPos(http_parser_t *a_http_node, uchar *tcp_data, UINT32 tcp_data_len)
{
	uint32 *offset = &((a_http_node)->processed_offset);
	if(*offset == tcp_data_len)
	{
		return GO_BACK;
	}
	if(*offset+1==tcp_data_len)
	{
		if('\n'==*(tcp_data+*offset))
		{
			*offset += 1;		
			a_http_node->chunk_state=HTTP_CHUNK_STATE_DATA;
			return GO_BACK;
		}		
		a_http_node->chunk_state=HTTP_CHUNK_STATE_DATA;
		return OK;
	}
	if(tcp_data_len>=2+*offset)
	{
		if('\n'==*(tcp_data+*offset)) (*offset)++;		
		a_http_node->chunk_state=HTTP_CHUNK_STATE_DATA;
		return OK;
	}	
	return OK;
}

uchar http_readChunkedData(http_parser_t *a_http, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;
	uint32*	offset = &a_http->processed_offset;	
	char*	cur_data = (char*)(tcp_detail->pdata);	
	uint32 	len = 0;
	uchar 	rec = OK;
		
	len = tcp_detail->datalen - *offset;
	
	if(a_http->packet_entity_len+*offset <= tcp_detail->datalen)
	{
		a_http->session.buflen = a_http->packet_entity_len;		
		if(a_http->session.buflen > 0)
		{
			a_http->session.buf = cur_data+*offset;
		}	
		*offset += a_http->packet_entity_len;	
		a_http->packet_entity_len = 0; 
		a_http->chunk_state = HTTP_CHUNK_STATE_UNKONWN;
		a_http->acc_cont_length += a_http->packet_entity_len;
		
	}
	else
	{
		a_http->session.buflen = len;
		if(a_http->session.buflen > 0)
		{
			a_http->session.buf = cur_data+*offset;
		}		
		*offset += len;	
		a_http->packet_entity_len -= len;
		a_http->acc_cont_length += len;
		rec = GO_BACK;		
	}	
	http_judgeContentEncoding(a_http, a_tcp, thread_seq, a_packet);
	return rec;
}

/**********************************************************
 * 功能：读取chunked的长度.
 * a_http_node:消息节点,既是输入参数，也是返回参数。
 * chunked_len:输出值。chunked数据长度.
 * cur_half：当前数据。
 * return : HTTP_RETURN_SPAN_PACKET HTTP_RETURN_UNNORM
 **********************************************************/
uchar http_readChunkedLength(struct streaminfo *a_tcp, http_parser_t *a_http, char *tcp_data, uint32 tcp_data_len,int thread_seq)
{
	uint32 	end_flag = 0;		
	char*	cr_pos = NULL;
	uint32 	data_len = 0;
	uint32 	i=0;
	char 	chunklen_buf[32] = {0};
	uint32* offset = &a_http->processed_offset;

	/*上一次buf有数据*/
	if(0==a_http->buflen)
	{		
		http_deleteEmptyRow_chunk(offset, tcp_data, tcp_data_len);
	}		
	data_len = tcp_data_len-*offset;
	cr_pos = http_findCRLF_Chunk(tcp_data+*offset, data_len, &end_flag);
	if(NULL==cr_pos)
	{	
		if(data_len>0)
		{		
			a_http->pbuf = (char*)dictator_realloc(thread_seq,a_http->pbuf, a_http->buflen+data_len);
			memcpy(a_http->pbuf+a_http->buflen, tcp_data+*offset, data_len);
			a_http->buflen += data_len;
			*offset += data_len;		
		}
		return GO_BACK;
	}
	if(a_http->buflen>0)
	{		
		if(a_http->buflen>=sizeof(chunklen_buf)) return ERROR;
		memcpy(chunklen_buf, a_http->pbuf, a_http->buflen);
		http_freeBuf(thread_seq, &a_http->pbuf, &a_http->buflen);		
	}
	data_len = cr_pos-tcp_data-*offset;		
	if(data_len>=sizeof(chunklen_buf)-strlen(chunklen_buf)) return ERROR;
	memcpy(chunklen_buf+strlen(chunklen_buf), tcp_data + *offset, data_len);	
	*offset += data_len+end_flag;
	
	for(i=0;i<strlen(chunklen_buf);i++)
	{
		if(0==isxdigit(*(chunklen_buf+i)))  return ERROR;
	}
	
	sscanf(chunklen_buf, "%Lx", &(a_http->packet_entity_len));
	a_http->chunk_state = HTTP_CHUNK_STATE_LENGTH;
	if((int)(a_http->packet_entity_len)<0)
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "chunk_len errpr %lld:%s", (int)(a_http->packet_entity_len), printaddr(&a_tcp->addr,thread_seq));
		return ERROR;
	}
	else if(0==a_http->packet_entity_len)
	{
		/*delete 0\r\n\r\n...*/
		http_deleteEmptyRow_chunk(offset, tcp_data, tcp_data_len);
	}	
	return OK;
}

uchar http_doWithChunkedData(http_parser_t *cur_http_node, http_stream *a_http_stream,
										struct streaminfo *a_tcp,int thread_seq, void *a_packet)
{
	uchar rec=OK;	
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;
	/*malloc to cache chunk_length*/	
	while(1)
	{ 
		if(cur_http_node->chunk_state==HTTP_CHUNK_STATE_UNKONWN)
		{
			rec = http_readChunkedLength(a_tcp, cur_http_node, (char*)(tcp_detail->pdata), tcp_detail->datalen, thread_seq);
			if(GO_BACK==rec) return GO_BACK;
			if(ERROR==rec) 
			{
				cur_http_node->mgs_status = HTTP_RETURN_RESET;
				return ERROR;
			}
			/*chunk over*/
			if(0==cur_http_node->packet_entity_len)
			{
				cur_http_node->parser.http_state = HTTP_DATA_END;					
				cur_http_node->parser.cont_length = cur_http_node->acc_cont_length;
				return OK;
			}
		}		
		if(cur_http_node->chunk_state==HTTP_CHUNK_STATE_LENGTH)
		{
			if(OK!=http_findChunkedDataStartPos(cur_http_node, (uchar*)(tcp_detail->pdata),tcp_detail->datalen))  return GO_BACK;		
		}		
		if(cur_http_node->chunk_state==HTTP_CHUNK_STATE_DATA)
		{
			if(OK!=http_readChunkedData(cur_http_node, a_tcp, thread_seq, a_packet))  return GO_BACK;		
		}	
	}
	return OK;	
}

/*return GO_BACK  OK ERROR*/
uchar http_doWithEntity(http_parser_t *cur_http_node, http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	uchar rec = OK;		
	uint32 len = ((struct tcpdetail*)a_tcp->pdetail)->datalen - cur_http_node->processed_offset;
	
	if(len<=0) return GO_BACK;
	
	if(HTTP_TRANS_ENCOD_CHUNKED==cur_http_node->parser.trans_encoding)
	{
		rec = http_doWithChunkedData(cur_http_node, a_http_stream, a_tcp,thread_seq, a_packet);
	}	
	else if(HTTP_TRANS_ENCOD_CNNTCLOSE==cur_http_node->parser.trans_encoding)
	{
		rec = http_doWithCnntcloseData(cur_http_node, a_http_stream,a_tcp,thread_seq, a_packet);
	}
	/*Switching Protocols*/
	else if(cur_http_node->parser.res_code==101)
	{
		rec = http_doWithCnntcloseData(cur_http_node, a_http_stream,a_tcp,thread_seq, a_packet);
	}
	else if(a_http_stream->is_proxy)
	{	
		rec = http_doWithProxyData(cur_http_node, a_http_stream,a_tcp,thread_seq, a_packet);
	}
	else
	{
		rec = http_doWithDefaultData(cur_http_node, a_http_stream, a_tcp,thread_seq, a_packet);
	}	
	
	if(HTTP_DATA_END==cur_http_node->parser.http_state)
	{
		if(DIR_C2S==a_http_stream->dir||DIR_S2C==cur_http_node->parser.curdir||DIR_S2C==a_tcp->curdir)
		{		
			FLAG_SET(cur_http_node->flag, HTTP_FLAG_OVER);
		}
		/*output http state or http over*/
		if(g_http_prog_para.need_http_state|| FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER))
		{			
			FLAG_SET(cur_http_node->flag, HTTP_FLAG_BATCH_CALLBACK);
			if(g_http_prog_para.need_http_state)
			{
				cur_http_node->interested_reg_mask = HTTP_STATE_MASK;
			}
			http_callPlugin(cur_http_node, a_tcp, thread_seq, a_packet);
		}	
	}	
	return OK;
}

uchar http_judgeRequestEntityPresent(http_parser_t *cur_http_node, http_stream *a_http_stream, 
									  struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	/*have not entity*/
	if(0==cur_http_node->parser.cont_length && HTTP_TRANS_ENCOD_CHUNKED != cur_http_node->parser.trans_encoding && !a_http_stream->is_proxy)
	{		
		//one-way traffic
		if(DIR_C2S==a_http_stream->dir)
		{		
			FLAG_SET(cur_http_node->flag, HTTP_FLAG_OVER);
		}
		
		cur_http_node->parser.http_state = HTTP_DATA_END;		
		/*output http state or http over*/
		if(g_http_prog_para.need_http_state||FLAG_TEST(cur_http_node->flag, HTTP_FLAG_OVER))
		{			
			FLAG_SET(cur_http_node->flag, HTTP_FLAG_BATCH_CALLBACK);
			if(g_http_prog_para.need_http_state)
			{
				cur_http_node->interested_reg_mask = HTTP_STATE_MASK;
			}		
			http_callPlugin(cur_http_node, a_tcp, thread_seq, a_packet);	
		}		
		return ERROR;
	}	
	return OK;
}

uchar http_judgeResponseEntityPresent(http_parser_t *a_http,  http_stream* a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	/*temp ack: reset response */
	if(a_http->parser.res_code==100)
	{				
		http_resetResponseSpace(a_http, thread_seq);		
		return ERROR;
	}
	
	if(
		(0==a_http->parser.cont_length && HTTP_TRANS_ENCOD_CHUNKED != a_http->parser.trans_encoding && HTTP_TRANS_ENCOD_CNNTCLOSE!= a_http->parser.trans_encoding && !a_http_stream->is_proxy && a_http->parser.res_code!=101) ||
		HTTP_METHOD_HEAD==a_http->parser.method ||		
		(a_http->parser.res_code>101 && a_http->parser.res_code<200) ||
		204==(a_http->parser.res_code) ||
		304==a_http->parser.res_code
		)
	{		
		FLAG_SET(a_http->flag, HTTP_FLAG_OVER);	
		a_http->parser.http_state = HTTP_DATA_END;	
		
		/*output http state or http over*/
		if(g_http_prog_para.need_http_state||FLAG_TEST(a_http->flag, HTTP_FLAG_OVER))
		{
			FLAG_SET(a_http->flag, HTTP_FLAG_BATCH_CALLBACK);			
			if(g_http_prog_para.need_http_state)
			{
				a_http->interested_reg_mask = HTTP_STATE_MASK;
			}
			http_callPlugin(a_http, a_tcp, thread_seq, a_packet);	
		}	
		return ERROR;
	}	
	return OK;
}/*http_judgeResponseEntityPresent*/

uchar http_judgeEntityPresent(http_parser_t *cur_http_node, http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	uchar rec=OK;
	if(DIR_S2C==a_http_stream->res_req)
	{		
		rec = http_judgeResponseEntityPresent(cur_http_node, a_http_stream, a_tcp, thread_seq, a_packet);			
	}
	else
	{		
		rec = http_judgeRequestEntityPresent(cur_http_node, a_http_stream, a_tcp, thread_seq, a_packet);		
	}	
	return rec;
}

uchar http_findAndDoWithEntity(uchar* msg_status, http_parser_t *a_http, http_stream* a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	uchar 	rec = OK;
	
	if(HTTP_DATA!=a_http->parser.http_state && HTTP_DATA_BEGIN!=a_http->parser.http_state)	return OK;

	if(a_http->parser.http_state==HTTP_DATA_BEGIN)
	{	
		rec = http_judgeEntityPresent(a_http, a_http_stream, a_tcp, thread_seq, a_packet);
		if(ERROR==rec)/*have not entity*/
		{					
			*msg_status = a_http->mgs_status;
			a_http->mgs_status = HTTP_RETURN_GIVEME;
			http_updatePktOffset(a_http, a_http_stream, a_tcp); 		
			if(HTTP_DATA_END==a_http->parser.http_state)
			{					
				http_clearSpace(a_http_stream, a_tcp, thread_seq, a_packet);		
			}	
			return OK;
		}
		else /*have entity*/
		{
			a_http->parser.http_state = HTTP_DATA;			
			a_http->interested_reg_mask = HTTP_CONTENT_MASK;	
		}
	}

	if(a_http->parser.http_state==HTTP_DATA)
	{
		rec = http_doWithEntity(a_http, a_http_stream, a_tcp, thread_seq, a_packet); 		
		http_updatePktOffset(a_http, a_http_stream, a_tcp); 		
		*msg_status = a_http->mgs_status;
		a_http->mgs_status = HTTP_RETURN_GIVEME;
		if(HTTP_DATA_END==a_http->parser.http_state)
		{					
			http_clearSpace(a_http_stream, a_tcp, thread_seq, a_packet);		
		}		
	}	
	return rec;
}
