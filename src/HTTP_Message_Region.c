#include <ctype.h>
#include <assert.h>
#include <arpa/inet.h>


#include "HTTP_Message_Region.h"
#include "HTTP_Common.h"
#include "HTTP_Message_Header.h"
#include "MESA_handle_logger.h"
#include "MESA_htable.h"
#include "field_stat.h"

extern http_prog_runtime_parameter_t 	g_http_prog_para;
extern string_map_t  					g_http_regions[];

uchar http_doWithProxyRegion(http_parser_t *a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 	 								   			  
							   struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
#if HTTP_PROXY
	if(g_http_prog_para.proxy_switch)
	{
		if(a_http->proxy_flag == HTTP_TRUE && NULL!=((http_stream*)(a_http_stream))->p_stream_proxy)
		{
			struct proxydetail* p_proxy_detail = (struct proxydetail *)(((http_stream*)(a_http_stream))->p_stream_proxy->pdetail);
			if(p_proxy_detail!=NULL)
			{
				p_proxy_detail->pUser = (UCHAR*)dictator_malloc(thread_seq, valuelen);
				memcpy(p_proxy_detail->pUser, (uchar*)value, valuelen); 				
			}		
		}
	}		
#endif    
	return http_doWithDefaultRegion(a_http, a_http_stream, value, valuelen,a_tcp, thread_seq, a_packet);	
}

uchar http_doWithCharset(http_parser_t *a_http,  char* value, uint32 valuelen, char *semicolon_pos, 
						  struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	char* 	equals_pos=NULL;
	uint32 	charset_type_len = 0,start_pos=0;	
	char 	region_name[REGION_NAME_LEN] = {0};
	
	equals_pos = (char*)memchr(semicolon_pos,'=',valuelen-(semicolon_pos-value));
	if(equals_pos==NULL)
	{
		equals_pos = (char*)memchr(semicolon_pos,':',valuelen-(semicolon_pos-value));
	}	
	if(equals_pos!=NULL)
	{  
		memcpy(region_name, semicolon_pos+1, MIN(REGION_NAME_LEN-1, equals_pos-(semicolon_pos+1)));
		if(NULL==memcasemem(region_name, strlen(region_name), "charset", sizeof("charset")-1)) return OK;
		charset_type_len = valuelen-(equals_pos-value)-1;
		http_deleteEmptyRow(&start_pos, equals_pos+1, charset_type_len);
		charset_type_len -= start_pos;	
		a_http->interested_reg_mask = HTTP_CHARSET_MASK;
		a_http->session.buf =  equals_pos+1+start_pos;
		a_http->session.buflen = charset_type_len;			
		http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	}
	return OK;
}

/**********************************************************

***********************************************************/
uchar http_doWithContentType(http_parser_t *a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 
							   struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	char *semicolon_pos=(char*)memchr(value,';',valuelen);;
	uint32 cont_type_dellen=0;		
	if(NULL!=semicolon_pos)
	{		
		http_doWithCharset(a_http, value, valuelen, semicolon_pos, a_tcp,thread_seq, a_packet);
		a_http->interested_reg_mask = HTTP_CONT_TYPE_MASK;
		valuelen = semicolon_pos-value;
		http_deleteSPHTCRLFAtLast(&cont_type_dellen, value, valuelen);	
		a_http->session.buf =  value;
		a_http->session.buflen = cont_type_dellen;			
	}
	else 
	{		
		a_http->session.buf =  value;
		a_http->session.buflen = valuelen;		
	}	
	http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	return OK;
}

/**********************************************************
 
***********************************************************/
uchar http_doWithHost(http_parser_t* a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 								   
					   struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{		
	if(a_tcp->curdir==DIR_S2C) return OK;	
	char*	uri = NULL;
	uint32 	urilen = 0;	
	uint64 	region_flag_host = g_http_prog_para.http_interested_region_flag & HTTP_HOST ;	
	uint64 	region_flag_url = g_http_prog_para.http_interested_region_flag & HTTP_MESSAGE_URL;
	
	FLAG_SET(a_http->flag, HTTP_FLAG_GET_URL);

	/*not joint URL when proxy and absolute uri*/
	if(a_http->parser.method!=HTTP_METHOD_CONNECT)
	{
		if(a_http->url_buf==NULL||a_http->url_buf[0]=='/')
		{
			uri = (char*)dictator_malloc(thread_seq, a_http->url_buflen);
			urilen = a_http->url_buflen;
			memcpy(uri, a_http->url_buf, a_http->url_buflen);
			if(a_http->url_buf!=NULL) dictator_free(thread_seq, a_http->url_buf);
			a_http->url_buf = NULL;
			a_http->url_buflen = valuelen+urilen;
			a_http->url_buf = (char*)dictator_malloc(thread_seq, a_http->url_buflen);
			memcpy(a_http->url_buf, value, valuelen);
			memcpy(a_http->url_buf+valuelen, uri, urilen);
			if(uri!=NULL) 
			{
				dictator_free(thread_seq, uri); 
				uri = NULL;
			}	
		}
		/*20190111 ¾ø¶ÔURI*/
		else if(a_http->url_buf!=NULL && a_http->url_buflen>=strlen("http://") && 0==strncasecmp(a_http->url_buf, "http://", strlen("http://")))
		{
			a_http->parser.is_ab_uri = 1;
		}	
		/*URI=sample.html, do not start with '/'; then we add a '/' */ 
		else if(a_http->url_buf!=NULL && a_http->url_buf[0]!='/')
		{
			uri = (char*)dictator_malloc(thread_seq, a_http->url_buflen);
			urilen = a_http->url_buflen;
			memcpy(uri, a_http->url_buf, a_http->url_buflen);
			if(a_http->url_buf!=NULL) dictator_free(thread_seq, a_http->url_buf);
			a_http->url_buf = NULL;
			a_http->url_buflen = valuelen+strlen("/")+urilen;
			a_http->url_buf = (char*)dictator_malloc(thread_seq, a_http->url_buflen);
			memcpy(a_http->url_buf, value, valuelen);
			memcpy(a_http->url_buf+valuelen, "/", strlen("/"));
			memcpy(a_http->url_buf+valuelen+strlen("/"), uri, urilen);
			if(uri!=NULL) 
			{
				dictator_free(thread_seq, uri); 
				uri = NULL;
			}			
		}
	}	
	
	a_http->parser.p_url = a_http->url_buf;
	a_http->parser.url_len = a_http->url_buflen;	
	
	if(region_flag_host && valuelen>0)
	{
		a_http->interested_reg_mask = HTTP_HOST_MASK;
		a_http->session.buf = value;
		a_http->session.buflen = valuelen;
		http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	}
	
	if(region_flag_url)
	{		
		a_http->interested_reg_mask = HTTP_MESSAGE_URL_MASK; 
		a_http->session.buf = a_http->url_buf;
		a_http->session.buflen = a_http->url_buflen;		
		http_callPlugin(a_http, a_tcp, thread_seq, a_packet);		
		if(g_http_prog_para.http_log_level<=RLOG_LV_DEBUG)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_DEBUG, HTTP_PLUGIN_NAME, "%s:%lu HOST_URL:%s", 
									printaddr(&a_tcp->addr,thread_seq),a_http->parser.http_session_seq,a_http->url_buf);
		}
	}	
	return OK;
}

uchar http_recogniseTransferEncoding(uchar *trans_Encoding, char *value_data,uint32 value_data_len, int thread_seq)
{
	if(0==strncasecmp(value_data,"chunked",sizeof("chunked")-1))
		*trans_Encoding = HTTP_TRANS_ENCOD_CHUNKED;
	else
		*trans_Encoding = HTTP_TRANS_ENCOD_OTHERS;

	return OK;
}
uchar http_recogniseContentEncoding(uchar *Cont_Encoding, char *value_data,uint32 value_data_len, int thread_seq)
{	
	if(0==strncasecmp(value_data,"gzip", sizeof("gzip")-1))
		*Cont_Encoding = HTTP_CONT_ENCOD_GZIP;
	else if(0==strncasecmp(value_data,"compress",sizeof("compress")-1))
		*Cont_Encoding = HTTP_CONT_ENCOD_COMPRESS;
	else if(0==strncasecmp(value_data,"deflate",sizeof("deflate")-1))
		*Cont_Encoding = HTTP_CONT_ENCOD_DEFLATE;
	else if(0==strncasecmp(value_data,"default",sizeof("default")-1))
		*Cont_Encoding = HTTP_CONT_ENCOD_DEFAULT;
	else
		*Cont_Encoding = HTTP_CONT_ENCOD_OTHERS;
	return OK;
}

uchar http_doWithEncoding(http_parser_t* a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 								   			  
						    struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	switch(a_http->interested_reg_mask)
	{
		case HTTP_TRANSFER_ENCODING_MASK:
			http_recogniseTransferEncoding(&(a_http->parser.trans_encoding),(char*)value,valuelen, thread_seq);
			break;
		case HTTP_CONT_ENCODING_MASK:
			http_recogniseContentEncoding(&(a_http->parser.cont_encoding), (char*)value,valuelen, thread_seq);
			break;
		default:
			return OK;
			break;
	}		
	a_http->session.buf = value;
	a_http->session.buflen = valuelen;
	http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	return OK;
}

uchar http_doWithLength(http_parser_t *a_http, int64 *cont_len, char* value, uint32 valuelen,  struct streaminfo *a_tcp, int thread_seq)
{
	char 	char_len[HTTP_MAX_UINT64_LEN]={0};	
	
	memcpy(char_len, value, MIN(valuelen,HTTP_MAX_UINT64_LEN-1));
   	*cont_len = strtol(char_len, NULL, 10);
	//20150323 content-length : -1
	if(*cont_len==-1)
	{
		a_http->mgs_status = HTTP_RETURN_RESET;
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "content length error. addr:%s, content-length:%lld", 
								printaddr(&a_tcp->addr, thread_seq), *cont_len);
		return ERROR;
	}
	return OK;
}

uchar http_doWithTransferLength(http_parser_t* a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 	 								   			  
								  struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	if(HTTP_TRANS_ENCOD_CHUNKED==a_http->parser.trans_encoding ) return OK;	
	int64 len = 0;	
	uchar rec = http_doWithLength(a_http, &len, value, valuelen, a_tcp, thread_seq);
	if(ERROR==rec) return ERROR;
	a_http->parser.cont_length = len;
	a_http->packet_entity_len = len;
	FLAG_SET(a_http->flag, HTTP_FLAG_TRANS_LEN);
	a_http->session.buf = value;
	a_http->session.buflen = valuelen;	
	http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	return OK;
}

uchar http_doWithContentLength(http_parser_t* a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 	 								   			  
								 struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	if(HTTP_TRANS_ENCOD_CHUNKED==a_http->parser.trans_encoding ) return OK;	
	int64 len=0;	
	uchar rec = http_doWithLength(a_http, &len, value, valuelen, a_tcp, thread_seq);
	if(ERROR==rec) return ERROR;	
	if(!FLAG_TEST(a_http->flag, HTTP_FLAG_TRANS_LEN))
	{
		a_http->parser.cont_length = len;
		a_http->packet_entity_len = len;
	}	
	a_http->session.buf = value;
	a_http->session.buflen = valuelen;
	http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	return OK;
}

/*
example:
Content-Range: bytes -154100106/154100107
*/
uchar http_doWithContentRange(http_parser_t* a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 
								struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	int rec = 0;
	char range[HTTP_MAX_UINT64_LEN] = {0};
	char* digit = value;
	uint32 i = 0;
	/*only get digit*/
	for(i=0;i<valuelen;i++)
	{
		if( (*(value+i)>='0' && *(value+i)<='9') || *(value+i)=='-') 
		{
			digit = value+i;
			valuelen -= i;
			break;
		}
	}
	if(i==valuelen)
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "content range error. addr:%s, range:%s", 
								printaddr(&a_tcp->addr, thread_seq), range);
		return ERROR;
	}
	a_http->parser.cont_range = (cont_range_t*)dictator_malloc(thread_seq, sizeof(cont_range_t));
	/*20190128 bytes -154100106/154100107*/
	if(*digit=='-')
	{
		range[0] = '0';
		memcpy(range+1, digit, MIN(HTTP_MAX_UINT64_LEN-1,valuelen));
	}
	else
	{
		memcpy(range, digit, MIN(HTTP_MAX_UINT64_LEN-1,valuelen));
	}
	rec = sscanf(range, "%llu-%llu/%llu", &(a_http->parser.cont_range->start), &(a_http->parser.cont_range->end), &(a_http->parser.cont_range->len));
	if(rec!=3)	
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "content range error. addr:%s, range:%s", 
								printaddr(&a_tcp->addr, thread_seq), range);
		dictator_free(thread_seq, a_http->parser.cont_range);
		a_http->parser.cont_range = NULL;
		return ERROR;
	}
	a_http->session.buf = value;
	a_http->session.buflen = valuelen;
	http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	return OK;
}

uchar http_doWithDefaultRegion(http_parser_t* a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 
							    struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	a_http->session.buf = value;
	a_http->session.buflen = valuelen;
	http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	return OK;
}

uchar http_doWithConnection(http_parser_t* a_http, http_stream *a_http_stream, char* value, uint32 valuelen, 
							  struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	if(0==strncasecmp((char*)value,"keep-alive", sizeof("keep-alive")-1))
	{
		FLAG_CLEAR(a_http->flag, HTTP_FLAG_CONNECT_CLOSE);
	}
	else if(0==strncasecmp((char*)value,"close",sizeof("close")-1))
	{
		FLAG_SET(a_http->flag, HTTP_FLAG_CONNECT_CLOSE);			
	}
	a_http->session.buf = value;
	a_http->session.buflen = valuelen;
	http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
	return OK;
}

uchar http_outPutUrl(http_parser_t *a_http, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	char* 						uri = NULL;
	uint32 						urilen = 0;	
	char 						serverIP_str[64] = {0};
	struct stream_tuple4_v4*	paddr = NULL;
    struct stream_tuple4_v6*	paddr6 = NULL;
	
	if(	FLAG_TEST(a_http->flag, HTTP_FLAG_GET_URL)) return OK;	
	
	FLAG_SET(a_http->flag, HTTP_FLAG_GET_URL);

	if(DIR_C2S==a_http->parser.curdir && a_http->url_buf!=NULL)
	{
		/*releative url*/
		if(a_http->url_buf[0]=='/')
		{
			uri = (char*)dictator_malloc(thread_seq, a_http->url_buflen);
			urilen = a_http->url_buflen;
			memcpy(uri, a_http->url_buf, a_http->url_buflen);
			if(a_http->url_buf!=NULL) 
			{
				dictator_free(thread_seq, a_http->url_buf);
				a_http->url_buf = NULL;
			}
			
			switch(a_tcp->addr.addrtype)
			{
				case ADDR_TYPE_IPV4:
					paddr = a_tcp->addr.tuple4_v4;
					inet_ntop(AF_INET, &paddr->daddr, serverIP_str, 64);				
					break;

				case ADDR_TYPE_IPV6:
					paddr6 = a_tcp->addr.tuple4_v6;
					inet_ntop(AF_INET6, &paddr6->daddr, serverIP_str, 64);
					break;

				default:
					break;
			}
				
			a_http->url_buflen = strlen(serverIP_str)+urilen;
			a_http->url_buf = (char*)dictator_malloc(thread_seq, a_http->url_buflen);
			memcpy(a_http->url_buf, serverIP_str, strlen(serverIP_str));
			memcpy(a_http->url_buf+strlen(serverIP_str), uri, urilen);
			if(uri!=NULL) 
			{
				dictator_free(thread_seq, uri); 
				uri = NULL;
			}
		}
		else
		{
			a_http->parser.is_ab_uri = 1;
		}		
		
		a_http->parser.p_url = a_http->url_buf;
		a_http->parser.url_len = a_http->url_buflen;
		if(g_http_prog_para.http_log_level<=RLOG_LV_DEBUG)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_DEBUG, HTTP_PLUGIN_NAME, "%s:%lu IP_URL:%s", 
									printaddr(&a_tcp->addr,thread_seq),a_http->parser.http_session_seq,a_http->url_buf);
		}
		
		a_http->interested_reg_mask = HTTP_MESSAGE_URL_MASK;
		a_http->session.buf = a_http->url_buf;
		a_http->session.buflen = a_http->url_buflen;
		http_callPlugin(a_http, a_tcp, thread_seq, a_packet);		
	}	
	return OK;
}

int http_recogniseRequestRegion(const char *region_name, uint32 region_name_len)
{
	switch(region_name_len)
	{				
		case 13:
			if(0==strncasecmp(region_name, "authorization", 13)) return HTTP_AUTHORIZATION_MASK;			
			break;	
		case 19:
			if(0==strncasecmp(region_name, "proxy-authorization", 19)) return HTTP_PROXY_AUTHORIZATION_MASK;			
			break;		
		default:
			return -1;
			break;
	}
	return -1;
}

int http_recogniseResponseRegion(const char *region_name, uint32 region_name_len)
{
	switch(region_name_len)
	{		
		case 6:
			if(0==strncasecmp(region_name, "server", 6)) return HTTP_SERVER_MASK;			
			break;		
		default:
			return -1;
			break;
	}
	return -1;
}

int http_recogniseGeneralEntityRegion(const char *region_name, uint32 region_name_len)
{
	switch(region_name_len)
	{		
		case 3:
			if(0==strncasecmp(region_name, "via", 3)) return HTTP_VIA_MASK;			
			break;	
		case 4:
			if(0==strncasecmp(region_name, "host", 4)) return HTTP_HOST_MASK;			
			if(0==strncasecmp(region_name, "etag", 4)) return HTTP_ETAG_MASK;				
			if(0==strncasecmp(region_name, "date", 4)) return HTTP_DATE_MASK;			
			break;		
		case 6:
			if(0==strncasecmp(region_name, "cookie", 6)) return HTTP_COOKIE_MASK;			
			if(0==strncasecmp(region_name, "pragma", 6)) return HTTP_PRAGMA_MASK;				
			break;		
		case 7:
			if(0==strncasecmp(region_name, "referer", 7)) return HTTP_REFERER_MASK;				
			if(0==strncasecmp(region_name, "trailer", 7)) return HTTP_TRAILER_MASK;	
			if(0==strncasecmp(region_name, "expires", 7)) return HTTP_EXPIRES_MASK;				
			if(0==strncasecmp(region_name, "charset", 7)) return HTTP_CHARSET_MASK;				
			break;		
		case 8:
			if(0==strncasecmp(region_name, "location", 8)) return HTTP_LOCATION_MASK;			
			break;
		case 10:
			if(0==strncasecmp(region_name, "connection", 10)) return HTTP_CONNECTION_MASK;				
			if(0==strncasecmp(region_name, "user-agent", 10)) return HTTP_USER_AGENT_MASK;			
			break;				
		case 12:
			if(0==strncasecmp(region_name, "content-type", 12)) return HTTP_CONT_TYPE_MASK;				
			break;
		case 13:
			if(0==strncasecmp(region_name, "content-range", 13)) return HTTP_CONT_RANGE_MASK;				
			break;
		case 14:
			if(0==strncasecmp(region_name, "content-length", 14)) return HTTP_CONT_LENGTH_MASK;				
			break;
		case 15:
			if(0==strncasecmp(region_name, "transfer-length", 15)) return HTTP_TRANSFER_LENGTH_MASK;				
			if(0==strncasecmp(region_name, "x-flash-version", 15)) return HTTP_X_FLASH_VERSION_MASK;				
			break;	
		case 16:
			if(0==strncasecmp(region_name, "content-location", 16)) return HTTP_CONT_LOCATION_MASK;				
			if(0==strncasecmp(region_name, "content-encoding", 16)) return HTTP_CONT_ENCODING_MASK;				
			if(0==strncasecmp(region_name, "content-language", 16)) return HTTP_CONT_LANGUAGE_MASK;				
			break;	
		case 17:
			if(0==strncasecmp(region_name, "transfer-encoding", 17)) return HTTP_TRANSFER_ENCODING_MASK;			
			break;		
		case 19:
			if(0==strncasecmp(region_name, "content-disposition", 19)) return HTTP_CONT_DISPOSITION_MASK;				
			break;		
		default:
			return -1;
			break;
	}
	return -1;
}

int http_analyseRegion(char curdir, const char *region_name, uint32 region_name_len)
{
	int 	rec = -1;

	if(curdir==DIR_C2S)
	{
		rec = http_recogniseRequestRegion(region_name, region_name_len);
	}
	else
	{
		rec = http_recogniseResponseRegion(region_name, region_name_len);
	}

	if(-1==rec)
	{
		rec = http_recogniseGeneralEntityRegion(region_name, region_name_len);
	}
	if(-1==rec)
	{
		return HTTP_OTHER_REGIONS_MASK;
	}
	return rec;	
}

/*return : ERROR, OK*/
uchar http_doWithACompleteRegion(http_parser_t *cur_http_node, http_stream *a_http_stream, struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	int				region_id = 0;
	int*			region_id_hash= NULL;
	char* 			data = cur_http_node->poneline_data;
	uint32 			datalen = cur_http_node->poneline_datalen;
	uint32 			start_pos=0,	end_pos = datalen;	
	uchar 			rec=OK;			
	char* 			colon_pos=NULL;	
	char* 			value = NULL;
	uint32 			valuelen=0, sp_offset=0;	
	uint32 			reg_name_len=0, del_data_len=0;
	char* 			region_name = NULL;
	char 			copy_region_name[128] = {0};
#if HTTP_STATIC
	long long 		before_str = 0, after_str = 0;	
#endif
#if HTTP_REGION_HASH
	long long 		before_hash = 0, after_hash = 0;
#endif
	
	unsigned long long region_flag = g_http_prog_para.http_interested_region_flag;
	int64 prot_flag = 0;


	http_deleteEmptyRow(&start_pos, data, datalen);	
	/*region name process*/
	colon_pos = (char*)memchr(data+start_pos,':',end_pos-start_pos);
	/*span pkt*/
	if(NULL==(colon_pos))	
	{		
		//cur_http_node->mgs_status = HTTP_RETURN_RESET;
		char* buf = (char*)calloc(1, datalen+1);
		memcpy(buf, data, datalen);
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_INFO, HTTP_PLUGIN_NAME, "get region name error, addr:%s, oneline:%s, onelinelen:%u", 
								printaddr(&a_tcp->addr,thread_seq), buf, datalen);			
		free(buf);
		return ERROR;	
	}
	reg_name_len = colon_pos - data;	
	http_deleteSPHTCRLFAtLast(&del_data_len, data+start_pos, reg_name_len);
	reg_name_len = del_data_len;	
	if(reg_name_len>=REGION_NAME_LEN) 
	{
		cur_http_node->mgs_status = HTTP_RETURN_RESET;
		char* buf = (char*)calloc(1, datalen+1);
		memcpy(buf, data, datalen);
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "region name len is more than %d, addr:%s, oneline:%s, onelinelen:%u", 
								REGION_NAME_LEN, printaddr(&a_tcp->addr,thread_seq), buf, datalen);			
		free(buf);
		return ERROR;
	}
	region_name = data+start_pos;
	
#if HTTP_STATIC
	if(g_http_prog_para.http_stat_cycle)
	{
		before_str = rdtsc();
	}
#endif
	region_id = http_analyseRegion(cur_http_node->parser.curdir, (const char*)region_name, reg_name_len);
#if HTTP_STATIC
	if(g_http_prog_para.http_stat_cycle)
	{
		after_str = rdtsc();	
		stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_REGION_TIME_STR], FS_OP_TYPE_ADD, (after_str-before_str));
	}
#endif

#if HTTP_REGION_HASH
	before_hash = rdtsc();
	memcpy(copy_region_name, region_name, reg_name_len);
	stringA_to_stringa(copy_region_name, reg_name_len);
	region_id_hash = (int*)MESA_htable_search(g_http_prog_para.region_hash, (const uchar*)copy_region_name, reg_name_len);
	after_hash = rdtsc();	
	stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_REGION_TIME_HASH], FS_OP_TYPE_ADD, after_hash-before_hash);
	if(-1!=region_id &&  HTTP_OTHER_REGIONS_MASK!=region_id && NULL!=region_id_hash && NULL!=g_http_regions[*region_id_hash].handler) 
	{		
		if(region_id!=*region_id_hash)
		{
			assert(0);
		}
#else	
	if(-1!=region_id && NULL!=g_http_regions[region_id].handler) 
	{
#endif		
		/*standard header*/
		cur_http_node->interested_reg_mask = (interested_region_mask)(region_id);
		prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
		region_flag &= prot_flag ;

		/*region value process, url in proc function*/
		if(g_http_regions[region_id].handler!=NULL&&
			(region_flag||
			cur_http_node->interested_reg_mask==HTTP_HOST_MASK||
			cur_http_node->interested_reg_mask==HTTP_CHARSET_MASK||
			cur_http_node->interested_reg_mask==HTTP_TRANSFER_ENCODING_MASK||
			cur_http_node->interested_reg_mask==HTTP_CONNECTION_MASK||
			cur_http_node->interested_reg_mask==HTTP_CONT_ENCODING_MASK||
			cur_http_node->interested_reg_mask==HTTP_CONT_LENGTH_MASK||
			cur_http_node->interested_reg_mask==HTTP_TRANSFER_LENGTH_MASK||
			cur_http_node->interested_reg_mask==HTTP_PROXY_AUTHORIZATION_MASK))			
		{	
			/*standard append*/
			cur_http_node->parser.append_infor.content = data+start_pos;
			cur_http_node->parser.append_infor.contlen = datalen-start_pos;			
			valuelen = data+end_pos - colon_pos-1;	
			http_deleteEmptyRow(&sp_offset, colon_pos+1, valuelen);
			value = colon_pos+1+sp_offset;
			valuelen -= sp_offset;
			/*proc url when host through host is NULL*/
			if(valuelen>0 || cur_http_node->interested_reg_mask==HTTP_HOST_MASK)
			{
				rec = g_http_regions[region_id].handler(cur_http_node, a_http_stream, value, valuelen, a_tcp, thread_seq, a_packet);
			}
			cur_http_node->parser.append_infor.content = NULL;
			cur_http_node->parser.append_infor.contlen = 0;	
		}	
	}
	else  //other region
	{
		//if have expand head ,use hash to identify
		if(g_http_prog_para.http_region_cnt>HTTP_REGION_NUM)
		{	
			memcpy(copy_region_name, region_name, reg_name_len);
			stringA_to_stringa(copy_region_name,  reg_name_len);
			region_id_hash = (int*)MESA_htable_search(g_http_prog_para.region_hash, (const uchar*)copy_region_name, reg_name_len);
		}

		/*expand region*/
		if(NULL!=region_id_hash)
		{
			cur_http_node->interested_reg_mask = (interested_region_mask)(*region_id_hash);

		}
		/*other region*/
		else
		{	
			cur_http_node->interested_reg_mask = HTTP_OTHER_REGIONS_MASK;			
		}
		prot_flag = (((int64)1)<<cur_http_node->interested_reg_mask);
		region_flag &= prot_flag ;
		if(region_flag)
		{			
			/*expand append*/
			cur_http_node->parser.append_infor.content = data+start_pos;
			cur_http_node->parser.append_infor.contlen = datalen-start_pos;
			valuelen = data+end_pos - colon_pos-1;	
			http_deleteEmptyRow(&sp_offset, colon_pos+1, valuelen);
			value = colon_pos+1+sp_offset;
			valuelen -= sp_offset;		
			rec = http_doWithDefaultRegion(cur_http_node, a_http_stream, value, valuelen, a_tcp, thread_seq, a_packet);
			cur_http_node->parser.append_infor.content = NULL;
			cur_http_node->parser.append_infor.contlen = 0;	
		}
	}	
	return rec;
}

/**********************************************************
***********************************************************/
uchar http_analyseACompleteRegion(http_parser_t *cur_http_node, http_stream *a_http_stream,struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{	
	uchar rec = OK;
	rec = http_positioningACompleteLine(1, cur_http_node, a_tcp, thread_seq);
	/*error : too long . go_back : not long enough*/
	if(rec!=OK) return rec;	 
	rec = http_doWithACompleteRegion(cur_http_node, a_http_stream, a_tcp, thread_seq, a_packet);	
	/*after oneline , clear*/	
	http_inintRegionParam(cur_http_node, thread_seq);	
	if(rec!=OK) return rec;		
	return OK;
}

uchar http_findAndDoWithRegion(http_parser_t *a_http, http_stream *a_http_stream,struct streaminfo *a_tcp, int thread_seq, void *a_packet)
{
	uchar rec = OK;	
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;	
	
	while(1)
	{			
		rec = http_judgeHeaderOver(a_http, (char*)(tcp_detail->pdata), tcp_detail->datalen, thread_seq);		
		if(OK==rec)
		{
			/*output : URL*/
			http_outPutUrl(a_http, a_tcp, thread_seq, a_packet);

			/*output : http state*/
			a_http->parser.http_state = HTTP_DATA_BEGIN;
			
			/*proxy header proc*/
#if HTTP_PROXY	
			if(g_http_prog_para.proxy_switch)
			{
				http_processHttpProxy(a_http,a_http_stream,a_tcp,thread_seq,a_packet);				
			}
#endif
			if(g_http_prog_para.need_http_state)
			{				
				FLAG_SET(a_http->flag, HTTP_FLAG_BATCH_CALLBACK);
				a_http->session.buf = a_http->phttp_begin;		
				a_http->session.buflen = (char*)(tcp_detail->pdata)+a_http->processed_offset-a_http->phttp_begin;
				a_http->interested_reg_mask = HTTP_STATE_MASK;
				http_callPlugin(a_http, a_tcp, thread_seq, a_packet);
			}
			break;
		}
		if(GO_BACK==rec) return GO_BACK;
		rec = http_analyseACompleteRegion(a_http, a_http_stream, a_tcp, thread_seq, a_packet);
		if(rec!=OK) return rec;		
	}
	if(HTTP_TRANS_ENCOD_UNKNOWN==a_http->parser.trans_encoding)
	{
		a_http->parser.trans_encoding = HTTP_TRANS_ENCOD_DEFAULT;
	}
	if(HTTP_TRANS_ENCOD_CHUNKED==a_http->parser.trans_encoding)
	{
		a_http->parser.cont_length = 0;
	}
	if( FLAG_TEST(a_http->flag, HTTP_FLAG_CONNECT_CLOSE) && a_http->parser.cont_length == 0 && a_http->parser.trans_encoding != HTTP_TRANS_ENCOD_CHUNKED)
   	{        	
   		a_http->parser.trans_encoding = HTTP_TRANS_ENCOD_CNNTCLOSE;
	}
	if(HTTP_CONT_ENCOD_UNKNOWN==a_http->parser.cont_encoding)
	{
		a_http->parser.cont_encoding = HTTP_CONT_ENCOD_DEFAULT;	
	}	
	http_inintRegionParam(a_http,thread_seq);
	return OK;
}

string_map_t  g_http_regions[] = 
{
	{"",					HTTP_INTEREST_KEY_MASK,				NULL},
	{"",					HTTP_ALL_MASK,						NULL},
	{"",					HTTP_OTHER_REGIONS_MASK,			NULL},
	{"",					HTTP_STATE_MASK,					NULL},
	{"",					HTTP_REQ_LINE_MASK,					NULL},
	{"",					HTTP_RES_LINE_MASK,					NULL},
	{"",					HTTP_CONTENT_MASK,					NULL},
	{"",					HTTP_UNGZIP_CONTENT_MASK,			NULL},
	{"",					HTTP_MESSAGE_URL_MASK,				NULL},	
	{"",					HTTP_URI_MASK,						NULL},	
	
	{"host",				HTTP_HOST_MASK,						http_doWithHost},
	{"referer",				HTTP_REFERER_MASK,					http_doWithDefaultRegion},
	{"user-agent",			HTTP_USER_AGENT_MASK,				http_doWithDefaultRegion},
	{"cookie",				HTTP_COOKIE_MASK,					http_doWithDefaultRegion},
	{"proxy-authorization",	HTTP_PROXY_AUTHORIZATION_MASK,		http_doWithProxyRegion},
	{"authorization",		HTTP_AUTHORIZATION_MASK,			http_doWithDefaultRegion},
	
	{"location",			HTTP_LOCATION_MASK,					http_doWithDefaultRegion},
	{"server",				HTTP_SERVER_MASK,					http_doWithDefaultRegion},
	{"etag",				HTTP_ETAG_MASK,						http_doWithDefaultRegion},
	
	{"date",				HTTP_DATE_MASK,						http_doWithDefaultRegion},	
	{"trailer",				HTTP_TRAILER_MASK,					http_doWithDefaultRegion},
	{"transfer-encoding",	HTTP_TRANSFER_ENCODING_MASK,		http_doWithEncoding},		
	{"via",					HTTP_VIA_MASK,						http_doWithDefaultRegion},	
	{"pragma",				HTTP_PRAGMA_MASK,					http_doWithDefaultRegion},
	{"connection",			HTTP_CONNECTION_MASK,				http_doWithConnection},
	
	{"content-encoding",	HTTP_CONT_ENCODING_MASK,			http_doWithEncoding},		
	{"content-language",	HTTP_CONT_LANGUAGE_MASK,			http_doWithDefaultRegion},
	{"content-location",	HTTP_CONT_LOCATION_MASK,			http_doWithDefaultRegion},
	{"content-disposition",	HTTP_CONT_DISPOSITION_MASK,			http_doWithDefaultRegion},
	{"content-range",		HTTP_CONT_RANGE_MASK,				http_doWithContentRange},
	{"content-length",		HTTP_CONT_LENGTH_MASK,				http_doWithContentLength},
	{"content-type",		HTTP_CONT_TYPE_MASK,				http_doWithContentType},	
	{"charset",				HTTP_CHARSET_MASK,					http_doWithDefaultRegion},
	{"expires",				HTTP_EXPIRES_MASK,					http_doWithDefaultRegion},
	{"x-flash-version",		HTTP_X_FLASH_VERSION_MASK,			http_doWithDefaultRegion},
	{"transfer-length",		HTTP_TRANSFER_LENGTH_MASK,			http_doWithTransferLength},			
};

