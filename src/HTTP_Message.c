#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <math.h>

#include "HTTP_Message.h"
#include "HTTP_Analyze.h"
#include "HTTP_Common.h"
#include "HTTP_Message_Region.h"
#include "MESA_handle_logger.h"
#include "MESA_prof_load.h"
#include "MESA_htable.h"
#include "field_stat.h"

static int 								g_iThreadNum = get_thread_count();
extern http_prog_runtime_parameter_t 	g_http_prog_para;
extern string_map_t  					g_http_regions[];
extern const char*  					g_http_method[];

const char* http_get_method(uchar method)
{
	if(method>0&&method<=HTTP_METHOD_TRACE)
	{
		return g_http_method[method];
	}
	return NULL;
}

char http_is_hexChar(char c)
{
    return  c >= '0' && c <= '9' ?  c - '0' : c >= 'A' && c <= 'F'? c - 'A' + 10 : c - 'a' + 10;    /* accept small letters just in case */
}

int is_absolute_uri(void* app_info)
{
	return ((http_infor*)app_info)->is_ab_uri;
}

int http_line2region(const char *line, uint32 line_len, char** region, uint32* region_len)
{
	/*line来自业务层，即append,所以line前面的空格已经删除，只需要删除: 之后的空格*/
	uint32	del_data_len=0;	
	char* colon_pos = (char*)memchr(line, ':', line_len);		
	if(NULL==colon_pos) return -1;	
	http_deleteSPHTCRLFAtLast(&del_data_len, (char*)line,  colon_pos - line);
	*region = (char*)line;
	*region_len = del_data_len;	
	return 0;
}

/* old platform
char* http_url_decode(char *data,  int* data_len)
{
    if (!data)     return NULL;
    char *str  = (char *)malloc(*data_len + 1);   
    strncpy(str, data, *data_len);
    str[*data_len] = '\0';  
    char *p = str;
    char *q = str;  

    while(*p) 
    {    
        if (*p == '%')             
        {   
        	p++;
			if (*p) *q = http_is_hexChar(*p++) * 16;
			if (*p) *q = (*q + http_is_hexChar(*p)), ++p;
			q++; 
        } 
        else 
        {    
            *q++ = *p++; 
        }
    }
    *q++ = 0;
    *data_len = strlen(str);
    strncpy(data, str, *data_len);
    free(str);
    return data;
} 
*/

char* http_url_decode(char *data,  int* data_len)
{
    if (!data)     return NULL;
    char *str  = (char *)malloc(*data_len);   
    strncpy(str, data, *data_len);
    char *p = str;
    char *q = str;  	
    char *str_end = str+*data_len;

    while(p<str_end) 
    {    
        if (*p == '%')             
        {   
        	p++;
			if (*p) *q = http_is_hexChar(*p++) * 16;
			if (*p) *q = (*q + http_is_hexChar(*p)), ++p;
			q++; 
        } 
        else 
        {    
            *q++ = *p++; 
        }
    }
    *data_len = (int)(q - str);
    memcpy(data, str, *data_len);
    free(str);
    return data;
} 


const char* http_proto_flag2region(int64 proto_flag)
{
	//int region_id = get_bitnum(prot_flag);
	int region_id = (int) (log(proto_flag)/log(2));
	if(region_id>=(int)g_http_prog_para.http_region_cnt) return NULL;
	return (const char*)g_http_prog_para.http_conf_regionname[region_id];
}

/*standard region: support Server(in pcap) or HTTP_SERVER*/
long long http_region2proto_flag(const char *region, uint32 region_len)
{
	uint32*	region_id = NULL;
	char 	reg[REGION_NAME_LEN] = {0};
	
	memcpy(reg, region, region_len);
	stringA_to_stringa(reg,  region_len);	
	region_id = (uint32*)MESA_htable_search_cb(g_http_prog_para.region_hash, (const uchar*)reg, region_len, NULL, NULL, NULL);
	if(region_id!=NULL)
	{			
		return (long long)(((long long)1)<<(*region_id));
	}
	/*http content......*/
	else 
	{
		 for(int i=0;i<g_http_prog_para.http_region_cnt;i++)
    		{    		
      			if(0==strcasecmp(g_http_prog_para.http_conf_regionname[i], region))
        		{  
        			return  (long long)(((long long)1)<<(i));;
			}
		}
	}
	return -1;
}

MESA_htable_handle http_initRegionHash()
{	
	MESA_htable_create_args_t hash_args;
	memset(&hash_args,0,sizeof(MESA_htable_create_args_t));
	hash_args.thread_safe = 0;
	hash_args.recursive = 0;
	hash_args.hash_slot_size = 1024;
	hash_args.max_elem_num = 1024;
	hash_args.eliminate_type = 0;
	hash_args.expire_time = 0;
	hash_args.key_comp = NULL;
	hash_args.key2index = NULL;
	hash_args.data_free = NULL; 
	hash_args.data_expire_with_condition = NULL;
	MESA_htable_handle hash_handler = MESA_htable_create(&hash_args, sizeof(hash_args));
	if(NULL==hash_handler) 
	{
		MESA_htable_destroy(hash_handler, NULL);
		return NULL;
	}
	
	/*init header hash: standard*/
	int i=0;
	for(i=0;i<HTTP_REGION_NUM;i++)
	{		
		if(g_http_regions[i].string[0]=='\0') continue;	
		if(-1==(MESA_htable_add(hash_handler, (const uchar*)g_http_regions[i].string, strlen(g_http_regions[i].string), &g_http_regions[i].stringid)))
		{
			MESA_htable_destroy(hash_handler, NULL);
			return NULL;
		}
	}
	/*init header hash: expand*/
	int* m = NULL;
	for(i=HTTP_REGION_NUM;i<g_http_prog_para.http_region_cnt;i++)
	{				
		m = (int*)malloc(sizeof(int));
		*m = i;
		stringA_to_stringa(g_http_prog_para.http_conf_regionname[i],  strlen(g_http_prog_para.http_conf_regionname[i]));
		if(-1==(MESA_htable_add(hash_handler, (const uchar*)g_http_prog_para.http_conf_regionname[i], strlen(g_http_prog_para.http_conf_regionname[i]), m)))
		{
			MESA_htable_destroy(hash_handler, NULL);
			return NULL;
		}			
	}	
	return hash_handler;
}

int http_readHttpConf(const char* filename)
{	
	FILE*	fp 			= NULL;
	char 	buf[2048] 	= {0};	
	int 	region_id = 0;
	int 	temp 		= 0;
	char 	region_name[REGION_NAME_LEN] 	= {0};	
	
	g_http_prog_para.http_region_cnt++;
	if(((fp = fopen(filename, "r"))!=NULL))
	{
		while( fgets(buf, sizeof(buf), fp))
		{
			if(buf[0]=='#' || buf[0]==' ' || buf[0]=='\r' ||  buf[0]=='\n') continue;
			temp = sscanf(buf, "%d\t%s", &region_id, region_name);
			if(2 > temp)
			{			
				MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http.conf read %s error!", buf);
				return -1;
			}
			if(region_id > MAX_REGION_NUM)
			{		 	 		 
				MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http.conf bigger than %d", MAX_REGION_NUM);
				return -1;
			}
			strncpy(g_http_prog_para.http_conf_regionname[region_id], region_name, strlen(region_name));
			g_http_prog_para.http_region_cnt++;
			memset(region_name, 0, sizeof(region_name));
		}
		fclose(fp);
	}
	else  
	{		 	 
		 MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http.conf open error!");
		 return -1;
	}
	/*init region hash*/
	g_http_prog_para.region_hash = http_initRegionHash();
	if(NULL==g_http_prog_para.region_hash)
	{
		return -1;
	}
	return 0;
}

int http_readMainConf(const char* filename)
{
	char 	http_log_filename[256];	
	
	MESA_load_profile_short_def(filename, "LOG", "log_level", (short*)&g_http_prog_para.http_log_level, 30);	
	MESA_load_profile_string_def(filename, "LOG", "log_path", http_log_filename, sizeof(http_log_filename),"./log/http/runtime");
	
	g_http_prog_para.http_log_handle = MESA_create_runtime_log_handle(http_log_filename, g_http_prog_para.http_log_level);
	if(NULL==g_http_prog_para.http_log_handle)
	{		
		printf("%s get log handle error!\n", HTTP_PLUGIN_NAME);
		return -1;
	}
	MESA_load_profile_short_def(filename, "FUNCTION", "switch_no_biz", (short*)&g_http_prog_para.http_switch_no_biz,0);
	MESA_load_profile_short_def(filename, "FUNCTION", "ungzip_switch", (short*)&g_http_prog_para.ungzip_switch,1);
	MESA_load_profile_short_def(filename, "FUNCTION", "proxy_switch", (short*)&g_http_prog_para.proxy_switch,1);
	MESA_load_profile_int_def(filename, "FUNCTION", "stat_screen_print", &g_http_prog_para.http_stat_screen_print_trigger,0);
	MESA_load_profile_int_def(filename, "FUNCTION", "stat_cycle", &g_http_prog_para.http_stat_cycle,0);
	MESA_load_profile_uint_def(filename, "FUNCTION", "singleway_maxseq", &g_http_prog_para.singleway_seq,0);
	MESA_load_profile_short_def(filename, "FUNCTION", "callback_mode", (short*)&g_http_prog_para.callback_mode,0);
	MESA_load_profile_short_def(filename, "FUNCTION", "batch_field_maxnum", (short*)&g_http_prog_para.batch_field_maxnum,64);
	MESA_load_profile_string_def(filename, "FUNCTION", "stat_file", g_http_prog_para.http_stat_filename, sizeof(g_http_prog_para.http_stat_filename),"./log/http/http_stat.log");

	return 0;
}

int HTTP_INIT(void)
{	
    memset(&g_http_prog_para,0,sizeof(http_prog_runtime_parameter_t));
	if(0!=http_readMainConf("./conf/http/http_main.conf"))
	{		
		printf("%s http_main.conf read error!", HTTP_PLUGIN_NAME);
		return -1;
	}
	if(0!=http_readHttpConf("./conf/http/http.conf"))
	{		
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http.conf read error!");
		return -1;
	}		

	/*ungzip init*/	
	g_http_prog_para.docanly_handler = docanalyze_initialize(g_iThreadNum);
	if(NULL==g_http_prog_para.docanly_handler)
	{
		MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "docanalyze_initialize error!");
		return -1;
	}

#if HTTP_PROXY_CAPFILE	
	g_http_prog_para.capfile_project_id = project_producer_register("MESA_CAPFILE", "char", NULL);
#endif
	
#if DEBUG_TEST_DEAL_TIME	
	pthread_mutex_init(&g_http_prog_para.stat_lock, NULL);
#endif

	/*http stat*/
	if(g_http_prog_para.http_stat_cycle)
	{			
		if(g_http_prog_para.http_stat_screen_print_trigger==0)
		{
			g_http_prog_para.stat_handler = init_screen_stat(stdout,g_http_prog_para.http_stat_cycle, 1);
		}
		else if(g_http_prog_para.http_stat_screen_print_trigger==1&&(g_http_prog_para.http_stat_file = fopen(g_http_prog_para.http_stat_filename, "a"))!=NULL)
		{
			g_http_prog_para.stat_handler = init_screen_stat(g_http_prog_para.http_stat_file ,g_http_prog_para.http_stat_cycle, 1);					
		}
		else
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat file open error!");
			return -1;
		}		
		if((g_http_prog_para.stat_field[HTTP_STAT_PKTS] = stat_field_register(g_http_prog_para.stat_handler,"http_pkts"))	==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_pkts register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_BITS] = stat_field_register(g_http_prog_para.stat_handler,"http_bytes"))	==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_bits register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_REQ] = stat_field_register(g_http_prog_para.stat_handler,"req_counts"))	==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_req_counts register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_RES] = stat_field_register(g_http_prog_para.stat_handler,"res_counts"))	==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_res_counts register error!");
			return -1;
		}	
		if((g_http_prog_para.stat_field[HTTP_STAT_CREATE] = stat_field_register(g_http_prog_para.stat_handler,"http_create_N"))	==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_create register error!");
			return -1;
		}	
		if((g_http_prog_para.stat_field[HTTP_STAT_RELEASE] = stat_field_register(g_http_prog_para.stat_handler,"http_release_N"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_release register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_C2S] = stat_field_register(g_http_prog_para.stat_handler,"single_c2s_N"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_single_c2s register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_S2C] = stat_field_register(g_http_prog_para.stat_handler,"single_s2c_N"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_single_s2c register error!");
			return -1;
		}	
		if((g_http_prog_para.stat_field[HTTP_STAT_HEADER_C2S] = stat_field_register(g_http_prog_para.stat_handler,"header_c2s_B"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat header_c2s register error!");
			return -1;
		}	
		if((g_http_prog_para.stat_field[HTTP_STAT_HEADER_S2C] = stat_field_register(g_http_prog_para.stat_handler,"header_s2c_B"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat header_s2c register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_CONTENT_C2S] = stat_field_register(g_http_prog_para.stat_handler,"content_c2s_B"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat content_c2s register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_CONTENT_S2C] = stat_field_register(g_http_prog_para.stat_handler,"content_s2c_B"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat content_s2c register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_LOST] = stat_field_register(g_http_prog_para.stat_handler,"tcplost_cnt"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_tcplost_cnt register error!");
			return -1;
		}	
		if((g_http_prog_para.stat_field[HTTP_STAT_RESET] = stat_field_register(g_http_prog_para.stat_handler,"reset_cnt"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat http_reset_cnt register error!");
			return -1;
		}
#if HTTP_STATIC
		if((g_http_prog_para.stat_field[HTTP_STAT_REGION_TIME_STR] = stat_field_register(g_http_prog_para.stat_handler,"region_str"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat region_str register error!");
			return -1;
		}
#if HTTP_REGION_HASH
		if((g_http_prog_para.stat_field[HTTP_STAT_REGION_TIME_HASH] = stat_field_register(g_http_prog_para.stat_handler,"region_hash"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat region_hash register error!");
			return -1;
		}
#endif
		if((g_http_prog_para.stat_field[HTTP_STAT_TCP_PKT_CALLBACK] = stat_field_register(g_http_prog_para.stat_handler,"tcppkt_cb_N"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat tcppkt_cb_N register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_TCP_PKT_PROC_TIME] = stat_field_register(g_http_prog_para.stat_handler,"tcppkt_proc_T"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat tcppkt_proc_T register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_TCP_PKT_PROC_MAXTIME] = stat_field_register(g_http_prog_para.stat_handler,"tcppkt_proc_MT"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat tcppkt_proc_MT register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_CBPLUGIN] = stat_field_register(g_http_prog_para.stat_handler,"plugin_cb_N"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat tcppkt_proc_T register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_CBPLUGIN_PROC_TIME] = stat_field_register(g_http_prog_para.stat_handler,"plugin_cb_T"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat tcppkt_proc_MT register error!");
			return -1;
		}
#endif
		if((g_http_prog_para.stat_field[HTTP_STAT_CLIENT_PKT] = stat_field_register(g_http_prog_para.stat_handler,"client_pkt"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat client_pkt register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_CLIENT_BYTE] = stat_field_register(g_http_prog_para.stat_handler,"client_byte"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat client_byte register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_SERVER_PKT] = stat_field_register(g_http_prog_para.stat_handler,"server_pkt"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat server_pkt register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_SERVER_BYTE] = stat_field_register(g_http_prog_para.stat_handler,"server_byte"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat server_byte register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_HEADER_SPAN_CNT] = stat_field_register(g_http_prog_para.stat_handler,"header_span_cnt"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat header_span_cnt register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_HEADER_SPAN_PKT] = stat_field_register(g_http_prog_para.stat_handler,"header_span_pkt"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat header_span_pkt register error!");
			return -1;
		}
		if((g_http_prog_para.stat_field[HTTP_STAT_HEADER_SPAN_BYTE] = stat_field_register(g_http_prog_para.stat_handler,"header_span_byte"))==-1)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_stat header_span_byte register error!");
			return -1;
		}
	}
	return 0;
}

void HTTP_DESTROY(void)
{	
	MESA_htable_destroy(g_http_prog_para.region_hash, NULL);
	/*http stat*/
	if(NULL!=g_http_prog_para.http_stat_file)
	{
		fclose(g_http_prog_para.http_stat_file);
	}

	/*runtimelog*/	
	MESA_destroy_runtime_log_handle(g_http_prog_para.http_log_handle);

	/*ungzip*/
	docanalyze_destroy(g_http_prog_para.docanly_handler);
}

void HTTP_PROT_FUNSTAT(unsigned long long protflag)
{
	g_http_prog_para.http_interested_region_flag = protflag;
	if((protflag&HTTP_STATE) || (protflag&HTTP_ALL))
	{
		g_http_prog_para.need_http_state = 1;
	}	
	/*no bizplugin need*/
	if(g_http_prog_para.http_interested_region_flag < HTTP_KEY)	
	{
		g_http_prog_para.not_proc = 1;
	}
	/*switch set proc*/
	if(g_http_prog_para.http_switch_no_biz) 
	{
		g_http_prog_para.not_proc = 0;
	}
	/*protflag cnt*/
	if(!(protflag & HTTP_OTHER_REGIONS))
	{
		unsigned long long protflag_temp = protflag;
		int	region_cnt = 0;
		while(protflag_temp)
		{
			protflag_temp = protflag_temp & (protflag_temp-1);
			region_cnt++;
		}		
		g_http_prog_para.batch_field_maxnum = region_cnt;
	}
}

void HTTP_GETPLUGID(unsigned short plugid)
{
	g_http_prog_para.http_plugid = plugid;
}

/*for HTTP_FLAG_CHANGE, only use when http.so init*/
int http_region2id(const char *region, uint32 region_len)
{
    int i=0;
    for(i=0;i<(int)g_http_prog_para.http_region_cnt;i++)
    {    		
        if(0==strcasecmp(g_http_prog_para.http_conf_regionname[i], region))
        {   
            return i;
        }   
    }   
    return -1;
}

long long HTTP_FLAG_CHANGE(char* flag_str)
{
	if(flag_str==NULL) return -1;
	
	int64 		protflag = 0;
	int			region_id = 0;	
	short		region_cnt = 0;	
	char*		start_token = flag_str;
	char*		end_token = flag_str;
	char*		end_pos = flag_str+strlen(flag_str);
	char 		region_name[REGION_NAME_LEN] = {0};

	/*all regions*/
	if(0==(strncasecmp(flag_str, "all" , sizeof("all")))||(0==strncasecmp(flag_str, "http_all" , sizeof("http_all"))))
	{
		long long i=0;
		for( i=0;i<(long long)g_http_prog_para.http_region_cnt;i++)
		{    		
			protflag |= ((long long)1)<<i;
		} 
		return protflag;
	}
	
	while (end_token < end_pos)
	{		
		end_token = (char*)memchr(start_token, ',', end_pos-start_token);
		if(end_token!=NULL)
		{
			memcpy(region_name, start_token, end_token-start_token);
			start_token = end_token+1;
			end_token += 1;			
		}
		else 
		{
			memcpy(region_name, start_token, end_pos-start_token);			
			end_token = end_pos;		
		}			
		region_id = http_region2id(region_name, strlen(region_name));
		if(-1==region_id)
		{
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "FLAG_CHANGE %s:%s error!", flag_str, region_name);
			return -1;
        }
		region_cnt++;
		protflag |= ((long long)1)<<region_id;
		memset(region_name, 0, REGION_NAME_LEN);
	}	
	return protflag;
}

/**********************************************************
 * 功能：判定消息头是否结束。
 * buffer:域存储缓存区。
 * data：当前数据。
 * data_len:当前数据的长度。
 * proc_offset:当前数据已处理数据的偏移量。
 return : GO_BACK  OK   ERROR
***********************************************************/
uchar http_judgeHeaderOver(http_parser_t *a_http, char *data, uint32 data_len, int thread_seq)
{
	/*at least two char*/
	if(data_len+a_http->buflen<=a_http->processed_offset+1) 
	{
		a_http->pbuf = (char*)dictator_realloc(thread_seq, a_http->pbuf, data_len-a_http->processed_offset);
		memcpy(a_http->pbuf+a_http->buflen,data+a_http->processed_offset, data_len-a_http->processed_offset);
		a_http->buflen +=  data_len-a_http->processed_offset;		
		a_http->processed_offset += data_len-a_http->processed_offset;		
		return GO_BACK;
	}
	if(a_http->pbuf!=NULL)
	{			
		switch(a_http->endline_flag)
		{
			case LINE_FLAG_LF:	
				if('\n'==*(a_http->pbuf))
				{					
					return OK;
				}
				break;
			case LINE_FLAG_CR:
				if('\r'==*(a_http->pbuf))
				{					
					return OK;
				}
				break;
			case LINE_FLAG_CRLF:		
				/*only one situation*/
				if('\r'==*(a_http->pbuf) && '\n'==*(data+a_http->processed_offset))
				{
					(a_http->processed_offset) ++;
					return OK;
				}
				break;
			default:
				break;
		}				
	}
	else
	{
		switch(a_http->endline_flag)
		{
			case LINE_FLAG_LF:	
				if('\n'==*(data+a_http->processed_offset))
				{					
					(a_http->processed_offset)++;
					return OK;
				}
				break;
			case LINE_FLAG_CR:
				if('\r'==*(data+a_http->processed_offset))
				{					
					(a_http->processed_offset)++;
					return OK;
				}
				break;
			case LINE_FLAG_CRLF:				
				if('\r'==*(data+a_http->processed_offset) && '\n'==*(data+a_http->processed_offset+1))
				{
					(a_http->processed_offset) += 2;
					return OK;
				}
				break;
			default:
				break;
		}		
	}	
	return ERROR;
}

void http_updateBefore(char* pos_n_1, const char**p, uint32* l_p, const char** q, uint32* l_q)
{
	if(pos_n_1>=*p&&pos_n_1<*p+*l_p)//pos_n_1 in before
	{		
		*l_p = *l_p-(pos_n_1-*p);
		*p = pos_n_1;
	}
	else// means pos_r>=q&&pos_r<q+l_q  //pos_n_1 in this_data
	{
		*p = NULL;
		*l_p = 0;
		*l_q = *l_q-(pos_n_1-*q);
		*q = pos_n_1;
	}
}

/* \r  or \r\n*/
char* http_findLineEnd_CR(char* end_flag, char* fold_flag, const char*before, uint32 before_len,const char* this_data,uint32 this_len)
{
	char* pos_r=NULL;
	char* pos_r_1=NULL;
	char* pos_r_2=NULL;
	const char*	p=before;
	const char*	q=this_data;
	uint32 l_p=before_len,l_q=this_len;	
	char  search_rp_flag = 0;

	/*\r\n \r as complete line*/
	do
	{
		switch(*end_flag)
		{
			case LINE_FLAG_LF:
				return NULL;
				break;
				
			case LINE_FLAG_CR:
				if(l_p>0 && !search_rp_flag)
				{
					pos_r = double_memchr(p,l_p,q,l_q,'\r');
					search_rp_flag = 1;
				}
				else
				{
					pos_r = double_memchr(NULL,0,q,l_q,'\r');
				}					
				if(pos_r!=NULL)
				{
					pos_r_1=double_memread(p,l_p,q,l_q,pos_r,1);
					if(pos_r_1==NULL)
					{						
						return  NULL;
					}					
					if(*pos_r_1!='\t'&&*pos_r_1!=' ')
					{
						//\r complete line, return \r
						return pos_r;
					}				
					else //fold line
					{
						*fold_flag = 1;
						http_updateBefore(pos_r_1, &p ,&l_p, &q, &l_q);
					}
				}				
				break;			

			/*same with default*/
			case LINE_FLAG_CRLF:
				/* \r\n : search p only first time,*/
				if(l_p>0 && !search_rp_flag)
				{
					pos_r = double_memchr(p,l_p,q,l_q,'\r');
					search_rp_flag = 1;
				}
				else
				{
					pos_r = double_memchr(NULL,0,q,l_q,'\r');
				}					
				if(pos_r!=NULL)
				{
					pos_r_1=double_memread(p,l_p,q,l_q,pos_r,1);
					pos_r_2=double_memread(p,l_p,q,l_q,pos_r,2);
					if(pos_r_1==NULL)
					{						
						return  NULL;
					}
					if(*pos_r_1=='\n'&&pos_r_2==NULL)  //\r\n over
					{
						return  NULL;
					}
					if(*pos_r_1=='\n'&&pos_r_2!=NULL&&*pos_r_2!='\t'&&*pos_r_2!=' ')
					{
						//\r\n complete line, return \r
						return pos_r;
					}					
					else //fold line
					{
						*fold_flag = 1;
						http_updateBefore(pos_r_1, &p ,&l_p, &q, &l_q);
					}
				}
				break;
			//do not know line end flag
			default:
				/*\r or \r\n : search p only first time,*/
				if(l_p>0 && !search_rp_flag)
				{
					pos_r = double_memchr(p,l_p,q,l_q,'\r');
					search_rp_flag = 1;
				}
				else
				{
					pos_r = double_memchr(NULL,0,q,l_q,'\r');
				}					
				if(pos_r!=NULL)
				{
					pos_r_1=double_memread(p,l_p,q,l_q,pos_r,1);
					pos_r_2=double_memread(p,l_p,q,l_q,pos_r,2);
					if(pos_r_1==NULL)
					{						
						return  NULL;
					}
					if(*pos_r_1=='\n'&&pos_r_2==NULL)  //\r\n over
					{
						return  NULL;
					}
					if(*pos_r_1=='\n'&&pos_r_2!=NULL&&*pos_r_2!='\t'&&*pos_r_2!=' ')
					{
						//\r\n complete line, return \r
						*end_flag = LINE_FLAG_CRLF;
						return pos_r;
					}
					else if(*pos_r_1!='\n'&&*pos_r_1!='\t'&&*pos_r_1!=' ')
					{
						//\r complete line, return \r					
						*end_flag = LINE_FLAG_CR;
						return pos_r;
					}
					else //fold line
					{
						*fold_flag = 1;
						http_updateBefore(pos_r_1, &p ,&l_p, &q, &l_q);
					}
				}
				break;
		}
	}while(pos_r!=NULL);
	return NULL;
}

/*\n*/
char* http_findLineEnd_LF(char* end_flag, char* fold_flag, const char*before, uint32 before_len,const char* this_data,uint32 this_len)
{
	char* pos_n=NULL;
	char* pos_n_1=NULL;
	const char *p=before;
	const char *q=this_data;
	uint32 l_p=before_len,l_q=this_len;	
	char  search_np_flag = 0;

	/*\r\n \r as complete line*/
	do
	{
		switch(*end_flag)
		{
			case LINE_FLAG_CR:			
			case LINE_FLAG_CRLF:
				return NULL;
				break;

			/*same with*/
			case LINE_FLAG_LF:
			//do not know line end flag
			default:
				/*\r or \r\n : search p only first time,*/
				if(l_p>0 && !search_np_flag)
				{
					pos_n = double_memchr(p,l_p,q,l_q,'\n');
					search_np_flag = 1;
				}
				else
				{
					pos_n = double_memchr(NULL,0,q,l_q,'\n');
				}					
				if(pos_n!=NULL)
				{					
					pos_n_1=double_memread(p,l_p,q,l_q,pos_n,1);
					if(pos_n_1==NULL)
					{
						return NULL;
					}
					if(*pos_n_1!='\t'&&*pos_n_1!=' ')
					{
						//\n complete line, return \n				
						*end_flag = LINE_FLAG_LF;
						return pos_n;
					}
					else //fold line
					{						
						*fold_flag = 1;
						http_updateBefore(pos_n_1, &p ,&l_p, &q, &l_q);							
					}
				}
				break;
		}
	}while(pos_n!=NULL);
	return NULL;
}


/*\r\n or \r or \n*/
char* http_findLineEnd(char* end_flag, char* fold, const char*before, uint32 before_len,const char* this_data,uint32 this_len)
{
	char* p_end = http_findLineEnd_CR(end_flag, fold, before, before_len, this_data, this_len);
	if(NULL!=p_end) 
	{
		return p_end;
	}
	return http_findLineEnd_LF(end_flag, fold, before, before_len, this_data, this_len);
}

void http_saveToBuf(const char* curdata,uint32 cur_datalen,const char* p_end, char fold_flag, char del_space, http_parser_t *cur_http_node, int thread_seq)
{
	/*not include end flag \r\n,\r,\n*/
	uint32 append_line_len = 0;
	uint32 i=0,j=0;
	char* c = NULL;
	
	if(NULL==p_end)
	{
		/*null, delete fold flag to save*/
		append_line_len = cur_datalen;		
	}
	else
	{
		/*p_end must in curdata*/
		append_line_len = p_end - curdata;	
	}

	/*need proc fold line*/
	if(fold_flag)
	{
		char* newdata = (char*)dictator_malloc(thread_seq, append_line_len);;
		for(i=0;i<append_line_len;i++)
		{
			c = (char*)(curdata+i);
			if(*c!=HTTP_SP && *c!=HTTP_HT && *c!=HTTP_CR && *c!=HTTP_LF) 
			{
				newdata[j] = *c;
				j++;
			}
			/*may not delate sapce because in start_line*/
			if(*c==HTTP_SP && !del_space)
			{
				newdata[j] = *c;
				j++;
			}			
		}			
		cur_http_node->pbuf = (char*)dictator_realloc(thread_seq, cur_http_node->pbuf, cur_http_node->buflen + j);	
		memcpy(cur_http_node->pbuf+cur_http_node->buflen, newdata, j);
		cur_http_node->buflen += j;		
		dictator_free(thread_seq, newdata);
	}
	else
	{		
		cur_http_node->pbuf = (char*)dictator_realloc(thread_seq, cur_http_node->pbuf, cur_http_node->buflen + append_line_len);	
		memcpy(cur_http_node->pbuf+cur_http_node->buflen, curdata, append_line_len);
		cur_http_node->buflen += append_line_len;
	}

	if(NULL==p_end)
	{
		/*update process*/				
		cur_http_node->processed_offset += cur_datalen;
	}
	else
	{
		cur_http_node->poneline_data = cur_http_node->pbuf; 
		cur_http_node->poneline_datalen = cur_http_node->buflen;
			
		/*update process*/		
		cur_http_node->processed_offset += p_end-curdata;
		/*add endline flag*/
		switch(cur_http_node->endline_flag)
		{
			case LINE_FLAG_LF:
			case LINE_FLAG_CR:
				cur_http_node->processed_offset += 1;
				break;	
			case LINE_FLAG_CRLF:	
				cur_http_node->processed_offset += 2;
				break;
			default:
				break;
		}			
	}
}
/**********************************************************
 * buffer:数据存储缓存区。
  * processed_offset：当前数据中，已处理数据的偏移量.
 * cur_data：当前数据。
 * cur_data_len：当前数据的长度。
***********************************************************/
uchar http_positioningACompleteLine(char del_space, http_parser_t *cur_http_node, struct streaminfo *a_tcp, int thread_seq)
{			
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;
	char*	curdata = (char*)(tcp_detail->pdata)+cur_http_node->processed_offset;
	uint32 	curdata_len = tcp_detail->datalen-cur_http_node->processed_offset;
	char*	before = cur_http_node->pbuf;
	uint32 	before_len = cur_http_node->buflen;
	char* 	p_end=NULL;
	char	fold_flag = 0;
	
	p_end = http_findLineEnd(&cur_http_node->endline_flag, &fold_flag, before, before_len, curdata, curdata_len);
	if(p_end==NULL)
	{		
		if(COMPLETE_BUFLEN<cur_http_node->buflen) 
		{
			cur_http_node->mgs_status = HTTP_RETURN_RESET;
			MESA_handle_runtime_log(g_http_prog_para.http_log_handle, RLOG_LV_FATAL, HTTP_PLUGIN_NAME, "http_positioningACompleteLine error, comleteline is too long, %u>%u", 
									cur_http_node->buflen, COMPLETE_BUFLEN);
			return ERROR;
		}
		/*to keep buf no fold flag, to avoid search fold flag next time*/
		if(fold_flag)
		{
			http_saveToBuf(curdata,curdata_len,NULL,fold_flag,1,cur_http_node,thread_seq);
		}
		else
		{
			cur_http_node->pbuf = (char*)dictator_realloc(thread_seq, cur_http_node->pbuf, before_len+curdata_len);
			memcpy(cur_http_node->pbuf+before_len,curdata,curdata_len);
			cur_http_node->buflen += curdata_len;		
			cur_http_node->processed_offset += curdata_len;
		}		
		return GO_BACK;
	}
	else
	{
		if(NULL==cur_http_node->pbuf)
		{
			/*need copy and delete fold flag*/
			if(fold_flag)
			{
				http_saveToBuf(curdata,curdata_len,p_end,fold_flag,del_space,cur_http_node,thread_seq);
			}
			else
			{
				switch(cur_http_node->endline_flag)
				{
					case LINE_FLAG_LF:				
					case LINE_FLAG_CR:
						cur_http_node->poneline_data = curdata;	
						cur_http_node->poneline_datalen = p_end-curdata;	
						cur_http_node->processed_offset += p_end-curdata+1;
						break;			
						
					case LINE_FLAG_CRLF:	
						cur_http_node->poneline_data = curdata;	
						cur_http_node->poneline_datalen = p_end-curdata;	
						cur_http_node->processed_offset += p_end-curdata+2;
						break;
				}
			}		
		}
		else
		{	
			/*free pbuf outside*/
			if(p_end>=before&&p_end<=before+before_len-1)//\r or \n endline flag in before
			{
				cur_http_node->poneline_data = before; 
				cur_http_node->poneline_datalen = p_end-before;	
				/*in before, can not be fold flag*/					
				switch(cur_http_node->endline_flag)
				{					
					case LINE_FLAG_LF:				
					case LINE_FLAG_CR:											
						cur_http_node->processed_offset += 0;
						break;
					case LINE_FLAG_CRLF:						
						if(p_end==before+before_len-1)// \n in curdata
						{
							cur_http_node->processed_offset += 1;
						}
						else
						{
							cur_http_node->processed_offset += 0;
						}
						break;									
				}								
			}
			else //\r or \n endline flag in curdata
			{	
				if(p_end==curdata)//\r , \n,  \r in \r\n  in  curdata
				{
					cur_http_node->poneline_data = before; 
					cur_http_node->poneline_datalen = before_len;					
					switch(cur_http_node->endline_flag)
					{	
						case LINE_FLAG_LF:					
						case LINE_FLAG_CR:	
							cur_http_node->processed_offset += 1;
							break;					
						case LINE_FLAG_CRLF:
							cur_http_node->processed_offset += 2;
							break;
						default:
							break;
					}
				
				}
				else
				{				
					http_saveToBuf(curdata,curdata_len,p_end,fold_flag,del_space,cur_http_node,thread_seq);					
				}														
			}						
		}
	}		
	if(g_http_prog_para.http_stat_cycle)
	{
		if(DIR_C2S==cur_http_node->parser.curdir)
		{
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_HEADER_C2S], FS_OP_TYPE_ADD,cur_http_node->poneline_datalen);
		}
		else
		{
			stat_field_operation(g_http_prog_para.stat_handler, g_http_prog_para.stat_field[HTTP_STAT_HEADER_S2C], FS_OP_TYPE_ADD,cur_http_node->poneline_datalen);
		}		
	}
	return OK;
}

void http_updatePktOffset(http_parser_t *a_http, http_stream* a_http_stream, struct streaminfo *a_tcp)
{
	struct tcpdetail *tcp_detail = (struct tcpdetail*)a_tcp->pdetail;
	if(tcp_detail->datalen>a_http->processed_offset)
	{
		/*because pbuf, a_http->processed_offset maybe 0 ,but need proc continue*/
		a_http_stream->packet_offset = a_http->processed_offset;
		a_http_stream->proc_pkt_continue = 1;
	}
	else
	{
		a_http_stream->packet_offset = 0;
	}
}
