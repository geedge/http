#ifndef HTTP_MESSAGE_H_
#define HTTP_MESSAGE_H_

#include <stdio.h>
#include "http.h"
#include "stream.h"
#include "DocumentAnalyze.h"

#define	HTTP_PLUGIN_NAME 				"http.so"

/*-------------------function switch---------------------------*/
#define	DEBUG_TEST_DEAL_TIME			0
#define	HTTP_PROXY						1
#define	HTTP_PROXY_CAPFILE				0
/*-------------------function switch end---------------------------*/

#define	HTTP_REGION_HASH				0
#define	HTTP_STATIC						0    //close some test static   1. hash  VS str 2. pkt proc time when HTTP_ENTRY

#define PROXY_CONNECTION_SUCC 			"Connection established"
#define PROXY_CONNECTION_FAIL_401 	"unauthorized"
#define PROXY_CONNECTION_FAIL_407 	"proxy authentication required"

#define HTTP_KEY 						2
#define	HTTP_TRUE 						1
#define HTTP_FLASE 						0

#define MAX_REGION_NUM 					64
#define REGION_NAME_LEN 				64

#define HTTP_RETURN_GIVEME 				0x00
#define HTTP_RETURN_RESET 				0x01
#define HTTP_RETURN_DROPPKT				0x02

#define HTTP_CR 						13
#define HTTP_LF 						10
#define HTTP_SP 						32
#define HTTP_HT 						9
#define HTTP_NULL						0x00

#define MAX_DEALTIME_LEVEL				20

/*http state*/
#define HTTP_STAT_PKTS					0
#define HTTP_STAT_BITS					1
#define HTTP_STAT_REQ					2
#define HTTP_STAT_RES					3
#define HTTP_STAT_CREATE				4
#define HTTP_STAT_RELEASE				5
#define HTTP_STAT_C2S					6
#define HTTP_STAT_S2C					7
#define HTTP_STAT_HEADER_C2S			8
#define HTTP_STAT_HEADER_S2C			9
#define HTTP_STAT_CONTENT_C2S			10
#define HTTP_STAT_CONTENT_S2C			11
#define HTTP_STAT_LOST					12
#define HTTP_STAT_RESET					13
#define HTTP_STAT_REGION_TIME_STR		14
#define HTTP_STAT_REGION_TIME_HASH		15
#define HTTP_STAT_TCP_PKT_CALLBACK		16
#define HTTP_STAT_TCP_PKT_PROC_TIME		17
#define HTTP_STAT_TCP_PKT_PROC_MAXTIME	18
#define HTTP_STAT_CBPLUGIN				19
#define HTTP_STAT_CBPLUGIN_PROC_TIME 	20
#define HTTP_STAT_CLIENT_PKT 			21
#define HTTP_STAT_CLIENT_BYTE 			22
#define HTTP_STAT_SERVER_PKT 			23
#define HTTP_STAT_SERVER_BYTE 			24
#define HTTP_STAT_HEADER_SPAN_CNT 		25
#define HTTP_STAT_HEADER_SPAN_PKT 		26
#define HTTP_STAT_HEADER_SPAN_BYTE 		27
#define HTTP_MAX_STAT_FIELD				28

/*������룬û��chunk��û��cont-length*/
#define HTTP_TRANS_ENCOD_CNNTCLOSE 		0X04//connection close

#define HTTP_CHUNK_STATE_UNKONWN		0X00
#define HTTP_CHUNK_STATE_LENGTH			0X01
#define HTTP_CHUNK_STATE_DATA			0X02

#define COMPLETE_BUFLEN					100*1024*1024

#define FLAG_SET(x, flag) 				((x) |= (flag))
#define FLAG_CLEAR(x, flag) 				((x) &= ~(flag))
#define FLAG_TEST(x, flag) 				(0 != ((x) & (flag))) 

/*http flag in http_parser_t*/
#define HTTP_FLAG_OVER					0x0001
#define HTTP_FLAG_SESSION				0x0002
#define HTTP_FLAG_TRANS_LEN				0x0004
#define HTTP_FLAG_GET_URL				0x0008
#define HTTP_FLAG_CONNECT_CLOSE			0x0010
#define HTTP_FLAG_NO_UNGZIP				0x0020
#define HTTP_FLAG_SPAN					0x0040
#define HTTP_FLAG_BATCH_CALLBACK		0x0080
#define HTTP_FLAG_CONNECT_WEBSOCKET		0x0100

/*callback mode*/
#define HTTP_CALLBACK_MODE_FIELD		0x00
#define HTTP_CALLBACK_MODE_BATCH		0x01
#define HTTP_CALLBACK_MODE_FIELD_BATCH	0x02

#define LINE_FLAG_CR					0x01 
#define LINE_FLAG_LF					0x02 
#define LINE_FLAG_CRLF 					0x03

#define	HTTP_UNZIP_CONTENT_LEN		16*1024

typedef enum
{
	GO_BACK=1,
	OK=2,
	ERROR=3,
}rec_val;

typedef struct _business_infor_t
{
	void*						param;
	uchar 						return_value;
}business_infor_t;

typedef struct _session_infor_t
{
	char* 						buf;
	uint32 						buflen;
}session_infor_t;

typedef struct _fold_infor_t
{
	void*						buf;			   //�۵��л�����
	int							buflen;		   //�۵��л�������С
}fold_infor_t;

typedef struct _fold_buf_t
{
	int 						cnt;
	fold_infor_t* 				fold;
}fold_buf_t;

typedef struct _http_parser_t
{
	http_infor					parser; 	
	business_infor_t 			business;			
	session_infor_t 			session;		

	struct _http_parser_t* 	prev;
	struct _http_parser_t* 	next;
	
	interested_region_mask 		interested_reg_mask;		
	uint32 						buflen;	
	
	char*	 					pbuf;
	fold_buf_t*					pbuf_fold;				 	
	char* 						poneline_data;	
	char* 						phttp_begin;		
	
	uint32 						poneline_datalen;	
	uint32 						processed_offset;			//�Ѵ��������ڵ�ǰ����ƫ����,��������һ������Ҫ����	
	
	uint64 						packet_entity_len;			//δ������ʵ�峤��			
	docanalyze_streamparam_t	ungzip_handle;		
	uint64 						acc_cont_length;	
	int64 						batch_prot_flag;	
	char*						url_buf;		
	uint32 						url_buflen;	
	uint16						flag;							//see define 
	
	uint8 						chunk_state;    				//chunk state : 3 state
	char						endline_flag;  		        //complete line flag: \r\n, \r, \n.
	uint8 						mgs_status;					//return state							
	uint8						header_span_flag;			//see define 
		
#if HTTP_PROXY
	uchar						proxy_flag;					//DIR_C2S, DIR_S2C,DIR_DOUBLE	
	uchar						proxy_cb_flag;		
#endif
	
}http_parser_t;

typedef struct _http_prog_runtime_parameter_t
{	
	uint64 						http_interested_region_flag;
	char 						http_stat_filename[256];
	char 						http_conf_regionname[MAX_REGION_NUM][REGION_NAME_LEN];	

	FILE*   					http_stat_file;	
	void* 						http_log_handle;		
	void*						region_hash;	    //��չ���ʶ��
	void*						stat_handler;
	void* 						docanly_handler;
	
	uint16 						http_plugid;	
	uint16 						http_log_level;	
	uint16 						ungzip_switch;
	uint16 						http_switch_no_biz;
	
	int 						http_stat_screen_print_trigger;
	int 						http_stat_cycle;		
	
	long long					stat_value[HTTP_MAX_STAT_FIELD];
	int							stat_field[HTTP_MAX_STAT_FIELD];	
	uint32 						http_header_string_map_num;	
	uint32						singleway_seq;
#if HTTP_STATIC
	long long 					tcppkt_dealtime_max;	
#endif
	int 						http_region_cnt;
	uint16 						callback_mode;
	uint16 						batch_field_maxnum;
	uint16 						proxy_switch;
	uint16 						s2c_head_check_switch;
	uchar						need_http_state;	
	uchar						not_proc;	
	
#if DEBUG_TEST_DEAL_TIME	
	unsigned long 				pkt_dealtime;
	unsigned long 				pkt_dealtime_total;
	unsigned long 				pkt_dealtime_max;
	unsigned long 				pkt_dealtime_arv;
	unsigned long 				pkt_num;	
	unsigned long 				dealtime_level[MAX_DEALTIME_LEVEL];
	pthread_mutex_t stat_lock;
#endif

#if HTTP_PROXY_CAPFILE
	int 						capfile_project_id;
#endif
	int							proto_tag_id ;
	fold_infor_t *unzip_content;
}http_prog_runtime_parameter_t;

struct http_proto_tag_t
{    
	char buf[8];
};

#ifdef __cplusplus
extern "C" {
#endif

int HTTP_INIT(void);
char HTTP_ENTRY(struct streaminfo *a_tcp, void**pme, int thread_seq, void *a_pcaket);
void HTTP_DESTROY(void);

long long HTTP_FLAG_CHANGE(char* flag_str);
void HTTP_PROT_FUNSTAT(unsigned long long protflag);
void HTTP_GETPLUGID(unsigned short plugid);
uchar http_judgeHeaderOver(http_parser_t *a_http, char *data, uint32 data_len, int thread_seq);
uchar http_positioningACompleteLine(char del_space, http_parser_t *cur_http_node, struct streaminfo *a_tcp, int thread_seq);
int http_add_proto_tag(int projetc_id, struct streaminfo *a_stream, const char* value, int len);
int http_host_parser(const char* buf, uint32 buflen, int http_dir, char** host);

#ifdef __cplusplus
}
#endif

#endif 
