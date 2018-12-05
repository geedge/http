#ifndef HTTP_COMMON_H_
#define HTTP_COMMON_H_

#include "HTTP_Message.h"

#define MIN(a, b)                    ((a) <= (b) ? (a):(b))
#define MAX(a, b)                    ((a) >= (b) ? (a):(b))

#ifdef __cplusplus
extern "C" {
#endif

void http_freeBuf(int thread_seq, char **buf, uint32 *buflen);
char* double_memchr(const char* before, uint32 before_len, const char* this_data, uint32 this_len, char c);
char* double_memread(const char*before,uint32 before_len,const char* this_data,uint32 this_len,const char*pos,uint32 offset);
uint32 double_mem_offset(const char*before,uint32 before_len,const char* this_data,uint32 this_len,const char* p);
char A_to_a(char ch);
void http_deleteEmptyRow(uint32 *offset, char* data, uint32 data_len);
void http_deleteEmptyRow_chunk(uint32 *offset, char* data, uint32 data_len);
void http_deleteSPHT(uint32 *offset, char* data, uint32 data_len);
void http_deleteSPHTCRLFAtLast(uint32 *del_data_len, char* data, uint32 data_len);
char* http_findCRLF(char *all_data, uint32 len);
char* http_findCRLF_Chunk(char *all_data, uint32 len, uint32* end_flag_size);
void stringA_to_stringa(char* str, uint32 l_str);
char *memcasemem(const char *strsrc,int len1,const char *substr,int len2);
long long rdtsc(void);

#ifdef __cplusplus
}
#endif
#endif /* HTTP_COMMON_H_ */
