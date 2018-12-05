#ifndef H_SCREEN_STAT_H_INCLUDE
#define H_SCREEN_STAT_H_INCLUDE
#include <stdio.h>

typedef	void* screen_stat_handle_t;


screen_stat_handle_t init_screen_stat(FILE* output_fp,int stat_cycle,int screen_print_trigger);

//return field_id >=0 when success, return -1 when failed.
int stat_field_register(screen_stat_handle_t handle,const char* field_name);

//return >=0 when success, return -1 when failed.
#define	FS_OP_TYPE_ADD	1
#define	FS_OP_TYPE_SET	2
int stat_field_operation(screen_stat_handle_t handle,int field_id,int operation,long long value);

#endif

