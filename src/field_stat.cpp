#include "field_stat.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#define	MAX_STAT_FIELD_NUM	256
#define	FIELD_PER_LINE		8
struct stat_field_t
{
	char	*filed_name;
	long long current_value;
	long long last_output_value;
};
struct screen_stat_space_t
{
	int stat_cycle;
	int screen_print_trigger;
	FILE* fp;
	struct stat_field_t stat_array[MAX_STAT_FIELD_NUM];
	int inuse_num;
};
void *thread_screen_print(void *arg)
{
	struct screen_stat_space_t* handle=(struct screen_stat_space_t*)arg;
	int i=0,j=0;
	long long differenc_valule;
	time_t now;
	char print_buf[1024*64]={0};
	char*pos=NULL;
	while(1)
	{
		now=time(NULL);
		pos=print_buf;
		pos+=snprintf(pos,sizeof(print_buf)-(pos-print_buf),"=====================================================%s",ctime(&now));
		while(i<handle->inuse_num)
		{
			pos+=snprintf(pos,sizeof(print_buf)-(pos-print_buf),"\t");
			for(j=0;j<FIELD_PER_LINE&&i+j<handle->inuse_num;j++)
			{
				pos+=snprintf(pos,sizeof(print_buf)-(pos-print_buf),"%10s\t",handle->stat_array[i+j].filed_name);
			}
			pos+=snprintf(pos,sizeof(print_buf)-(pos-print_buf),"\nsum\t");
			for(j=0;j<FIELD_PER_LINE&&i+j<handle->inuse_num;j++)
			{
				pos+=snprintf(pos,sizeof(print_buf)-(pos-print_buf),"%10lld\t",handle->stat_array[i+j].current_value);	
			}
			pos+=snprintf(pos,sizeof(print_buf)-(pos-print_buf),"\nspeed/s\t");
			for(j=0;j<FIELD_PER_LINE&&i+j<handle->inuse_num;j++)
			{
				differenc_valule=handle->stat_array[i+j].current_value-handle->stat_array[i+j].last_output_value;
				handle->stat_array[i+j].last_output_value=handle->stat_array[i+j].current_value;
				pos+=snprintf(pos,sizeof(print_buf)-(pos-print_buf),"%10lld\t",differenc_valule/handle->stat_cycle);	
			}
			i+=j;
			pos+=snprintf(pos,sizeof(print_buf)-(pos-print_buf),"\n");
		}
		fprintf(handle->fp,"%s",print_buf);
		i=0;
		sleep(handle->stat_cycle);
	}
	return NULL;
}
screen_stat_handle_t init_screen_stat(FILE* output_fp,int stat_cycle,int screen_print_trigger)
{
	struct screen_stat_space_t* handle=(struct screen_stat_space_t*)calloc(sizeof(struct screen_stat_space_t),1);
	handle->fp=output_fp;
	handle->stat_cycle=stat_cycle;
	handle->screen_print_trigger=screen_print_trigger;
	pthread_t cfg_mon_t;
	if(handle->screen_print_trigger==1)
	{
		pthread_create(&cfg_mon_t, NULL, thread_screen_print, (void*)handle);
	}
	return handle;
}

int stat_field_register(screen_stat_handle_t handle,const char* field_name)
{
	struct screen_stat_space_t* _handle=(struct screen_stat_space_t*)handle;
	int idx=_handle->inuse_num++;
	_handle->stat_array[idx].filed_name=(char*)calloc(strlen(field_name)+1,1);
	memcpy(_handle->stat_array[idx].filed_name,field_name,strlen(field_name));
	return idx;
}

int stat_field_operation(screen_stat_handle_t handle,int field_id,int operation,long long value)
{
	struct screen_stat_space_t* _handle=(struct screen_stat_space_t*)handle;
	switch(operation)
	{
		case	FS_OP_TYPE_ADD:
			_handle->stat_array[field_id].current_value+=value;
			break;
		case	FS_OP_TYPE_SET:
			_handle->stat_array[field_id].current_value=value;
			break;	
		default:
			return -1;
			break;
	}
	return 0;
}
   
