vpath %.a ../lib
vpath %.h ./inc

PAPP_PATH=/home/lishu/soq/sapp/

#CFLAGS          =  -g3 -Wall -fPIC -Werror -O
#CFLAGS          =  -g3 -Wall -fPIC -O
CFLAGS          =  -g3 -Wall -fPIC
CFLAGS	       	+= $(INCLUDES)
CC              = g++
CCC             = g++
INCLUDES        = -I./inc/
INCLUDES        += -I/usr/include/MESA/

LIB		= -L./lib/ 
LIB		+= -lMESA_handle_logger
LIB		+= -lMESA_prof_load
LIB		+= -lMESA_htable 
LIB   		+= -lMESA_field_stat
LIB		+= -ldocumentanalyze
LIB		+= ./lib/libhttp_parser.a

LIB_FILE	= $(wildcard ./lib/*.a)
SOURCES		= $(wildcard *.c)
OBJECTS 	= $(SOURCES:.c=.o)
DEPS		= $(SOURCES:.c=.d)

TARGET		= http.so

.PHONY:clean all 

all:$(TARGET)

$(TARGET):$(OBJECTS) $(LIB_FILE)
	$(CCC) -shared $(CFLAGS) $(OBJECTS) $(LIB) -o $@ -Wl,--version-script=http_global.map   
	cp http.so ../bin/
	
.c.o:
%.d:%.c
	$(CCC) $< -MM $(INCLUDES) > $@

-include $(DEPS)

clean :
	rm -f $(OBJECTS) $(DEPS) $(TARGET) 


PLUGIN_PATH=./plug/protocol
CONFLIST_NAME=conflist_protocol.inf
PLUGIN_DIR_NAME=http
PLUGIN_INF_NAME=http.inf

TARGET_DIR=$(PAPP_PATH)/$(PLUGIN_PATH)/$(PLUGIN_DIR_NAME)/
INSERT_FILE=$(PAPP_PATH)/$(PLUGIN_PATH)/$(CONFLIST_NAME)
INSERT_CONTENT=$(PLUGIN_PATH)/$(PLUGIN_DIR_NAME)/$(PLUGIN_INF_NAME)
install:
	mkdir -p  $(TARGET_DIR) 
	cp -r ../bin/http.inf $(TARGET_DIR)
	cp -r ../bin/http.so $(TARGET_DIR)
	@ret=`cat $(INSERT_FILE)|grep $(INSERT_CONTENT)|wc -l`;if [ $$ret -eq 0 ];then echo $(INSERT_CONTENT) >>$(INSERT_FILE);fi
        
CONF_DIR=$(PAPP_PATH)/conf/
conf:
	mkdir -p  $(CONF_DIR) 
	cp -r ../bin/http $(CONF_DIR)   
