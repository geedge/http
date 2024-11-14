cmake_minimum_required (VERSION 2.8...3.10)

project(${lib_name}_test)

include(ExternalProject)
#### GoogleTest
ExternalProject_Add(GoogleTest PREFIX GoogleTest
        URL ${CMAKE_CURRENT_SOURCE_DIR}/googletest-release-1.8.0.tar.gz
        URL_MD5 16877098823401d1bf2ed7891d7dce36
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(GoogleTest INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)
add_library(gtest STATIC IMPORTED GLOBAL)
add_dependencies(gtest GoogleTest)
set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libgtest.a)
set_property(TARGET gtest PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET gtest PROPERTY INTERFACE_LINK_LIBRARIES pthread)

enable_testing()
add_executable(HTTPUintTest unit_test.cpp mock_sapp.cpp)
target_link_libraries(HTTPUintTest gtest http)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "/opt/tsg/sapp" CACHE PATH "default install path" FORCE)
	message(STATUS "CMAKE_INSTALL_PREFIX='${CMAKE_INSTALL_PREFIX}'")
endif()

LINK_DIRECTORIES(${CMAKE_INSTALL_PREFIX}/lib)
LINK_DIRECTORIES(/home/mesasoft/sapp_run/lib)
LINK_DIRECTORIES(/opt/tsg/sapp/lib/)
LINK_DIRECTORIES(/opt/MESA/lib/)
LINK_DIRECTORIES(/opt/tsg/framework/lib/)

set(TEST_RUN_DIR ${CMAKE_INSTALL_PREFIX})
set(PLUGIN_TEST_MAIN ${CMAKE_INSTALL_PREFIX}/plugin_test_main)
message(STATUS "TEST_RUN_DIR='${TEST_RUN_DIR}'")

add_library(${lib_name}_test_plug SHARED ${lib_name}_test_plug.cpp md5.c)
target_link_libraries(${lib_name}_test_plug MESA_prof_load cjson)
set_target_properties(${lib_name}_test_plug  PROPERTIES PREFIX "")

# build test env
add_test(NAME MKDIR COMMAND sh -c "mkdir -p ${TEST_RUN_DIR}/plug/protocol/${lib_name} && mkdir -p ${TEST_RUN_DIR}/plug/business/${lib_name}_test_plug && mkdir -p ${TEST_RUN_DIR}/conf/http")
add_test(NAME COPY_PLUGIN_TEST_MAIN COMMAND sh -c "cp ${TEST_RUN_DIR}/tools/plugin_test_main ${TEST_RUN_DIR}/plugin_test_main")
add_test(NAME COPY_CONFLIST COMMAND sh -c "mkdir -p ${TEST_RUN_DIR}/plug/ && cp ${CMAKE_CURRENT_SOURCE_DIR}/conflist.inf ${TEST_RUN_DIR}/plug/conflist.inf")
add_test(NAME COPY_HTTP_DECODER_CONF COMMAND sh -c "cp ${CMAKE_SOURCE_DIR}/bin/http/http*.conf ${TEST_RUN_DIR}/conf/http/")

add_test(NAME COPY_HTTP_INF COMMAND sh -c "cp ${CMAKE_SOURCE_DIR}/bin/http.inf ${TEST_RUN_DIR}/plug/protocol/${lib_name}/${lib_name}.inf")
add_test(NAME COPY_HTTP_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/${lib_name}.so ${TEST_RUN_DIR}/plug/protocol/${lib_name}/${lib_name}.so")

add_test(NAME COPY_TEST_INF COMMAND sh -c "cp ${CMAKE_CURRENT_SOURCE_DIR}/http_test_plug.inf ${TEST_RUN_DIR}/plug/business/${lib_name}_test_plug/${lib_name}_test_plug.inf")
add_test(NAME COPY_TEST_SO COMMAND sh -c "cp ${CMAKE_CURRENT_BINARY_DIR}/${lib_name}_test_plug.so ${TEST_RUN_DIR}/plug/business/${lib_name}_test_plug/${lib_name}_test_plug.so")

# update sapp config files
add_test(NAME UPDATE_SAPP_LOG_LEVEL COMMAND bash -c "sed -i 's/sapp_log.fatal/sapp_log.info/' ${TEST_RUN_DIR}/etc/sapp_log.conf")
add_test(NAME UPDATE_SAPP_SYN_MODE COMMAND bash -c "sed -i 's/syn_mandatory=1/syn_mandatory=0/' ${TEST_RUN_DIR}/etc/sapp.toml")
add_test(NAME ENABLE_SAPP_MONITOR COMMAND bash -c "sed -i 's/monitor_thread_enabled=0/monitor_thread_enabled=1/' ${TEST_RUN_DIR}/etc/sapp.toml")


add_test(NAME RUN_HTTP_GET_TEST COMMAND ./plugin_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/http_get/http_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/http_get/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_HTTP_POST_TEST COMMAND ./plugin_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/http_post/http_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/http_post/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_HTTP_GZIP_SMALL_TEST COMMAND ./plugin_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_small/gzip_small.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_small/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_HTTP_GZIP_LARGE_TEST COMMAND ./plugin_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_large/gzip_large.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_large/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_HTTP_DEFLATE_SMALL_TEST COMMAND ./plugin_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/deflate_small/deflate_small.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/deflate_small/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_HTTP_DEFLATE_LARGE_TEST COMMAND ./plugin_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/deflate_large/deflate_large.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/deflate_large/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_HTTP_CLEAR_TEXT_TEST COMMAND ./plugin_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/clear_text/clear_text.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/clear_text/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})