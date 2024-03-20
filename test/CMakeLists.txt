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



include(ExternalProject)
#### Protoco_test_run

ExternalProject_Add(ProtoTest PREFIX ProtoTest
        URL ${CMAKE_CURRENT_SOURCE_DIR}/test_protocol_run.zip
        URL_MD5 71d8284b59af0286b5f31f0a3160bc44  
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/conf/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/bin/http/${lib_name}.conf <SOURCE_DIR>/conf/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/bin/http/${lib_name}_main.conf <SOURCE_DIR>/conf/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/conflist.inf <SOURCE_DIR>/plug/
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/plug/protocol/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/bin/${lib_name}.inf <SOURCE_DIR>/plug/protocol/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/plug/business/${lib_name}_test_plug/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/test/${lib_name}_test_plug.inf <SOURCE_DIR>/plug/business/${lib_name}_test_plug/)

ExternalProject_Get_Property(ProtoTest INSTALL_DIR)
ExternalProject_Get_Property(ProtoTest SOURCE_DIR)
set(PROTO_TEST_RUN_DIR ${SOURCE_DIR})

add_executable(proto_test_main IMPORTED GLOBAL)
add_dependencies(proto_test_main ProtoTest)
set_property(TARGET proto_test_main PROPERTY IMPORTED_LOCATION ${SOURCE_DIR}/test_protocol_plug_main)


add_library(${lib_name}_test_plug SHARED ${lib_name}_test_plug.cpp md5.c)
target_link_libraries(${lib_name}_test_plug MESA_prof_load cjson)
set_target_properties(${lib_name}_test_plug  PROPERTIES PREFIX "")

add_test(NAME COPY_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/${lib_name}.so ${PROTO_TEST_RUN_DIR}/plug/protocol/${lib_name}/${lib_name}.so")
add_test(NAME COPY_TEST_SO COMMAND sh -c "cp ${CMAKE_CURRENT_BINARY_DIR}/${lib_name}_test_plug.so ${PROTO_TEST_RUN_DIR}/plug/business/${lib_name}_test_plug/${lib_name}_test_plug.so")

add_test(NAME RUN_HTTP_GET_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/http_get/http_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/http_get/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_HTTP_POST_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/http_post/http_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/http_post/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_HTTP_GZIP_SMALL_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_small/gzip_small.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_small/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_HTTP_GZIP_LARGE_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_large/gzip_large.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_large/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_HTTP_DEFLATE_SMALL_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/deflate_small/deflate_small.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/deflate_small/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_HTTP_DEFLATE_LARGE_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/deflate_large/deflate_large.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/deflate_large/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_HTTP_CLEAR_TEXT_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/clear_text/clear_text.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/clear_text/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME RUN_HTTP_GZIP_BOMB_TEST COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_bomb/gzip_bomb.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/gzip_bomb/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})