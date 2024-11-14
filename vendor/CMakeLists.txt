include(ExternalProject)

ExternalProject_Add(http_parser PREFIX http_parser
                        URL ${CMAKE_CURRENT_SOURCE_DIR}/http-parser-2.9.0.tar.gz
                        URL_MD5 030a4f637582de0461d47a1664e8ef62
                        CONFIGURE_COMMAND ""
                        BUILD_COMMAND make static-library
                        INSTALL_COMMAND ""
                        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(http_parser INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/src/http_parser/)

add_library(http_parser-static STATIC IMPORTED GLOBAL)
add_dependencies(http_parser-static http_parser)
set_property(TARGET http_parser-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/src/http_parser/libhttp_parser.a)
set_property(TARGET http_parser-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/src/http_parser/)
