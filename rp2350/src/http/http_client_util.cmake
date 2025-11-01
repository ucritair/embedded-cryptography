pico_add_library(http_client NOFLAG)

target_sources(http_client INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/http_client_util.c
        ${CMAKE_CURRENT_LIST_DIR}/httpss_client.c
)

pico_mirrored_target_link_libraries(http_client INTERFACE
        pico_lwip_http
        pico_lwip_mbedtls
        pico_mbedtls
)

target_include_directories(http_client INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}
)
