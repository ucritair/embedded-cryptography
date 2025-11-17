cmake_minimum_required(VERSION 3.13)

project(cat_rp2350 C CXX ASM)

include(http/http_client_util.cmake)

add_executable(cat_rp2350
    main.c
    tf_port.c
    ipc.c
    cli_commands.c
    FreeRTOS_CLI.c
    cloud/balvi_config.c
    http/httpss_client.c
    http/http_post_client.c

    # Crypto Ops
    crypto/crypto_shared.c
)

target_include_directories(cat_rp2350 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/cloud
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/http
    ${CMAKE_SOURCE_DIR}/../
    ${CMAKE_SOURCE_DIR}/../include
)

# pull in common dependencies
target_link_libraries(cat_rp2350 pico_stdlib tinyframe pico_cyw43_arch_lwip_sys_freertos pico_lwip pico_lwip_sntp pico_multicore
    pico_async_context_freertos
    pico_bootrom
    FreeRTOS-Kernel-Heap4
    http_client
    ${CMAKE_SOURCE_DIR}/../target/thumbv8m.main-none-eabihf/release/libbattery_embedded.a
)

target_compile_definitions(cat_rp2350 PRIVATE
    configNUMBER_OF_CORES=1
    NO_SYS=0
)

# enable usb output, disable uart output
pico_enable_stdio_usb(cat_rp2350 1)
pico_enable_stdio_uart(cat_rp2350 0)


pico_add_extra_outputs(cat_rp2350)
