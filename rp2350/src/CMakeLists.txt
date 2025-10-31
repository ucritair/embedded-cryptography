cmake_minimum_required(VERSION 3.13)

project(pico_project C CXX ASM)

include(http_client_util.cmake)

add_executable(pico_project
    main.c
    tf_port.c
    ipc.c
    httpss_client.c

    # Crypto Ops
    battery_e2e.c
)

target_include_directories(pico_project PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/../
)

# pull in common dependencies
target_link_libraries(pico_project pico_stdlib tinyframe pico_cyw43_arch_lwip_sys_freertos pico_lwip pico_multicore
    pico_async_context_freertos
    FreeRTOS-Kernel-Heap4
    http_client_util
    ${CMAKE_SOURCE_DIR}/../target/thumbv8m.main-none-eabihf/release/libbattery_embedded.a
)

target_compile_definitions(pico_project PRIVATE
    configNUMBER_OF_CORES=1
    NO_SYS=0
)

# enable usb output, disable uart output
pico_enable_stdio_usb(pico_project 1)
pico_enable_stdio_uart(pico_project 0)


pico_add_extra_outputs(pico_project)
