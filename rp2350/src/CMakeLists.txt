cmake_minimum_required(VERSION 3.13)

project(pico_project C CXX ASM)

add_executable(pico_project
    main.c
    tf_port.c
    ipc.c
)

target_include_directories(pico_project PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# pull in common dependencies
target_link_libraries(pico_project pico_stdlib tinyframe pico_cyw43_arch_lwip_poll pico_lwip)

# enable usb output, disable uart output
pico_enable_stdio_usb(pico_project 1)
pico_enable_stdio_uart(pico_project 0)


pico_add_extra_outputs(pico_project)
