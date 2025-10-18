cmake_minimum_required(VERSION 3.13)

# initialize the SDK directly
include(./pico_sdk_import.cmake)

project(my_project)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()

# rest of your project


add_executable(test
	test.c
#	battery_e2e.c
)

target_compile_definitions(test PUBLIC
	PICO_USE_STACK_GUARDS=1
	PICO_STACK_SIZE=4096
)
#target_compile_definitions(test PUBLIC PARAM_ASSERTIONS_ENABLE_ALL=1)


target_include_directories(test PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/
	${CMAKE_CURRENT_LIST_DIR}/include
)

# Add pico_stdlib library which aggregates commonly used features
target_link_libraries(test
	pico_malloc
	pico_stdlib
	pico_multicore
	hardware_dma
	${CMAKE_CURRENT_SOURCE_DIR}/lib/libbattery_embedded.a
)

#pico_set_linker_script(test ${CMAKE_CURRENT_SOURCE_DIR}/memmap_griffon.ld)

pico_enable_stdio_usb(test 1)
pico_enable_stdio_uart(test 0)

# create map/bin/hex/uf2 file in addition to ELF.
pico_add_extra_outputs(test)

