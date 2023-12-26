cmake_minimum_required(VERSION 3.6)

SET( PROJECT_VERSION 0.0.8 )

project(electricui-embedded)

add_library(electricui_static STATIC src/electricui.c src/eui_utilities.c src/transports/eui_binary_transport.c)
add_library(electricui SHARED src/electricui.c src/eui_utilities.c src/transports/eui_binary_transport.c)

target_include_directories(electricui_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/transports)
target_include_directories(electricui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/transports)
