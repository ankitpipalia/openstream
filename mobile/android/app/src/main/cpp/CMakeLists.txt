cmake_minimum_required(VERSION 3.22.1)
project(openstream_jni LANGUAGES CXX)

add_library(openstream_mobile_ffi STATIC IMPORTED)
set_target_properties(openstream_mobile_ffi PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_LIST_DIR}/../jniLibs/${ANDROID_ABI}/libopenstream_mobile_ffi.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_LIST_DIR}/../../../../../../include")

add_library(openstream_jni SHARED openstream_jni.cpp)
target_include_directories(openstream_jni PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../../../../../include")
find_library(log-lib log)
target_link_libraries(openstream_jni openstream_mobile_ffi ${log-lib})
