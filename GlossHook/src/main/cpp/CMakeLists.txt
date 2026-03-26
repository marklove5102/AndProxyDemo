cmake_minimum_required(VERSION 3.22.1)
project("GlossHook")

# 真实库路径（根据 ABI 动态选择）
set(REAL_LIB_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libGlossHook.so)

message(STATUS ${REAL_LIB_PATH})

# 创建空源文件
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp "")

# 创建目标（类型与真实库一致，此处为 SHARED）
add_library(GlossHook SHARED ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp)

# 构建完成后用真实库覆盖
add_custom_command(TARGET GlossHook POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${REAL_LIB_PATH}"
        "$<TARGET_FILE:GlossHook>"
        COMMENT "Copying real libGlossHook.so to output"
)

# 导出头文件目录
target_include_directories(GlossHook INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)