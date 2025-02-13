cmake_minimum_required(VERSION 3.10)
project(nicread LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE ON)
add_compile_options(-g )

# 包含头文件目录
include_directories(include)
find_package(Threads REQUIRED)


# 添加源文件
file(GLOB_RECURSE SOURCES "src/*.cpp")
#file(GLOB NETWORK_SOURCES "src/network")

# 生成可执行文件
add_executable(nicread ${NETWORK_SOURCES} ${SOURCES})

# 链接线程库
target_link_libraries(nicread PRIVATE Threads::Threads)

target_include_directories(nicread PRIVATE src)