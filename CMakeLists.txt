cmake_minimum_required(VERSION 3.10)
project(nicread LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE ON)
#add_compile_options(-O2 )
add_compile_options(-g )

#set(CMAKE_C_COMPILER clang)
#set(CMAKE_CXX_COMPILER clang++)


# 包含头文件目录
include_directories(include)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# 添加源文件
file(GLOB_RECURSE SOURCES "src/*.cpp")
#file(GLOB NETWORK_SOURCES "src/network")

# 生成可执行文件
add_executable(nicread ${NETWORK_SOURCES} ${SOURCES})

# 链接线程库
target_link_libraries(nicread PRIVATE Threads::Threads OpenSSL::Crypto)

target_include_directories(nicread PRIVATE src)

if(OPENSSL_FOUND)
  string(REGEX MATCH "^([0-9]+)" OPENSSL_MAJOR_VERSION ${OPENSSL_VERSION})
  if(OPENSSL_MAJOR_VERSION GREATER_EQUAL 3)
    message("OpenSSL version is greater than 3: ${OPENSSL_VERSION}")
    #add_definitions(-DOPENSSL_VERSION="${OPENSSL_VERSION}")
    add_definitions(-DSSL_MY_3)
  else()
    message("OpenSSL version is ${OPENSSL_VERSION}, not greater than 3")
  endif()
endif()
