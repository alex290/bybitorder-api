cmake_minimum_required(VERSION 3.20.0)
project(ByBitOrder VERSION 0.1.0)

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-O3") # Компиляция больших файлов
set(CMAKE_CXX_STANDARD 17) 
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)


file(GLOB project
    src/*
)
add_executable(${PROJECT_NAME} ${project})

if(CURL_FOUND)
    include_directories(${CURL_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} ${CURL_LIBRARIES})
    message(STATUS "Found CURL ${CURL_VERSION_STRING}")
else()
    message(STATUS "CURL Not Found")
endif()

if (OPENSSL_FOUND)
    # Add the include directories for compiling
    target_include_directories(${PROJECT_NAME} PUBLIC ${OPENSSL_INCLUDE_DIR})
    # Add the static lib for linking
    target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
else()
    message(STATUS "OpenSSL Not Found")
endif()