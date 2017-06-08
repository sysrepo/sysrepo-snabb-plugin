cmake_minimum_required(VERSION 2.8.12)
project(sysrepo-snabb-plugin)

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wpedantic -std=gnu11")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

set(PLUGIN 1 CACHE BOOL "Build a plugin.")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

set(SOURCES
	src/snabb.c)

if (PLUGIN)
	add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
else()
	add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PREFIX "")

find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

# get sysrepo plugins directory
if (NOT SR_PLUGINS_DIR)
    if (PKG_CONFIG_FOUND)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=SR_PLUGINS_DIR" "libsysrepo" OUTPUT_VARIABLE SR_PLUGINS_DIR)
        string(STRIP ${SR_PLUGINS_DIR} SR_PLUGINS_DIR)
    endif()
endif()
if (NOT SR_PLUGINS_DIR)
    message(FATAL_ERROR "Cannot get sysrepo plugins directory due to missing pkg-config, set SR_PLUGINS_DIR manually.")
endif()

# find programs
if (NOT SYSREPOCTL_EXECUTABLE)
    find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
endif()
if (NOT SYSREPOCTL_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
endif()

execute_process(COMMAND ${SYSREPOCTL_EXECUTABLE} -i -g ${CMAKE_SOURCE_DIR}/yang/snabb-softwire-v1.yang -o root:root -p 666 RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE OUT)
if (RET)
	string(REPLACE \"\\n\" \"\\n  \" OUT \${OUT})
	message(FATAL_ERROR \"  Command sysrepoctl list failed:\n  \${OUT}\")
endif()

if (PLUGIN)
	install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION ${SR_PLUGINS_DIR})
else()
	install(TARGETS ${CMAKE_PROJECT_NAME} RUNTIME DESTINATION bin)
endif()
