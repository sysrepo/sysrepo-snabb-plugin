cmake_minimum_required(VERSION 2.8.12)
project(sysrepo-snabb-plugin)

include(CompileOptions.cmake)

set(YANG_MODEL "snabb-softwire-v2" CACHE STRING "YANG model to use.")
set(PLUGIN 0 CACHE BOOL "Build a plugin.")
set(LEAF_LIST 1 CACHE BOOL "YANG model has a leaf-list in configuration.")
set(THREADS 4 CACHE INTERNAL "Number of threads to use")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

set(SOURCES
	cfg_parse/cfg_parse.c
	src/libyang.c
	src/snabb.c
	src/cfg.c
	src/thpool.c
	src/transform.c)

# git SHA1 hash
execute_process(COMMAND
  git describe --always --abbrev=40
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_SHA1
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

# by default set to older version for backward compatibility
#set(SYSREPO_LESS_0_7_5 ON CACHE BOOL "Sysrepo version older than 0.7.5 (< 0.7.5)")
#set(SYSREPO_LESS_0_7_7 ON CACHE BOOL "Sysrepo version older than 0.7.7 (< 0.7.7)")

# get sysrepo version
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--modversion" "sysrepo" OUTPUT_VARIABLE SYSREPO_VERSION)
    if(SYSREPO_VERSION)
        # strip new line from string
        string(STRIP ${SYSREPO_VERSION} SYSREPO_VERSION)
        if(${SYSREPO_VERSION} VERSION_LESS "1.0.0")
            message(FATAL_ERROR "${PROJECT_NAME} requires at least libsysrepo verision 1.0.0")
        endif()
    endif()
endif()

# generate version.h
configure_file("${PROJECT_SOURCE_DIR}/src/version.h.in" "${PROJECT_SOURCE_DIR}/src/version.h" ESCAPE_QUOTES @ONLY)

CONFIGURE_FILE("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_SOURCE_DIR}/src/config.h" ESCAPE_QUOTES @ONLY)

if (PLUGIN)
	add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
else()
	add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES PREFIX "")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")
find_package(SYSREPO REQUIRED)
find_package(LIBYANG REQUIRED)

# find pthreads
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})

# pthread
set(CMAKE_REQUIRED_LIBRARIES pthread)

target_link_libraries(
    ${PROJECT_NAME}
    ${SYSREPO_LIBRARIES}
    ${LIBYANG_LIBRARIES}
)

include_directories(
    ${SYSREPO_INCLUDE_DIRS}
    ${LIBYANG_INCLUDE_DIRS}
)

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

if (PLUGIN)
	install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION ${SR_PLUGINS_DIR})
else()
	install(TARGETS ${CMAKE_PROJECT_NAME} RUNTIME DESTINATION bin)

	# istall systemd service if it does not exist.
	if(NOT EXISTS "/lib/systemd/system/sysrepo-snabb-plugin.service")
		set(CMD "cp ${CMAKE_SOURCE_DIR}/systemd/sysrepo-snabb-plugin.service /lib/systemd/system/ && systemctl enable sysrepo-snabb-plugin")
		execute_process(COMMAND bash "-c" "${CMD}" OUTPUT_QUIET RESULT_VARIABLE ret)
		if (NOT ${ret} EQUAL 0)
			message(FATAL_ERROR "Error: ${ret}")
		else()
			message("-- Systemd service installed and enabled")
		endif()
	endif()
endif()

# install config file
install (FILES "./cfg_parse/config.ini" DESTINATION "/etc/sysrepo_snabb")
