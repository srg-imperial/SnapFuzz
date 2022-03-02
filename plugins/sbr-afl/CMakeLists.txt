# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

include(ExternalProject)

list(APPEND SABRE_PLUGIN_C_FLAGS "-Wall" "-Werror" "-Wno-erro=unused-parameter"
     "-ftls-model=initial-exec")

option(SF_MEMFS "Enable Memory FS" ON)
if(SF_MEMFS)
  list(APPEND SABRE_COMPONENT_C_DEFINES "-DSF_MEMFS")
  list(APPEND SABRE_PLUGIN_C_DEFINES "-DSF_MEMFS")
endif()

option(SF_STDIO "Enable Virtual STDOUT/STRERR" ON)
if(SF_STDIO)
  list(APPEND SABRE_COMPONENT_C_DEFINES "-DSF_STDIO")
  list(APPEND SABRE_PLUGIN_C_DEFINES "-DSF_STDIO")
endif()

option(SF_SLEEP "Enable Virtual Sleeps" ON)
if(SF_SLEEP)
  list(APPEND SABRE_COMPONENT_C_DEFINES "-DSF_SLEEP")
  list(APPEND SABRE_PLUGIN_C_DEFINES "-DSF_SLEEP")
endif()

option(SF_SMARTDEFER "Enable Smart Defer" ON)
if(SF_SMARTDEFER)
  list(APPEND SABRE_COMPONENT_C_DEFINES "-DSF_SMARTDEFER")
  list(APPEND SABRE_PLUGIN_C_DEFINES "-DSF_SMARTDEFER")
endif()

add_library(libsqlfs STATIC libsqlfs/sqlfs.c)
set_property(TARGET libsqlfs PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(libsqlfs PUBLIC "-D_FILE_OFFSET_BITS=64"
                                           "-D_REENTRANT")

sabre_add_plugin(sbr-afl main.c)
add_dependencies(sbr-afl libsqlfs)
target_link_libraries(sbr-afl libsqlfs sqlite3 pthread)
