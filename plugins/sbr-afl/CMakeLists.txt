# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

include(ExternalProject)

list(APPEND SABRE_PLUGIN_C_FLAGS "-Wall" "-Werror" "-Wno-erro=unused-parameter"
     "-ftls-model=initial-exec")

ExternalProject_Add(libsqlfs
    URL ${CMAKE_CURRENT_SOURCE_DIR}/libsqlfs
    BUILD_IN_SOURCE TRUE
    CONFIGURE_COMMAND ./autogen.sh COMMAND ./configure
    INSTALL_COMMAND ""
)
ExternalProject_Get_property(libsqlfs SOURCE_DIR)
set(LIBSQLFS_STATIC ${SOURCE_DIR}/.libs/libsqlfs-1.0.a)

sabre_add_plugin(sbr-afl main.c)
add_dependencies(sbr-afl libsqlfs)
target_link_libraries(sbr-afl ${LIBSQLFS_STATIC} sqlite3 pthread)
