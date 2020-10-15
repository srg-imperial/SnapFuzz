# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

list(APPEND SABRE_PLUGIN_C_FLAGS "-Wall" "-Werror" "-Wno-erro=unused-parameter")

sabre_add_plugin(sbr-afl
  main.c)

target_link_libraries(sbr-afl sqlfs-1.0)
