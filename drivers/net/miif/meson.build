# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2019 Cisco Systems, Inc.  All rights reserved.

if not is_linux
	build = false
	reason = 'only supported on Linux'
endif

mishmem_dep = cc.find_library('libmishmem', required: false)
if not mishmem_dep.found() or not cc.has_header('mi_shmem_api.h')
	build = false
	reason = 'missing dependency, "mi-shmem"'
else
	ext_deps += mishmem_dep
endif

ocxl_dep = cc.find_library('libocxl', required: false)
if not ocxl_dep.found() or not cc.has_header('libocxl.h')
	build = false
	reason = 'missing dependency, "libocxl"'
else
	ext_deps += ocxl_dep
endif

sources = files('rte_eth_miif.c',
		'miif_socket.c')

allow_experimental_apis = true
# Experimantal APIs:
# - rte_intr_callback_unregister_pending
# - rte_mp_action_register
# - rte_mp_reply
# - rte_mp_request_sync

deps += ['hash']
