/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <ykaradzov@vmware.com>
 */

/**
 *  @file    vmw_combo.h
 *  @brief   Plugin for visualization of missed events due to overflow of the
 *	     ring buffer.
 */

#ifndef _KS_PLUGIN_VIRT_COMBO_H
#define _KS_PLUGIN_VIRT_COMBO_H

// KernelShark
#include "libkshark.h"
#include "libkshark-plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Structure representing a plugin-specific context. */
struct plugin_kvm_context {
	/** Input handle for the trace data file. */
	struct tracecmd_input	*handle;

	/** Page event used to parse the page. */
	struct tep_handle	*pevent;

	/** kvm_entry Id. */
	int vm_entry_id;

	/** kvm_exit Id. */
	int vm_exit_id;

	/** Hash table of the vCPU tasks. */
	struct kshark_hash_id	*vcpu_pids;
};

struct plugin_kvm_context *get_kvm_context(int sd);

void init_menu(void *ks_ptr);

void draw_kvm_combos(struct kshark_cpp_argv *argv,
		     int sd, int pid, int draw_action);

void plugin_kvm_add_menu(void *ks_ptr);

#ifdef __cplusplus
}
#endif

#endif
