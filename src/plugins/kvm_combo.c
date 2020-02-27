// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    vmw_combo.c
 *  @brief   Plugin for visualization of KVM exits.
 */

// C
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

// KernelShark
#include "plugins/kvm_combo.h"
#include "libkshark-plugin.h"

/** Plugin context instance. */
static struct plugin_kvm_context *
plugin_kvm_context_handler[KS_MAX_NUM_STREAMS] = {NULL};

/** Get the per stream context of the plugin. */
struct plugin_kvm_context *get_kvm_context(int sd)
{
	return plugin_kvm_context_handler[sd];
}

static bool plugin_kvm_init_context(struct kshark_data_stream *stream)
{
	struct plugin_kvm_context *plugin_ctx;

	if (stream->format != KS_TEP_DATA)
		return false;

	/* No context should exist when we initialize the plugin. */
	assert(plugin_kvm_context_handler[stream->stream_id] == NULL);

	plugin_ctx = calloc(1, sizeof(*plugin_ctx));
	if (!plugin_ctx) {
		fprintf(stderr,
			"Failed to allocate memory for plugin_sched_context.\n");
		return false;
	}

	plugin_ctx->vm_entry_id =
		stream->interface.find_event_id(stream, "kvm/kvm_entry");

	plugin_ctx->vm_exit_id =
		stream->interface.find_event_id(stream, "kvm/kvm_exit");

	if (plugin_ctx->vm_entry_id < 0 || plugin_ctx->vm_exit_id < 0)
		return false;

	plugin_ctx->vcpu_pids = kshark_hash_id_alloc(8);

	plugin_kvm_context_handler[stream->stream_id] = plugin_ctx;

	return true;
}

static void add_vcpu(struct kshark_data_stream *stream,
		     void *rec, struct kshark_entry *entry)
{
	struct plugin_kvm_context *plugin_ctx = get_kvm_context(entry->stream_id);
	int pid = kshark_get_pid(entry);

	kshark_hash_id_add(plugin_ctx->vcpu_pids, pid);
}

/** Load this plugin. */
int KSHARK_PLOT_PLUGIN_INITIALIZER(struct kshark_data_stream *stream)
{
	struct plugin_kvm_context *plugin_ctx;

	printf("--> KVM combos init %i \n", stream->stream_id);
	if (!plugin_kvm_init_context(stream))
		return 0;

	plugin_ctx = get_kvm_context(stream->stream_id);
	kshark_register_event_handler(stream,
				      plugin_ctx->vm_entry_id,
				      add_vcpu);

	kshark_register_draw_handler(stream, draw_kvm_combos);

	return 1;
}

/** Unload this plugin. */
int KSHARK_PLOT_PLUGIN_DEINITIALIZER(struct kshark_data_stream *stream)
{
	struct plugin_kvm_context *plugin_ctx;

	printf("<-- KVM combos close %i\n", stream->stream_id);
	plugin_ctx = plugin_kvm_context_handler[stream->stream_id];
	if (!plugin_ctx)
		return 0;

	kshark_unregister_event_handler(stream,
					plugin_ctx->vm_entry_id,
					add_vcpu);

	kshark_unregister_draw_handler(stream, draw_kvm_combos);

	kshark_hash_id_clear(plugin_ctx->vcpu_pids);
	kshark_hash_id_free(plugin_ctx->vcpu_pids);
	free(plugin_ctx);

	plugin_kvm_context_handler[stream->stream_id] = NULL;

	return 1;
}

void KSHARK_MENU_PLUGIN_INITIALIZER(void *gui_ptr)
{
	printf("--> KVM combos init menu\n");
	plugin_kvm_add_menu(gui_ptr);
}
