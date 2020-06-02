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

static void plugin_kvm_free_context(int sd)
{
	struct plugin_kvm_context *plugin_ctx = get_kvm_context(sd);
	if (!plugin_ctx)
		return;

	free(plugin_ctx);
	plugin_kvm_context_handler[sd] = NULL;
}

static struct plugin_kvm_context *
plugin_kvm_init_context(struct kshark_data_stream *stream)
{
	struct plugin_kvm_context *plugin_ctx;
	int sd = stream->stream_id;

	if (stream->format != KS_TEP_DATA)
		return NULL;

	/* No context should exist when we initialize the plugin. */
	assert(plugin_kvm_context_handler[sd] == NULL);

	plugin_kvm_context_handler[sd] = plugin_ctx =
		calloc(1, sizeof(*plugin_ctx));
	if (!plugin_ctx) {
		fprintf(stderr,
			"Failed to allocate memory for plugin_sched_context.\n");
		return NULL;
	}

	plugin_ctx->vm_entry_id =
		stream->interface.find_event_id(stream, "kvm/kvm_entry");

	plugin_ctx->vm_exit_id =
		stream->interface.find_event_id(stream, "kvm/kvm_exit");

	if (plugin_ctx->vm_entry_id < 0 || plugin_ctx->vm_exit_id < 0) {
		plugin_kvm_free_context(sd);
		return NULL;
	}

	return plugin_ctx;
}

/** Load this plugin. */
int KSHARK_PLOT_PLUGIN_INITIALIZER(struct kshark_data_stream *stream)
{
	printf("--> KVM combos init %i \n", stream->stream_id);
	struct plugin_kvm_context *plugin_ctx = plugin_kvm_init_context(stream);
	if (!plugin_ctx)
		return 0;

	kshark_register_draw_handler(stream, draw_kvm_combos);

	return 1;
}

/** Unload this plugin. */
int KSHARK_PLOT_PLUGIN_DEINITIALIZER(struct kshark_data_stream *stream)
{
	struct plugin_kvm_context *plugin_ctx;
	int sd = stream->stream_id;

	printf("<-- KVM combos close %i\n", sd);
	plugin_ctx = plugin_kvm_context_handler[sd];
	if (!plugin_ctx)
		return 0;

	kshark_unregister_draw_handler(stream, draw_kvm_combos);

	plugin_kvm_free_context(sd);

	return 1;
}

void *KSHARK_MENU_PLUGIN_INITIALIZER(void *gui_ptr)
{
	printf("--> KVM combos init menu\n");
	return plugin_kvm_add_menu(gui_ptr);
}
