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
#include "libkshark-tepdata.h"

/** Plugin context instance. */
static struct plugin_kvm_context *
plugin_kvm_context_handler[KS_MAX_NUM_STREAMS] = {NULL};

/** Get the per stream context of the plugin. */
struct plugin_kvm_context *get_kvm_context(int sd)
{
	return plugin_kvm_context_handler[sd];
}

static bool plugin_kvm_init_context(struct kshark_context *kshark_ctx,
				    int sd)
{
	struct plugin_kvm_context *plugin_ctx;
	struct kshark_data_stream *stream;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream || stream->format != KS_TEP_DATA)
		return false;

	/* No context should exist when we initialize the plugin. */
	assert(plugin_kvm_context_handler[sd] == NULL);

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

	plugin_kvm_context_handler[sd] = plugin_ctx;

	return true;
}

static void nop_action(struct kshark_context *kshark_ctx, void *rec,
		       struct kshark_entry *entry)
{}

/** Load this plugin. */
int KSHARK_PLUGIN_INITIALIZER(struct kshark_context *kshark_ctx, int sd)
{
	printf("--> KVM combos init %i \n", sd);
	if (!plugin_kvm_init_context(kshark_ctx, sd))
		return 0;

	kshark_register_event_handler(&kshark_ctx->event_handlers,
				      -1,
				      sd,
				      nop_action,
				      draw_kvm_combos);

	return 1;
}

/** Unload this plugin. */
int KSHARK_PLUGIN_DEINITIALIZER(struct kshark_context *kshark_ctx, int sd)
{
	printf("<-- KVM combos close %i\n", sd);
	kshark_unregister_event_handler(&kshark_ctx->event_handlers,
					-1,
					sd,
					nop_action,
					draw_kvm_combos);

	free(plugin_kvm_context_handler[sd]);
	plugin_kvm_context_handler[sd] = NULL;

	return 1;
}
