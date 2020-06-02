/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    rename_sched_events.c
 *  @brief   A plugin to deal with renamed threads.
 */

#ifndef _KS_PLUGIN_SHED_RENAME_H
#define _KS_PLUGIN_SHED_RENAME_H

// KernelShark
#include "libkshark.h"
#include "libkshark-model.h"

/** Structure representing a plugin-specific context. */
struct plugin_sched_context {
	/** Input handle for the trace data file. */
	struct tracecmd_input	*handle;

	/** Page event used to parse the page. */
	struct tep_handle	*pevent;

	/** Pointer to the sched_switch_event object. */
	struct tep_event	*sched_switch_event;

	/** Pointer to the sched_switch_next_field format descriptor. */
	struct tep_format_field	*sched_switch_next_field;

	/** Pointer to the sched_switch_comm_field format descriptor. */
	struct tep_format_field	*sched_switch_comm_field;

	/** True if the job is done. */
	bool done;
};

/** Plugin context instance. */
static struct plugin_sched_context *plugin_sched_context_handler = NULL;

static bool plugin_sched_update_context(struct kshark_context *kshark_ctx)
{
	struct plugin_sched_context *plugin_ctx;
	struct tep_event *event;

	if (!plugin_sched_context_handler) {
		plugin_sched_context_handler =
			malloc(sizeof(*plugin_sched_context_handler));
	}

	plugin_ctx = plugin_sched_context_handler;
	plugin_ctx->handle = kshark_ctx->handle;
	plugin_ctx->pevent = kshark_ctx->pevent;

	event = tep_find_event_by_name(plugin_ctx->pevent,
				       "sched", "sched_switch");
	if (!event)
		return false;

	plugin_ctx->sched_switch_event = event;
	plugin_ctx->sched_switch_next_field =
		tep_find_any_field(event, "next_pid");

	plugin_ctx->sched_switch_comm_field =
		tep_find_field(event, "next_comm");

	plugin_ctx->done = false;

	return true;
}

static void plugin_nop(struct kshark_context *kshark_ctx,
		       struct tep_record *rec,
		       struct kshark_entry *entry)
{}

static int plugin_get_next_pid(struct tep_record *record)
{
	unsigned long long val;
	struct plugin_sched_context *plugin_ctx =
		plugin_sched_context_handler;

	tep_read_number_field(plugin_ctx->sched_switch_next_field,
			      record->data, &val);
	return val;
}

static bool plugin_sched_switch_match_pid(struct kshark_context *kshark_ctx,
					  struct kshark_entry *e,
					  int pid)
{
	struct plugin_sched_context *plugin_ctx =
		plugin_sched_context_handler;
	struct tep_record *record = NULL;
	int switch_pid;

	if (plugin_ctx->sched_switch_event &&
	    e->event_id == plugin_ctx->sched_switch_event->id) {
		record = tracecmd_read_at(kshark_ctx->handle, e->offset, NULL);

		switch_pid = plugin_get_next_pid(record);
		free(record);

		if (switch_pid == pid)
			return true;
	}

	return false;
}

static void plugin_rename(struct kshark_cpp_argv *argv,
			  int pid, int draw_action)
{
	struct plugin_sched_context *plugin_ctx =
		plugin_sched_context_handler;
	struct kshark_context *kshark_ctx;
	const struct kshark_entry *entry;
	struct kshark_entry_request req;
	struct tep_record *record;
	int *pids, n_tasks, r;
	const char *comm;
	ssize_t index;

	if (plugin_ctx->done)
		return;

	req.first = argv->histo->data_size - 1;
	req.n = argv->histo->data_size;
	req.cond = plugin_sched_switch_match_pid;
	req.vis_only = false;

	kshark_ctx = NULL;
	kshark_instance(&kshark_ctx);
	n_tasks = kshark_get_task_pids(kshark_ctx, &pids);
	for (r = 0; r < n_tasks; ++r) {
		req.val = pids[r];
		entry = kshark_get_entry_back(&req, argv->histo->data, &index);
		if (!entry)
			continue;

		record = tracecmd_read_at(kshark_ctx->handle, entry->offset, NULL);
		comm = record->data +
			       plugin_ctx->sched_switch_comm_field->offset;

		printf("%li task: %s  pid: %i\n", index, comm, pids[r]);
	}

	plugin_ctx->done = true;

	free(pids);
}


static int plugin_rename_sched_init(struct kshark_context *kshark_ctx)
{
	struct plugin_sched_context *plugin_ctx;

	if (!plugin_sched_update_context(kshark_ctx)) {
		free(plugin_sched_context_handler);
		plugin_sched_context_handler = NULL;
		return 0;
	}

	plugin_ctx = plugin_sched_context_handler;
	kshark_register_event_handler(&kshark_ctx->event_handlers,
				      plugin_ctx->sched_switch_event->id,
				      plugin_nop,
				      plugin_rename);

	return 1;
}

static int plugin_rename_sched_close(struct kshark_context *kshark_ctx)
{
	struct plugin_sched_context *plugin_ctx;

	if (!plugin_sched_context_handler)
		return 0;

	plugin_ctx = plugin_sched_context_handler;

	kshark_unregister_event_handler(&kshark_ctx->event_handlers,
					plugin_ctx->sched_switch_event->id,
					plugin_nop,
					plugin_rename);

	free(plugin_ctx);
	plugin_sched_context_handler = NULL;

	return 1;
}

/** Load this plugin. */
int KSHARK_PLUGIN_INITIALIZER(struct kshark_context *kshark_ctx)
{
	return plugin_rename_sched_init(kshark_ctx);
}

/** Unload this plugin. */
int KSHARK_PLUGIN_DEINITIALIZER(struct kshark_context *kshark_ctx)
{
	return plugin_rename_sched_close(kshark_ctx);
}

#endif
