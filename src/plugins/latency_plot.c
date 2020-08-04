// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2020 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    latency_plot.c
 *  @brief
 */

// C
#ifndef _GNU_SOURCE
/** Use GNU C Library. */
#define _GNU_SOURCE
#endif // _GNU_SOURCE

#include <stdio.h>
#include <assert.h>

// KernelShark
#include "plugins/latency_plot.h"

/** Plugin context instance. */
static struct plugin_latency_context *
plugin_latency_context_handler[KS_MAX_NUM_STREAMS] = {NULL};

/** Get the per stream context of the plugin. */
struct plugin_latency_context *get_latency_context(int sd)
{
	return plugin_latency_context_handler[sd];
}

static void plugin_latency_free_context(int sd)
{
	struct plugin_latency_context *plugin_ctx = get_latency_context(sd);
	if (!plugin_ctx)
		return;

	free(plugin_ctx->event_name[0]);
	free(plugin_ctx->field_name[0]);

	free(plugin_ctx->event_name[1]);
	free(plugin_ctx->field_name[1]);

	if (plugin_ctx->data[0])
		kshark_free_data_container(plugin_ctx->data[0]);

	if (plugin_ctx->data[1])
		kshark_free_data_container(plugin_ctx->data[1]);

	plugin_latency_context_handler[sd] = NULL;
}

static struct plugin_latency_context *
plugin_latency_init_context(struct kshark_data_stream *stream)
{
	struct plugin_latency_context *plugin_ctx;
	int sd = stream->stream_id;

	/* No context should exist when we initialize the plugin. */
	assert(plugin_latency_context_handler[sd] == NULL);

	plugin_latency_context_handler[sd] = plugin_ctx =
		calloc(1, sizeof(*plugin_ctx));
	if (!plugin_ctx) {
		fprintf(stderr,
			"Failed to allocate memory for plugin event_field_plot.\n");
		return NULL;
	}

	plugin_set_event_fields(plugin_ctx);

	plugin_ctx->event_id[0] =
		stream->interface.find_event_id(stream, plugin_ctx->event_name[0]);
	if (plugin_ctx->event_id[0] < 0) {
		fprintf(stderr, "Event %s not found in stream %s:%s\n",
			plugin_ctx->event_name[0], stream->file, stream->name);
		goto fail;
	}

	plugin_ctx->event_id[1] =
		stream->interface.find_event_id(stream, plugin_ctx->event_name[1]);
	if (plugin_ctx->event_id[1] < 0) {
		fprintf(stderr, "Event %s not found in stream %s:%s\n",
			plugin_ctx->event_name[1], stream->file, stream->name);
		goto fail;
	}

	plugin_ctx->second_pass_done = false;
	plugin_ctx->max_latency = INT64_MIN;

	plugin_ctx->data[0] = kshark_init_data_container();
	plugin_ctx->data[1] = kshark_init_data_container();
	if (!plugin_ctx->data[0] || !plugin_ctx->data[1])
		goto fail;

	return plugin_ctx;

 fail:
	plugin_latency_free_context(sd);
	return NULL;
}

static void plugin_get_field(struct kshark_data_stream *stream, void *rec,
			     struct kshark_entry *entry,
			     char *field_name,
			     struct kshark_data_container *data)
{
	int64_t val;

	stream->interface.read_record_field_int64(stream, rec,
						  field_name,
						  &val);

	kshark_data_container_append(data, entry, val);
}

static void plugin_get_field_a(struct kshark_data_stream *stream, void *rec,
			       struct kshark_entry *entry)
{
	struct plugin_latency_context *plugin_ctx;

	plugin_ctx = get_latency_context(stream->stream_id);
	if (!plugin_ctx)
		return;

	plugin_get_field(stream, rec, entry,
			 plugin_ctx->field_name[0],
			 plugin_ctx->data[0]);
}

static void plugin_get_field_b(struct kshark_data_stream *stream, void *rec,
			       struct kshark_entry *entry)
{
	struct plugin_latency_context *plugin_ctx;

	plugin_ctx = get_latency_context(stream->stream_id);
	if (!plugin_ctx)
		return;

	plugin_get_field(stream, rec, entry,
			 plugin_ctx->field_name[1],
			 plugin_ctx->data[1]);
}

/** Load this plugin. */
int KSHARK_PLOT_PLUGIN_INITIALIZER(struct kshark_data_stream *stream)
{
	printf("--> latency_plot init %i\n", stream->stream_id);
	struct plugin_latency_context *plugin_ctx;

	plugin_ctx = plugin_latency_init_context(stream);
	if (!plugin_ctx)
		return 0;

	/* Register Event handler to be executed during data loading. */
	kshark_register_event_handler(stream,
				      plugin_ctx->event_id[0],
				      plugin_get_field_a);

	kshark_register_event_handler(stream,
				      plugin_ctx->event_id[1],
				      plugin_get_field_b);

	/* Register a drawing handler to plot on top of each Graph. */
	kshark_register_draw_handler(stream, draw_latency);

	return 1;
}

/** Unload this plugin. */
int KSHARK_PLOT_PLUGIN_DEINITIALIZER(struct kshark_data_stream *stream)
{
	printf("<-- latency_plot close %i\n", stream->stream_id);
	struct plugin_latency_context *plugin_ctx;
	int sd = stream->stream_id;

	plugin_ctx = get_latency_context(sd);
	if (!plugin_ctx)
		return 0;

	kshark_unregister_event_handler(stream,
					plugin_ctx->event_id[0],
					plugin_get_field_a);

	kshark_unregister_event_handler(stream,
					plugin_ctx->event_id[1],
					plugin_get_field_b);

	kshark_unregister_draw_handler(stream, draw_latency);

	plugin_latency_free_context(sd);

	return 1;
}

void *KSHARK_MENU_PLUGIN_INITIALIZER(void *gui_ptr)
{
	printf("--> latency_plot init menu\n");
	return plugin_latency_add_menu(gui_ptr);
}
