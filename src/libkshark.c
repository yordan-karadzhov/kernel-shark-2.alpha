// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

 /**
 *  @file    libkshark.c
 *  @brief   API for processing of FTRACE (trace-cmd) data.
 */

/** Use GNU C Library. */
#define _GNU_SOURCE 1

// C
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

// KernelShark
#include "libkshark.h"
#include "libkshark-plugin.h"
#include "libkshark-input.h"
#include "libkshark-tepdata.h"

static struct kshark_context *kshark_context_handler = NULL;

static bool kshark_default_context(struct kshark_context **context)
{
	struct kshark_context *kshark_ctx;

	kshark_ctx = calloc(1, sizeof(*kshark_ctx));
	if (!kshark_ctx)
		return false;

	kshark_ctx->stream = calloc(KS_MAX_NUM_STREAMS,
				    sizeof(*kshark_ctx->stream));

	kshark_ctx->event_handlers = NULL;
	kshark_ctx->collections = NULL;
	kshark_ctx->plugins = NULL;
	kshark_ctx->inputs = NULL;

	kshark_ctx->filter_mask = 0x0;

	/* Will free kshark_context_handler. */
	kshark_free(NULL);

	/* Will do nothing if *context is NULL. */
	kshark_free(*context);

	*context = kshark_context_handler = kshark_ctx;

	return true;
}

/**
 * @brief Initialize a kshark session. This function must be called before
 *	  calling any other kshark function. If the session has been
 *	  initialized, this function can be used to obtain the session's
 *	  context.
 *
 * @param kshark_ctx: Optional input/output location for context pointer.
 *		      If it points to a context, that context will become
 *		      the new session. If it points to NULL, it will obtain
 *		      the current (or new) session. The result is only
 *		      valid on return of true.
 *
 * @returns True on success, or false on failure.
 */
bool kshark_instance(struct kshark_context **kshark_ctx)
{
	if (*kshark_ctx != NULL) {
		/* Will free kshark_context_handler */
		kshark_free(NULL);

		/* Use the context provided by the user. */
		kshark_context_handler = *kshark_ctx;
	} else {
		if (kshark_context_handler) {
			/*
			 * No context is provided by the user, but the context
			 * handler is already set. Use the context handler.
			 */
			*kshark_ctx = kshark_context_handler;
		} else {
			/* No kshark_context exists. Create a default one. */
			if (!kshark_default_context(kshark_ctx))
				return false;
		}
	}

	return true;
}

/**
 * @brief Open and prepare for reading a trace data file specified by "file".
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param file: The file to load.
 *
 * @returns The Id number of the data stream associated with this file on success.
 * 	    Otherwise a negative errno code.
 */
int kshark_open(struct kshark_context *kshark_ctx, const char *file)
{
	struct kshark_plugin_list *plugin;
	int sd, rt;

	sd = kshark_add_stream(kshark_ctx);
	if (sd < 0)
		return sd;

	rt = kshark_stream_open(kshark_ctx->stream[sd], file);
	if (rt < 0)
		return rt;

	kshark_ctx->n_streams++;

	for (plugin = kshark_ctx->plugins; plugin; plugin = plugin->next)
		kshark_plugin_add_stream(plugin, sd);

	kshark_handle_all_plugins(kshark_ctx, sd, KSHARK_PLUGIN_INIT);

	return sd;
}

static void kshark_stream_free(struct kshark_data_stream *stream)
{
	if (!stream)
		return;

	kshark_hash_id_free(stream->show_task_filter);
	kshark_hash_id_free(stream->hide_task_filter);

	kshark_hash_id_free(stream->show_event_filter);
	kshark_hash_id_free(stream->hide_event_filter);

	kshark_hash_id_free(stream->show_cpu_filter);
	kshark_hash_id_free(stream->hide_cpu_filter);

	kshark_hash_id_free(stream->tasks);

	free(stream->calib_array);
	free(stream->file);
	free(stream);
}

static struct kshark_data_stream *kshark_stream_alloc()
{
	struct kshark_data_stream *stream;

	stream = calloc(1, sizeof(*stream));
	if (!stream)
		goto fail;

	stream->show_task_filter = kshark_hash_id_alloc(KS_FILTER_HASH_NBITS);
	stream->hide_task_filter = kshark_hash_id_alloc(KS_FILTER_HASH_NBITS);

	stream->show_event_filter = kshark_hash_id_alloc(KS_FILTER_HASH_NBITS);
	stream->hide_event_filter = kshark_hash_id_alloc(KS_FILTER_HASH_NBITS);

	stream->show_cpu_filter = kshark_hash_id_alloc(KS_FILTER_HASH_NBITS);
	stream->hide_cpu_filter = kshark_hash_id_alloc(KS_FILTER_HASH_NBITS);

	stream->tasks = kshark_hash_id_alloc(KS_TASK_HASH_NBITS);

	if (!stream->show_task_filter ||
	    !stream->hide_task_filter ||
	    !stream->show_event_filter ||
	    !stream->hide_event_filter ||
	    !stream->tasks) {
		    goto fail;
	}

	stream->format = KS_INVALIDE_DATA;

	return stream;

 fail:
	fprintf(stderr, "Failed to allocate memory for data stream.\n");
	if (stream)
		kshark_stream_free(stream);

	return NULL;
}

/**
 * @brief Add new Trace data stream.
 *
 * @param kshark_ctx: Input location for context pointer.
 *
 * @returns Zero on success or a negative error code in the case of an errno.
 */
int kshark_add_stream(struct kshark_context *kshark_ctx)
{
	int sd;

	for (sd = 0; sd < KS_MAX_NUM_STREAMS; ++sd)
		if (!kshark_ctx->stream[sd])
			break;

	if (sd == KS_MAX_NUM_STREAMS)
		return -EMFILE;

	kshark_ctx->stream[sd] = kshark_stream_alloc();
	kshark_ctx->stream[sd]->stream_id = sd;

	return sd;
}

static bool is_tep(const char *filename)
{
	char *ext = strrchr(filename, '.');
	return ext && strcmp(ext, ".dat") == 0;
}

static void set_format(struct kshark_context *kshark_ctx,
		       struct kshark_data_stream *stream,
		       const char *filename)
{
	struct kshark_input_list *input;

	stream->format = KS_INVALIDE_DATA;

	if (is_tep(filename)) {
		stream->format = KS_TEP_DATA;
		return;
	}

	for (input = kshark_ctx->inputs; input; input = input->next) {
		stream->format = input->check_data(filename);
		if (stream->format != KS_INVALIDE_DATA) {
			input->format = stream->format;
			return;
		}
	}
}

/**
 * @brief Use an existing Trace data stream to open and prepare for reading
 *	  a trace data file specified by "file".
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param file: The file to load.
 *
 * @returns Zero on success or a negative error code in the case of an errno.
 */
int kshark_stream_open(struct kshark_data_stream *stream, const char *file)
{
	struct kshark_context *kshark_ctx = NULL;
	struct kshark_input_list *input;

	if (!stream || !kshark_instance(&kshark_ctx))
		return -EFAULT;

	if (pthread_mutex_init(&stream->input_mutex, NULL) != 0)
		return -EAGAIN;

	stream->file = strdup(file);
	set_format(kshark_ctx, stream, file);

	switch (stream->format) {
	case KS_TEP_DATA:
		return kshark_tep_init_input(stream, file);

	default:
		for (input = kshark_ctx->inputs; input; input = input->next) {
			if (stream->format == input->format)
				return input->init(stream);
		}

		return -ENODATA;
	}
}

/**
 * @brief Get an array containing the Ids of all opened Trace data streams.
 * 	  The User is responsible for freeing the array.
 *
 * @param kshark_ctx: Input location for context pointer.
 */
int *kshark_all_streams(struct kshark_context *kshark_ctx)
{
	int *ids, n, i, count = 0;

	n = kshark_ctx->n_streams;
	ids = malloc(n * (sizeof(*ids)));
	if (!ids) {
		fprintf(stderr,
			"Failed to allocate memory for stream array.\n");
		return NULL;
	}

	for (i = 0; i < KS_MAX_NUM_STREAMS; ++i)
		if (kshark_ctx->stream[i])
			ids[count++] = i;

	return ids;
}

static void kshark_stream_close(struct kshark_data_stream *stream)
{
	struct kshark_context *kshark_ctx = NULL;
	struct kshark_input_list *input;

	if (!stream || !kshark_instance(&kshark_ctx))
		return;

	/*
	 * All filters are file specific. Make sure that all Process Ids and
	 * Event Ids from this file are not going to be used with another file.
	 */
	kshark_hash_id_clear(stream->show_task_filter);
	kshark_hash_id_clear(stream->hide_task_filter);
	kshark_hash_id_clear(stream->show_event_filter);
	kshark_hash_id_clear(stream->hide_event_filter);
	kshark_hash_id_clear(stream->show_cpu_filter);
	kshark_hash_id_clear(stream->hide_cpu_filter);

	switch (stream->format) {
	case KS_TEP_DATA:
		kshark_tep_close_interface(stream);
		break;

	default:
		for (input = kshark_ctx->inputs; input; input = input->next) {
			if (stream->format == input->format)
				input->close(stream);
		}

		break;
	}

	pthread_mutex_destroy(&stream->input_mutex);
}

/**
 * @brief Close the trace data file and free the trace data handle.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param sd: Data stream identifier.
 */
void kshark_close(struct kshark_context *kshark_ctx, int sd)
{
	struct kshark_data_stream *stream =

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	/*
	 * All data collections are file specific. Make sure that collections
	 * from this file are not going to be used with another file.
	 */
	kshark_unregister_stream_collections(&kshark_ctx->collections, sd);

	/* Close all active plugins for this stream. */
	kshark_handle_all_plugins(kshark_ctx, sd, KSHARK_PLUGIN_CLOSE);

	kshark_stream_close(stream);
	kshark_stream_free(stream);
	kshark_ctx->stream[sd] = NULL;
	kshark_ctx->n_streams--;
}

/**
 * @brief Close all currently open trace data file and free the trace data handle.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 */
void kshark_close_all(struct kshark_context *kshark_ctx)
{
	int i, *stream_ids, n_streams;

	stream_ids = kshark_all_streams(kshark_ctx);

	/*
	 * Get a copy of shark_ctx->n_streams befor you start closing. Be aware
	 * that kshark_close() will decrement shark_ctx->n_streams.
	 */
	n_streams = kshark_ctx->n_streams;
	for (i = 0; i < n_streams; ++i)
		kshark_close(kshark_ctx, stream_ids[i]);

	free(stream_ids);
}

/**
 * @brief Deinitialize kshark session. Should be called after closing all
 *	  open trace data files and before your application terminates.
 *
 * @param kshark_ctx: Optional input location for session context pointer.
 *		      If it points to a context of a session, that session
 *		      will be deinitialize. If it points to NULL, it will
 *		      deinitialize the current session.
 */
void kshark_free(struct kshark_context *kshark_ctx)
{
	if (kshark_ctx == NULL) {
		if (kshark_context_handler == NULL)
			return;

		kshark_ctx = kshark_context_handler;
		/* kshark_ctx_handler will be set to NULL below. */
	}

	kshark_close_all(kshark_ctx);

	free(kshark_ctx->stream);

	if (kshark_ctx->plugins) {
		kshark_free_plugin_list(kshark_ctx->plugins);
		kshark_free_event_handler_list(kshark_ctx->event_handlers);
	}

	kshark_free_input_list(kshark_ctx->inputs);

	if (kshark_ctx == kshark_context_handler)
		kshark_context_handler = NULL;

	free(kshark_ctx);
}

/**
 * @brief Get an array containing the Process Ids of all tasks presented in
 *	  the loaded trace data file.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param sd: Data stream identifier.
 * @param pids: Output location for the Pids of the tasks. The user is
 *		responsible for freeing the elements of the outputted array.
 *
 * @returns The size of the outputted array of Pids in the case of success,
 *	    or a negative error code on failure.
 */
ssize_t kshark_get_task_pids(struct kshark_context *kshark_ctx, int sd,
			     int **pids)
{
	struct kshark_data_stream *stream;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return -EBADF;

	*pids = kshark_hash_ids(stream->tasks);
	return stream->tasks->count;
}

/**
 * @brief Get the name of the command/task from its Process Id.
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param pid: Process Id of the command/task.
 */
char *kshark_comm_from_pid(int sd, int pid)
{
	struct kshark_context *kshark_ctx = NULL;
	struct kshark_data_stream *stream;
	struct kshark_entry e;

	if (!kshark_instance(&kshark_ctx))
		return NULL;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return NULL;

	e.visible = KS_PLUGIN_UNTOUCHED_MASK;
	e.pid = pid;

	return stream->interface.get_task(stream, &e);
}

/**
 * @brief Get the name of the event from its Id.
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param event_id: The unique Id of the event type.
 */
char *kshark_event_from_id(int sd, int event_id)
{
	struct kshark_context *kshark_ctx = NULL;
	struct kshark_data_stream *stream;
	struct kshark_entry e;

	if (!kshark_instance(&kshark_ctx))
		return NULL;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return NULL;

	e.visible = KS_PLUGIN_UNTOUCHED_MASK;
	e.event_id = event_id;

	return stream->interface.get_event_name(stream, &e);
}

/**
 * @brief Convert the timestamp of the trace record (nanosecond precision) into
 *	  seconds and microseconds.
 *
 * @param time: Input location for the timestamp.
 * @param sec: Output location for the value of the seconds.
 * @param usec: Output location for the value of the microseconds.
 */
void kshark_convert_nano(uint64_t time, uint64_t *sec, uint64_t *usec)
{
	uint64_t s;

	*sec = s = time / 1000000000ULL;
	*usec = (time - s * 1000000000ULL) / 1000;
}

static bool filter_find(struct kshark_hash_id *filter, int pid,
			bool test)
{
	return !filter || !filter->count ||
	       kshark_hash_id_find(filter, pid) == test;
}

static bool kshark_show_task(struct kshark_data_stream *stream, int pid)
{
	return filter_find(stream->show_task_filter, pid, true) &&
	       filter_find(stream->hide_task_filter, pid, false);
}

static bool kshark_show_event(struct kshark_data_stream *stream, int pid)
{
	return filter_find(stream->show_event_filter, pid, true) &&
	       filter_find(stream->hide_event_filter, pid, false);
}

static bool kshark_show_cpu(struct kshark_data_stream *stream, int cpu)
{
	return filter_find(stream->show_cpu_filter, cpu, true) &&
	       filter_find(stream->hide_cpu_filter, cpu, false);
}

static struct kshark_hash_id *get_filter(struct kshark_context *kshark_ctx,
					 int sd,
					 enum kshark_filter_type filter_id)
{
	struct kshark_data_stream *stream;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return NULL;

	return kshark_get_filter(stream, filter_id);
}

/**
 * @brief Get an Id Filter.
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param filter_id: Identifier of the filter.
 */
struct kshark_hash_id *
kshark_get_filter(struct kshark_data_stream *stream,
		  enum kshark_filter_type filter_id)
{
	switch (filter_id) {
	case KS_SHOW_CPU_FILTER:
		return stream->show_cpu_filter;
	case KS_HIDE_CPU_FILTER:
		return stream->hide_cpu_filter;
	case KS_SHOW_EVENT_FILTER:
		return stream->show_event_filter;
	case KS_HIDE_EVENT_FILTER:
		return stream->hide_event_filter;
	case KS_SHOW_TASK_FILTER:
		return stream->show_task_filter;
	case KS_HIDE_TASK_FILTER:
		return stream->hide_task_filter;
	default:
		return NULL;
	}
}

/**
 * @brief Add an Id value to the filter specified by "filter_id".
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param sd: Data stream identifier.
 * @param filter_id: Identifier of the filter.
 * @param id: Id value to be added to the filter.
 */
void kshark_filter_add_id(struct kshark_context *kshark_ctx, int sd,
			  int filter_id, int id)
{
	struct kshark_hash_id *filter;

	filter = get_filter(kshark_ctx, sd, filter_id);
	if (filter)
		kshark_hash_id_add(filter, id);
}

/**
 * @brief Get an array containing all Ids associated with a given Id Filter.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param sd: Data stream identifier.
 * @param filter_id: Identifier of the filter.
 * @param n: Output location for the size of the returned array.
 *
 * @return The user is responsible for freeing the array.
 */
int *kshark_get_filter_ids(struct kshark_context *kshark_ctx, int sd,
			   int filter_id, int *n)
{
	struct kshark_hash_id *filter;

	filter = get_filter(kshark_ctx, sd, filter_id);
	if (filter) {
		if (n)
			*n = filter->count;

		return kshark_hash_ids(filter);
	}

	if (n)
		*n = 0;

	return NULL;
}

/**
 * @brief Clear (reset) the filter specified by "filter_id".
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param sd: Data stream identifier.
 * @param filter_id: Identifier of the filter.
 */
void kshark_filter_clear(struct kshark_context *kshark_ctx, int sd,
			 int filter_id)
{
	struct kshark_hash_id *filter;

	filter = get_filter(kshark_ctx, sd, filter_id);
	if (filter)
		kshark_hash_id_clear(filter);
}

static bool filter_is_set(struct kshark_hash_id *filter)
{
	return filter && filter->count;
}

/**
 * @brief Check if an Id filter is set.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param sd: Data stream identifier.
 *
 * @returns True if at least one Id filter of the stream is set, otherwise
 *	    False.
 */
bool kshark_filter_is_set(struct kshark_context *kshark_ctx, int sd)
{
	struct kshark_data_stream *stream;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return false;

	return filter_is_set(stream->show_task_filter) ||
	       filter_is_set(stream->hide_task_filter) ||
	       filter_is_set(stream->show_cpu_filter) ||
	       filter_is_set(stream->hide_cpu_filter) ||
	       filter_is_set(stream->show_event_filter) ||
	       filter_is_set(stream->hide_event_filter);
}

/**
 * @brief Apply filters to a given entry.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param stream: Input location for a Trace data stream pointer.
 * @param entry: Input location for entry.
 */
void kshark_apply_filters(struct kshark_context *kshark_ctx,
			  struct kshark_data_stream *stream,
			  struct kshark_entry *entry)
{
	/* Apply event filtering. */
	if (!kshark_show_event(stream, entry->event_id))
		unset_event_filter_flag(kshark_ctx, entry);

	/* Apply CPU filtering. */
	if (!kshark_show_cpu(stream, entry->cpu))
		entry->visible &= ~kshark_ctx->filter_mask;

	/* Apply task filtering. */
	if (!kshark_show_task(stream, entry->pid))
		entry->visible &= ~kshark_ctx->filter_mask;
}

static void filter_entries(struct kshark_context *kshark_ctx, int sd,
			   struct kshark_entry **data, size_t n_entries)
{
	struct kshark_data_stream *stream = NULL;
	size_t i;

	if (sd >= 0) {
		/* We will filter particular Data stream. */
		stream = kshark_get_data_stream(kshark_ctx, sd);
		if (!stream)
			return;

		if (stream->format == KS_TEP_DATA &&
		    kshark_tep_filter_is_set(stream)) {
			/* The advanced filter is set. */
			fprintf(stderr,
				"Failed to filter (sd = %i)!\n", sd);
			fprintf(stderr,
				"Reset the Advanced filter or reload the data.\n");

			return;
		}

		if (!kshark_filter_is_set(kshark_ctx, sd))
			return;
	}

	/* Apply only the Id filters. */
	for (i = 0; i < n_entries; ++i) {
		if (sd >= 0) {
			/*
			 * We only filter particular stream. Chack is the entry
			 * belongs to this stream.
			 */
			if (data[i]->stream_id != sd)
				continue;
		} else {
			/* We filter all streams. */
			stream = kshark_ctx->stream[data[i]->stream_id];
		}

		/* Start with and entry which is visible everywhere. */
		data[i]->visible = 0xFF;

		/* Apply Id filtering. */
		kshark_apply_filters(kshark_ctx, stream, data[i]);
	}
}

/**
 * @brief This function loops over the array of entries specified by "data"
 *	  and "n_entries" and sets the "visible" fields of each entry from a
 *	  given Data stream according to the criteria provided by the filters
 *	  of the session's context. The field "filter_mask" of the session's
 *	  context is used to control the level of visibility/invisibility of
 *	  the entries which are filtered-out.
 *	  WARNING: Do not use this function if the advanced filter is set.
 *	  Applying the advanced filter requires access to prevent_record,
 *	  hence the data has to be reloaded using kshark_load_data_entries().
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param sd: Data stream identifier.
 * @param data: Input location for the trace data to be filtered.
 * @param n_entries: The size of the inputted data.
 */
void kshark_filter_stream_entries(struct kshark_context *kshark_ctx,
				  int sd,
				  struct kshark_entry **data,
				  size_t n_entries)
{
	if (sd >= 0)
		filter_entries(kshark_ctx, sd, data, n_entries);
}

/**
 * @brief This function loops over the array of entries specified by "data"
 *	  and "n_entries" and sets the "visible" fields of each entry from
 *	  all Data stream according to the criteria provided by the filters
 *	  of the session's context. The field "filter_mask" of the session's
 *	  context is used to control the level of visibility/invisibility of
 *	  the entries which are filtered-out.
 *	  WARNING: Do not use this function if the advanced filter is set.
 *	  Applying the advanced filter requires access to prevent_record,
 *	  hence the data has to be reloaded using kshark_load_data_entries().
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param data: Input location for the trace data to be filtered.
 * @param n_entries: The size of the inputted data.
 */
void kshark_filter_all_entries(struct kshark_context *kshark_ctx,
			       struct kshark_entry **data, size_t n_entries)
{
	filter_entries(kshark_ctx, -1, data, n_entries);
}

/**
 * @brief This function loops over the array of entries specified by "data"
 *	  and "n_entries" and resets the "visible" fields of each entry to
 *	  the default value of "0xFF" (visible everywhere).
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param data: Input location for the trace data to be unfiltered.
 * @param n_entries: The size of the inputted data.
 */
void kshark_clear_all_filters(struct kshark_context *kshark_ctx,
			      struct kshark_entry **data,
			      size_t n_entries)
{
	int i;

	for (i = 0; i < n_entries; ++i)
		data[i]->visible = 0xFF;
}

/**
 * @brief Post-process the content of the entry. This includes time calibration
 *	  and all registered event-specific plugin actions.
 *
 * @param kshark_ctx: Input location for the session context pointer. If NULL,
 *		      no plugin actions are applied.
 * @param stream: Input location for a Trace data stream pointer.
 * @param record: Input location for the trace record.
 * @param entry: Output location for entry.
 */
void kshark_postprocess_entry(struct kshark_context *kshark_ctx,
			      struct kshark_data_stream *stream,
			      void *record, struct kshark_entry *entry)
{
	if (stream && stream->calib && stream->calib_array) {
		/* Calibrate the timestamp of the entry. */
		stream->calib(entry, stream->calib_array);
	}

	if (kshark_ctx &&  kshark_ctx->event_handlers) {
		/* Execute all plugin-provided actions for this event (if any). */
		struct kshark_event_handler *evt_handler = kshark_ctx->event_handlers;

		while ((evt_handler = kshark_find_event_handler(evt_handler,
								entry->event_id,
								entry->stream_id))) {
			evt_handler->event_func(kshark_ctx, record, entry);
			evt_handler = evt_handler->next;
			entry->visible &= ~KS_PLUGIN_UNTOUCHED_MASK;
		}
	}
}

/**
 * @brief Binary search inside a time-sorted array of kshark_entries.
 *
 * @param time: The value of time to search for.
 * @param data: Input location for the trace data.
 * @param l: Array index specifying the lower edge of the range to search in.
 * @param h: Array index specifying the upper edge of the range to search in.
 *
 * @returns On success, the first kshark_entry inside the range, having a
	    timestamp equal or bigger than "time".
	    If all entries inside the range have timestamps greater than "time"
	    the function returns BSEARCH_ALL_GREATER (negative value).
	    If all entries inside the range have timestamps smaller than "time"
	    the function returns BSEARCH_ALL_SMALLER (negative value).
 */
ssize_t kshark_find_entry_by_time(uint64_t time,
				 struct kshark_entry **data,
				 size_t l, size_t h)
{
	size_t mid;

	if (data[l]->ts > time)
		return BSEARCH_ALL_GREATER;

	if (data[h]->ts < time)
		return BSEARCH_ALL_SMALLER;

	/*
	 * After executing the BSEARCH macro, "l" will be the index of the last
	 * entry having timestamp < time and "h" will be the index of the first
	 * entry having timestamp >= time.
	 */
	BSEARCH(h, l, data[mid]->ts < time);
	return h;
}

/**
 * @brief Simple Pid matching function to be user for data requests.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param e: kshark_entry to be checked.
 * @param sd: Data stream identifier.
 * @param pid: Matching condition value.
 *
 * @returns True if the Pid of the entry matches the value of "pid".
 *	    Else false.
 */
bool kshark_match_pid(struct kshark_context *kshark_ctx,
		      struct kshark_entry *e, int sd, int *pid)
{
	if (e->stream_id == sd && e->pid == *pid)
		return true;

	return false;
}

/**
 * @brief Simple Cpu matching function to be user for data requests.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param e: kshark_entry to be checked.
 * @param sd: Data stream identifier.
 * @param cpu: Matching condition value.
 *
 * @returns True if the Cpu of the entry matches the value of "cpu".
 *	    Else false.
 */
bool kshark_match_cpu(struct kshark_context *kshark_ctx,
		      struct kshark_entry *e, int sd, int *cpu)
{
	if (e->stream_id == sd && e->cpu == *cpu)
		return true;

	return false;
}

/**
 * @brief Simple event Id matching function to be user for data requests.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param e: kshark_entry to be checked.
 * @param sd: Data stream identifier.
 * @param event_id: Matching condition value.
 *
 * @returns True if the event Id of the entry matches the value of "event_id".
 *	    Else false.
 */
bool kshark_match_event_id(struct kshark_context *kshark_ctx,
			   struct kshark_entry *e, int sd, int *event_id)
{
	return e->stream_id == sd && e->event_id == *event_id;
}

/**
 * @brief Simple event Id and PID matching function to be user for data requests.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param e: kshark_entry to be checked.
 * @param sd: Data stream identifier.
 * @param values: An array of matching condition value.
 *	  values[0] is the matches PID and values[1] is the matches event Id.
 *
 * @returns True if the event Id of the entry matches the values.
 *	    Else false.
 */
bool kshark_match_event_and_pid(struct kshark_context *kshark_ctx,
				struct kshark_entry *e,
				int sd, int *values)
{
	return e->stream_id == sd &&
	       e->pid == values[1] &&
	       e->event_id == values[0];
}

/**
 * @brief Create Data request. The request defines the properties of the
 *	  requested kshark_entry.
 *
 * @param first: Array index specifying the position inside the array from
 *		 where the search starts.
 * @param n: Number of array elements to search in.
 * @param cond: Matching condition function.
 * @param sd: Data stream identifier.
 * @param values: Matching condition values, used by the Matching condition
 *		  function.
 * @param vis_only: If true, a visible entry is requested.
 * @param vis_mask: If "vis_only" is true, use this mask to specify the level
 *		    of visibility of the requested entry.
 *
 * @returns Pointer to kshark_entry_request on success, or NULL on failure.
 *	    The user is responsible for freeing the returned
 *	    kshark_entry_request.
 */
struct kshark_entry_request *
kshark_entry_request_alloc(size_t first, size_t n,
			   matching_condition_func cond, int sd, int *values,
			   bool vis_only, int vis_mask)
{
	struct kshark_entry_request *req = malloc(sizeof(*req));

	if (!req) {
		fprintf(stderr,
			"Failed to allocate memory for entry request.\n");
		return NULL;
	}

	req->next = NULL;
	req->first = first;
	req->n = n;
	req->cond = cond;
	req->sd = sd;
	req->values = values;
	req->vis_only = vis_only;
	req->vis_mask = vis_mask;

	return req;
}

/**
 * @brief Free all Data requests in a given list.
 * @param req: Intput location for the Data request list.
 */
void kshark_free_entry_request(struct kshark_entry_request *req)
{
	struct kshark_entry_request *last;

	while (req) {
		last = req;
		req = req->next;
		free(last);
	}
}

/** Dummy entry, used to indicate the existence of filtered entries. */
const struct kshark_entry dummy_entry = {
	.next		= NULL,
	.visible	= 0x00,
	.cpu		= KS_FILTERED_BIN,
	.pid		= KS_FILTERED_BIN,
	.event_id	= -1,
	.offset		= 0,
	.ts		= 0
};

static const struct kshark_entry *
get_entry(const struct kshark_entry_request *req,
          struct kshark_entry **data,
          ssize_t *index, ssize_t start, ssize_t end, int inc)
{
	struct kshark_context *kshark_ctx = NULL;
	const struct kshark_entry *e = NULL;
	ssize_t i;

	if (index)
		*index = KS_EMPTY_BIN;

	if (!kshark_instance(&kshark_ctx))
		return e;

	/*
	 * We will do a sanity check in order to protect against infinite
	 * loops.
	 */
	assert((inc > 0 && start < end) || (inc < 0 && start > end));
	for (i = start; i != end; i += inc) {
		if (req->cond(kshark_ctx, data[i], req->sd, req->values)) {
			/*
			 * Data satisfying the condition has been found.
			 */
			if (req->vis_only &&
			    !(data[i]->visible & req->vis_mask)) {
				/* This data entry has been filtered. */
				e = &dummy_entry;
			} else {
				e = data[i];
				break;
			}
		}
	}

	if (index) {
		if (e)
			*index = (e->cpu != KS_FILTERED_BIN)? i : KS_FILTERED_BIN;
		else
			*index = KS_EMPTY_BIN;
	}

	return e;
}

/**
 * @brief Search for an entry satisfying the requirements of a given Data
 *	  request. Start from the position provided by the request and go
 *	  searching in the direction of the increasing timestamps (front).
 *
 * @param req: Input location for Data request.
 * @param data: Input location for the trace data.
 * @param index: Optional output location for the index of the returned
 *		 entry inside the array.
 *
 * @returns Pointer to the first entry satisfying the matching conditionon
 *	    success, or NULL on failure.
 *	    In the special case when some entries, satisfying the Matching
 *	    condition function have been found, but all these entries have
 *	    been discarded because of the visibility criteria (filtered
 *	    entries), the function returns a pointer to a special
 *	    "Dummy entry".
 */
const struct kshark_entry *
kshark_get_entry_front(const struct kshark_entry_request *req,
                       struct kshark_entry **data,
                       ssize_t *index)
{
	ssize_t end = req->first + req->n;

	return get_entry(req, data, index, req->first, end, +1);
}

/**
 * @brief Search for an entry satisfying the requirements of a given Data
 *	  request. Start from the position provided by the request and go
 *	  searching in the direction of the decreasing timestamps (back).
 *
 * @param req: Input location for Data request.
 * @param data: Input location for the trace data.
 * @param index: Optional output location for the index of the returned
 *		 entry inside the array.
 *
 * @returns Pointer to the first entry satisfying the matching conditionon
 *	    success, or NULL on failure.
 *	    In the special case when some entries, satisfying the Matching
 *	    condition function have been found, but all these entries have
 *	    been discarded because of the visibility criteria (filtered
 *	    entries), the function returns a pointer to a special
 *	    "Dummy entry".
 */
const struct kshark_entry *
kshark_get_entry_back(const struct kshark_entry_request *req,
                      struct kshark_entry **data,
                      ssize_t *index)
{
	ssize_t end = req->first - req->n;

	if (end < 0)
		end = -1;

	return get_entry(req, data, index, req->first, end, -1);
}

/**
 * Add constant offset to the timestamp of the entry. To be used by the sream
 * object as a System clock calibration callback function.
 */
void kshark_offset_calib(struct kshark_entry *e, int64_t *argv)
{
	e->ts += argv[0];
}

static size_t copy_prior_data(struct kshark_entry **merged_data,
			      struct kshark_entry **prior_data,
			      size_t a_size,
			      uint64_t t)
{
	size_t mid, l = 0, h = a_size - 1;

	/*
	 * After executing the BSEARCH macro, "l" will be the index of the last
	 * prior entry having timestamp < t  and "h" will be the index of the
	 * first prior entry having timestamp >= t.
	 */
	BSEARCH(h, l, prior_data[mid]->ts < t);

	/*
	 * Copy all entries before "t" (in time).
	 */
	memcpy(merged_data, prior_data, h * sizeof(*prior_data));

	return h;
}

/**
 * @brief Merge two trace data streams.
 *
 * @param data_a: Input location for the prior trace data.
 * @param a_size: The size of the prior trace data.
 * @param data_b: Input location for the trace data to be merged to
 *			   the prior.
 * @param b_size: The size of the associated trace data.
 *
 * @returns Merged and sorted in time trace data. The user is responsible for
 *	    freeing the elements of the outputted array.
 */
struct kshark_entry **kshark_data_merge(struct kshark_entry **data_a,
					size_t a_size,
					struct kshark_entry **data_b,
					size_t b_size)
{
	size_t i = 0, a_count = 0, b_count = 0;
	size_t tot = a_size + b_size, cpy_size;
	struct kshark_entry **merged_data;

	merged_data = calloc(tot, sizeof(*merged_data));
	if (data_a[0]->ts < data_b[0]->ts) {
		i = a_count = copy_prior_data(merged_data, data_a,
					      a_size, data_b[0]->ts);
	} else {
		i = b_count = copy_prior_data(merged_data, data_b,
					      b_size, data_a[0]->ts);
	}

	for (; i < tot; ++i) {
		if (data_a[a_count]->ts <= data_b[b_count]->ts) {
			merged_data[i] = data_a[a_count++];
			if (a_count == a_size)
				break;
		} else {
			merged_data[i] = data_b[b_count++];
			if (b_count == b_size)
				break;
		}
	}

	/* Copy the remaining data. */
	++i;
	cpy_size = (tot - i) * sizeof(*merged_data);

	if (a_count == a_size && b_count < b_size)
		memcpy(&merged_data[i], &data_b[b_count], cpy_size);
	else if (a_count < a_size && b_count == b_size)
		memcpy(&merged_data[i], &data_a[a_count], cpy_size);

	return merged_data;
}

static int compare_time(const void* a, const void* b)
{
	const struct kshark_entry *entry_a, *entry_b;

	entry_a = *(const struct kshark_entry **) a;
	entry_b = *(const struct kshark_entry **) b;

	if (entry_a->ts > entry_b->ts)
		return 1;

	if (entry_a->ts < entry_b->ts)
		return -1;

	return 0;
}

static void kshark_data_qsort(struct kshark_entry **entries, size_t size)
{
	qsort(entries, size, sizeof(struct kshark_entry *), compare_time);
}

/**
 * @brief Apply constant offset to the timestamps of all entries from a given
 *	  Data stream.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param entries: Input location for the trace data.
 * @param size: The size of the trace data.
 * @param sd: Data stream identifier.
 * @param offset: The constant offset to be added (in nanosecond).
 */
void kshark_set_clock_offset(struct kshark_context *kshark_ctx,
			     struct kshark_entry **entries, size_t size,
			     int sd, int64_t offset)
{
	struct kshark_data_stream *stream;
	uint64_t correction;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	if (!stream->calib_array) {
		stream->calib_array = malloc(sizeof(*stream->calib_array));
		stream->calib_array_size = 1;
	}

	correction = offset - stream->calib_array[0];
	stream->calib_array[0] = offset;

	for (size_t i = 0; i < size; ++i)
		if (entries[i]->stream_id == sd)
			entries[i]->ts += correction;

	kshark_data_qsort(entries, size);
}

/**
 * @brief Load the content of the all opened data file into an array of
 *	  kshark_entries.
 *	  If one or more filters are set, the "visible" fields of each entry
 *	  is updated according to the criteria provided by the filters. The
 *	  field "filter_mask" of the session's context is used to control the
 *	  level of visibility/invisibility of the filtered entries.
 *
 * @param kshark_ctx: Input location for context pointer.
 * @param data_rows: Output location for the trace data. The user is
 *		     responsible for freeing the elements of the outputted
 *		     array.
 *
 * @returns The size of the outputted data in the case of success, or a
 *	    negative error code on failure.
 */
ssize_t kshark_load_all_entries(struct kshark_context *kshark_ctx,
				struct kshark_entry ***data_rows)
{
	size_t data_size = 0;
	int i, *stream_ids, sd;

	if (!kshark_ctx->n_streams)
		return data_size;

	stream_ids = kshark_all_streams(kshark_ctx);
	sd = stream_ids[0];

	data_size = kshark_load_entries(kshark_ctx, sd, data_rows);

	for (i = 1; i < kshark_ctx->n_streams; ++i) {
		struct kshark_entry **stream_data_rows = NULL;
		struct kshark_entry **merged_data_rows;
		size_t stream_data_size;

		sd = stream_ids[i];
		stream_data_size = kshark_load_entries(kshark_ctx, sd,
						       &stream_data_rows);

		merged_data_rows =
			kshark_data_merge(*data_rows, data_size,
					  stream_data_rows, stream_data_size);

		free(stream_data_rows);
		free(*data_rows);

		stream_data_rows = *data_rows = NULL;

		*data_rows = merged_data_rows;
		data_size += stream_data_size;
	}

	free(stream_ids);

	return data_size;
}

static inline void free_ptr(void *ptr)
{
	if (ptr)
		free(*(void **)ptr);
}

bool data_matrix_alloc(size_t n_rows, int16_t **cpu_array,
				      int32_t **pid_array,
				      int32_t **event_array,
				      int64_t **offset_array,
				      uint64_t **ts_array)
{
	if (offset_array) {
		*offset_array = calloc(n_rows, sizeof(**offset_array));
		if (!*offset_array)
			return false;
	}

	if (cpu_array) {
		*cpu_array = calloc(n_rows, sizeof(**cpu_array));
		if (!*cpu_array)
			goto free_offset;
	}

	if (ts_array) {
		*ts_array = calloc(n_rows, sizeof(**ts_array));
		if (!*ts_array)
			goto free_cpu;
	}

	if (pid_array) {
		*pid_array = calloc(n_rows, sizeof(**pid_array));
		if (!*pid_array)
			goto free_ts;
	}

	if (event_array) {
		*event_array = calloc(n_rows, sizeof(**event_array));
		if (!*event_array)
			goto free_pid;
	}

	return true;

 free_pid:
	free_ptr(pid_array);
 free_ts:
	free_ptr(ts_array);
 free_cpu:
	free_ptr(cpu_array);
 free_offset:
	free_ptr(offset_array);

	fprintf(stderr, "Failed to allocate memory during data loading.\n");
	return false;
}
