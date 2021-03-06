/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    libkshark-tepdata.h
 *  @brief   API for processing of FTRACE (trace-cmd) data.
 */

#ifndef _KSHARK_TEPDATA_H
#define _KSHARK_TEPDATA_H

// KernelShark
#include "libkshark.h"

#ifdef __cplusplus
extern "C" {
#endif

int kshark_tep_init_input(struct kshark_data_stream *stream,
			  const char *file);

int kshark_tep_init_local(struct kshark_data_stream *stream);

void kshark_tep_close_interface(struct kshark_data_stream *stream);

bool kshark_tep_filter_is_set(struct kshark_data_stream *stream);

int kshark_tep_add_filter_str(struct kshark_data_stream *stream,
			      const char *filter_str);

char *kshark_tep_filter_make_string(struct kshark_data_stream *stream,
				    int event_id);

int kshark_tep_filter_remove_event(struct kshark_data_stream *stream,
				   int event_id);

void kshark_tep_filter_reset(struct kshark_data_stream *stream);

char **kshark_tracecmd_local_plugins();

struct tep_handle;

/** Get the Page event object used to parse the page. */
struct tep_handle *kshark_get_tep(struct kshark_data_stream *stream);

struct tracecmd_input;

struct tracecmd_input *kshark_get_tep_input(struct kshark_data_stream *stream);

struct tep_record;

ssize_t kshark_load_tep_records(struct kshark_context *kshark_ctx, int sd,
				struct tep_record ***data_rows);

struct kshark_host_guest_map {
	/** ID of guest stream */
	int guest_id;

	/** ID of host stream */
	int host_id;

	/** Guest name */
	char *guest_name;

	/** Number of guest's CPUs in *cpu_pid array */
	int vcpu_count;

	/** Array of host task PIDs, index is the VCPU id */
	int *cpu_pid;
};

void kshark_tracecmd_free_hostguest_map(struct kshark_host_guest_map *map,
					int count);

int kshark_tracecmd_get_hostguest_mapping(struct kshark_host_guest_map **map);

char **kshark_tep_get_buffer_names(struct kshark_context *kshark_ctx, int sd,
				   int *n_buffers);

int kshark_tep_open_buffer(struct kshark_context *kshark_ctx, int sd,
			   const char *buffer_name);

int kshark_tep_init_all_buffers(struct kshark_context *kshark_ctx, int sd);

int kshark_tep_handle_plugins(struct kshark_context *kshark_ctx, int sd);

int kshark_tep_find_top_stream(struct kshark_context *kshark_ctx,
			       const char *file);

#ifdef __cplusplus
}
#endif

#endif // _KSHARK_TEPDATA_H
