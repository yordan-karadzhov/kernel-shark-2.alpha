// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2018 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

/**
 *  @file    SchedEvents.cpp
 *  @brief   Defines a callback function for Sched events used to plot in green
 *	     the wake up latency of the task and in red the time the task was
 *	     preempted by another task.
 */

// C++
#include<iostream>

// C++ 11
#include<functional>
#include<unordered_set>

// KernelShark
#include "libkshark.h"
#include "plugins/sched_events.h"
#include "KsPlotTools.hpp"
#include "KsPlugins.hpp"

//! @cond Doxygen_Suppress

#define PLUGIN_MIN_BOX_SIZE 4

#define KS_TASK_COLLECTION_MARGIN 25

//! @endcond

/** Sched Event identifier. */
enum class SchedEvent {
	/** Sched Switch Event. */
	Switch,

	/** Sched Wakeup Event. */
	Wakeup,
};

static void pluginDraw(kshark_context *kshark_ctx,
		       kshark_trace_histo *histo,
		       kshark_entry_collection *col,
		       SchedEvent e,
		       int sd, int pid,
		       KsPlot::Graph *graph,
		       KsPlot::PlotObjList *shapes)
{
	const kshark_entry *entryClose, *entryOpen, *entryME;
	ssize_t indexClose(0), indexOpen(0), indexME(0);
	std::function<void(int)> ifSchedBack;
	KsPlot::Rectangle *rec = nullptr;
	int height = graph->height() * .3;

	auto openBox = [&] (const KsPlot::Point &p)
	{
		/*
		 * First check if we already have an open box. If we don't
		 * have, open a new one.
		 */
		if (!rec)
			rec = new KsPlot::Rectangle;

		if (e == SchedEvent::Switch) {
			/* Red box. */
			rec->_color = KsPlot::Color(255, 0, 0);
		} else {
			/* Green box. */
			rec->_color = KsPlot::Color(0, 255, 0);
		}

		rec->setFill(false);

		rec->setPoint(0, p.x() - 1, p.y() - height);
		rec->setPoint(1, p.x() - 1, p.y() - 1);
	};

	auto closeBox = [&] (const KsPlot::Point &p)
	{
		if (rec == nullptr)
			return;

		int boxSize = p.x() - rec->getPoint(0)->x;
		if (boxSize < PLUGIN_MIN_BOX_SIZE) {
			/* This box is too small. Don't try to plot it. */
			delete rec;
			rec = nullptr;
			return;
		}

		rec->setPoint(3, p.x() - 1, p.y() - height);
		rec->setPoint(2, p.x() - 1, p.y() - 1);

		shapes->push_front(rec);
		rec = nullptr;
	};

	for (int bin = 0; bin < graph->size(); ++bin) {
		/*
		 * Starting from the first element in this bin, go forward
		 * in time until you find a trace entry that satisfies the
		 * condition defined by kshark_match_pid.
		 */
		entryClose = ksmodel_get_entry_back(histo, bin, false,
						    plugin_switch_match_entry_pid,
						    sd, &pid, col, &indexClose);

		entryME = ksmodel_get_task_missed_events(histo,
							 bin,
							 sd, pid,
							 col,
							 &indexME);

		if (e == SchedEvent::Switch) {
			/*
			 * Starting from the last element in this bin, go backward
			 * in time until you find a trace entry that satisfies the
			 * condition defined by plugin_switch_match_rec_pid.
			 */
			entryOpen =
				ksmodel_get_entry_back(histo, bin, false,
						       plugin_switch_match_rec_pid,
						       sd, &pid, col, &indexOpen);

		} else {
			/*
			 * Starting from the last element in this bin, go backward
			 * in time until you find a trace entry that satisfies the
			 * condition defined by plugin_wakeup_match_rec_pid.
			 */
			entryOpen =
				ksmodel_get_entry_back(histo, bin, false,
						       plugin_wakeup_match_rec_pid,
						       sd, &pid,
						       col,
						       &indexOpen);

			if (entryOpen) {
				int cpu = ksmodel_get_cpu_back(histo, bin,
								      sd, pid,
								      false,
								      col,
								      nullptr);
				if (cpu >= 0) {
					/*
					 * The task is already running. Ignore
					 * this wakeup event.
					 */
					entryOpen = nullptr;
				}
			}
		}

		if (rec) {
			if (entryME || entryClose) {
				/* Close the box in this bin. */
				closeBox(graph->getBin(bin)._base);
				if (entryOpen &&
				    indexME < indexOpen &&
				    indexClose < indexOpen) {
					/*
					 * We have a Sched switch entry that
					 * comes after (in time) the closure of
					 * the previous box. We have to open a
					 * new box in this bin.
					 */
					openBox(graph->getBin(bin)._base);
				}
			}
		} else {
			if (entryOpen &&
			    (!entryClose || indexClose < indexOpen)) {
				/* Open a new box in this bin. */
				openBox(graph->getBin(bin)._base);
			}
		}
	}

	if (rec)
		delete rec;

	return;
}

/*
 * Ideally, the sched_switch has to be the last trace event recorded before the
 * task is preempted. Because of this, when the data is loaded (the first pass),
 * the "pid" field of the sched_switch entries gets edited by this plugin to be
 * equal to the "next pid" of the sched_switch event. However, in reality the
 * sched_switch event may be followed by some trailing events from the same task
 * (printk events for example). This has the effect of extending the graph of
 * the task outside of the actual duration of the task. The "second pass" over
 * the data is used to fix this problem. It takes advantage of the "next" field
 * of the entry (this field is set during the first pass) to search for trailing
 * events after the "sched_switch".
 */
static void secondPass(kshark_entry **data,
		       kshark_entry_collection *col,
		       int sd, int pid)
{
	if (!col)
		return;

	const kshark_entry *e;
	kshark_entry *last;
	int first, n;
	ssize_t index;

	/* Loop over the intervals of the data collection. */
	for (size_t i = 0; i < col->size; ++i) {
		first = col->break_points[i];
		n = first - col->resume_points[i];

		kshark_entry_request *req =
			kshark_entry_request_alloc(first, n,
						   plugin_switch_match_rec_pid,
						   sd, &pid,
						   false,
						   KS_GRAPH_VIEW_FILTER_MASK);

		e = kshark_get_entry_back(req, data, &index);
		free(req);

		if (!e || index < 0) {
			/* No sched_switch event in this interval. */
			continue;
		}

		/* Find the very last trailing event. */
		for (last = data[index]; last->next; last = last->next) {
			if (last->next->pid != pid) {
				/*
				 * This is the last trailing event. Change the
				 * "pid" to be equal to the "next pid" of the
				 * sched_switch event and leave a sign that you
				 * edited this entry.
				 */
				last->pid = data[index]->pid;
				last->visible &= ~KS_PLUGIN_UNTOUCHED_MASK;
				break;
			}
		}
	}
}

/**
 * @brief Plugin's draw function.
 *
 * @param argv_c: A C pointer to be converted to KsCppArgV (C++ struct).
 * @param sd: Data stream identifier.
 * @param pid: Process Id.
 * @param draw_action: Draw action identifier.
 */
void plugin_draw(kshark_cpp_argv *argv_c, int sd, int pid, int draw_action)
{
	kshark_entry_collection *col, **collections_ptr;
	kshark_hash_id *second_pass_hash;
	kshark_context *kshark_ctx(NULL);

	if (draw_action != KSHARK_PLUGIN_TASK_DRAW || pid == 0)
		return;

	second_pass_hash = get_second_pass_hash(sd);
	collections_ptr = get_collections_ptr(sd);
	if (!kshark_instance(&kshark_ctx) ||
	    !second_pass_hash)
		return;

	KsCppArgV *argvCpp = KS_ARGV_TO_CPP(argv_c);

	/*
	 * Try to find a collections for this task. It is OK if
	 * coll = NULL.
	 */
	col = kshark_find_data_collection(*collections_ptr, plugin_match_pid,
					  sd, &pid, 1);
	if (!col) {
		/*
		 * If a data collection for this task does not exist,
		 * register a new one.
		 */
		kshark_entry **data = argvCpp->_histo->data;
		int size = argvCpp->_histo->data_size;

		col = kshark_add_collection_to_list(kshark_ctx,
						    collections_ptr,
						    data, size,
						    plugin_match_pid,
						    sd, &pid, 1,
						    KS_TASK_COLLECTION_MARGIN);
	}

	if (!kshark_hash_id_find(second_pass_hash, pid)) {
		/* The second pass for this task is not done yet. */
		secondPass(argvCpp->_histo->data, col, sd, pid);
		kshark_hash_id_add(second_pass_hash, pid);
	}

	try {
		pluginDraw(kshark_ctx,
			   argvCpp->_histo, col,
			   SchedEvent::Wakeup, sd, pid,
			   argvCpp->_graph, argvCpp->_shapes);

		pluginDraw(kshark_ctx,
			   argvCpp->_histo, col,
			   SchedEvent::Switch, sd, pid,
			   argvCpp->_graph, argvCpp->_shapes);
	} catch (const std::exception &exc) {
		std::cerr << "Exception in SchedEvents\n" << exc.what();
	}
}
