/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2018 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

/**
  *  @file    KsPlugins.hpp
  *  @brief   KernelShark C++ plugin declarations.
  */

#ifndef _KS_PLUGINS_H
#define _KS_PLUGINS_H

// C++11
#include <functional>
#include <forward_list>
#include <vector>

// KernelShark
#include "libkshark-plugin.h"
#include "libkshark-model.h"
#include "KsPlotTools.hpp"

class KsMainWindow;
typedef void (pluginActionFunc) (KsMainWindow *);

/**
 * Structure representing the vector of C++ arguments of the drawing function
 * of a plugin.
 */
struct KsCppArgV {
	/** Pointer to the model descriptor object. */
	kshark_trace_histo	*_histo;

	/** Pointer to the graph object. */
	KsPlot::Graph		*_graph;

	/**
	 * Pointer to the list of shapes. All shapes created by the plugin
	 * will be added to this list.
	 */
	KsPlot::PlotObjList	*_shapes;

	/**
	 * Convert the "this" pointer of the C++ argument vector into a
	 * C pointer.
	 */
	kshark_cpp_argv *toC()
	{
		return reinterpret_cast<kshark_cpp_argv *>(this);
	}
};
/**
 * Macro used to convert a C pointer into a pointer to KsCppArgV (C++ struct).
 */
#define KS_ARGV_TO_CPP(a) (reinterpret_cast<KsCppArgV *>(a))

typedef std::function<KsPlot::PlotObject *(std::vector<const KsPlot::Graph *> graph,
					   std::vector<int> bin,
					   std::vector<int64_t> data,
					   KsPlot::Color col,
					   float size)> pluginShapeFunc;

typedef std::function<bool(kshark_data_container *, ssize_t)> IsApplicableFunc;

void eventPlot(KsCppArgV *argvCpp, IsApplicableFunc isApplicable,
	       pluginShapeFunc makeShape, KsPlot::Color col, float size);

void eventFieldPlotMax(KsCppArgV *argvCpp,
		       kshark_data_container *dataEvt,
		       IsApplicableFunc checkField,
		       pluginShapeFunc makeShape,
		       KsPlot::Color col,
		       float size);

void eventFieldPlotMin(KsCppArgV *argvCpp,
		       kshark_data_container *dataEvt,
		       IsApplicableFunc checkField,
		       pluginShapeFunc makeShape,
		       KsPlot::Color col,
		       float size);

void eventFieldIntervalPlot(KsCppArgV *argvCpp,
			    kshark_data_container *dataEvtA,
			    IsApplicableFunc checkFieldA,
			    kshark_data_container *dataEvtB,
			    IsApplicableFunc checkFieldB,
			    pluginShapeFunc makeShape,
			    KsPlot::Color col,
			    float size);

#endif
