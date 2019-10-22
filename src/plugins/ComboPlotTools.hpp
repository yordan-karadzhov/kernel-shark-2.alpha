/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

/**
 *  @file    ComboPlotTools.hpp
 *  @brief   KernelShark Combo Plot tools.
 */

// KernelShark
#include "KsPlugins.hpp"
#include "KsPlotTools.hpp"

static void drawVitrBridges(kshark_trace_histo *histo,
			    KsPlot::Graph *hostGraph,
			    int sdHost, int pidHost,
			    int vcpuEntryId, int vcpuExitId,
			    KsPlot::PlotObjList *shapes)
{
	int guestBaseY = hostGraph->getBin(0)._base.y() - hostGraph->height();
	int gapHeight = hostGraph->height() * .3;
	KsPlot::VirtBridge *bridge = new KsPlot::VirtBridge();
	KsPlot::VirtGap *gap = new KsPlot::VirtGap(gapHeight);
	const kshark_entry *entry, *exit;
	ssize_t indexEntry, indexExit;
	int values[2] = {-1, pidHost};

	bridge->_size = 2;
	bridge->_visible = false;
	bridge->setEntryHost(hostGraph->getBin(0)._base.x(), guestBaseY);
	bridge->setEntryGuest(hostGraph->getBin(0)._base.x(), guestBaseY);

	gap->_size = 2;
	gap->_visible = false;
	gap->_exitPoint = KsPlot::Point(hostGraph->getBin(0)._base.x(),
					guestBaseY);

	auto lamStartBridg = [&] (int bin) {
		if (!bridge)
			bridge = new KsPlot::VirtBridge();

		bridge->setEntryHost(hostGraph->getBin(bin)._base.x(),
				     hostGraph->getBin(bin)._base.y());

		bridge->setEntryGuest(hostGraph->getBin(bin)._base.x(),
				      guestBaseY);

		bridge->_color = hostGraph->getBin(bin)._color;
	};

	auto lamCloseBridg = [&] (int bin) {
		if (!bridge)
			return;

		bridge->setExitGuest(hostGraph->getBin(bin)._base.x(),
				     guestBaseY);

		bridge->setExitHost(hostGraph->getBin(bin)._base.x(),
				    hostGraph->getBin(bin)._base.y());

		bridge->_color = hostGraph->getBin(bin)._color;
		bridge->_visible = true;
		shapes->push_front(bridge);
		bridge = nullptr;
	};

	auto lamStartGap = [&] (int bin) {
		if (!gap)
			gap = new KsPlot::VirtGap(gapHeight);

		gap->_exitPoint =
			KsPlot::Point(hostGraph->getBin(bin)._base.x(),
				      guestBaseY);
	};

	auto lamCloseGap = [&] (int bin) {
		if (!gap)
			return;

		gap->_entryPoint =
			KsPlot::Point(hostGraph->getBin(bin)._base.x(),
				      guestBaseY);

		gap->_visible = true;
		shapes->push_front(gap);
		gap = nullptr;
	};

	for (int bin = 0; bin < histo->n_bins; ++bin) {
		values[0] = vcpuEntryId;
		entry = ksmodel_get_entry_back(histo, bin, true,
					       kshark_match_event_and_pid,
					       sdHost, values,
					       nullptr, &indexEntry);

		values[0] = vcpuExitId;
		exit = ksmodel_get_entry_back(histo, bin, true,
					      kshark_match_event_and_pid,
					      sdHost, values,
					      nullptr, &indexExit);

		if (entry && !exit) {
			lamStartBridg(bin);
			lamCloseGap(bin);
		}

		if (exit && !entry) {
			lamCloseBridg(bin);
			lamStartGap(bin);
		}

		if (exit && entry) {
			if (bridge && bridge->_visible)
				lamCloseBridg(bin);

			if (gap && gap->_visible)
				lamCloseGap(bin);

			if (indexEntry > indexExit) {
				lamStartBridg(bin);
			} else {
				lamStartBridg(bin);
				lamCloseBridg(bin);
				lamStartGap(bin);
			}
		}
	}

	if (bridge && bridge->_visible) {
		bridge->setExitGuest(hostGraph->getBin(histo->n_bins - 1)._base.x(),
				     guestBaseY);

		bridge->setExitHost(hostGraph->getBin(histo->n_bins - 1)._base.x(),
				    guestBaseY);

		shapes->push_front(bridge);
	}
}

static void drawCombos(kshark_cpp_argv *argv_c,
		       int sdHost, int pidHost,
		       int entryId, int exitId,
		       int draw_action)
{
	KsCppArgV *argvCpp;

	if (draw_action != KSHARK_PLUGIN_HOST_DRAW ||
	    pidHost == 0)
		return;

	argvCpp = KS_ARGV_TO_CPP(argv_c);
	try {
		drawVitrBridges(argvCpp->_histo,
				argvCpp->_graph,
				sdHost, pidHost,
				entryId,
				exitId,
				argvCpp->_shapes);
	} catch (const std::exception &exc) {
		std::cerr << "Exception in KVMCombo\n" << exc.what();
	}
}
