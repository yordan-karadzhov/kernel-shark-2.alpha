// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KVMCombo.cpp
 *  @brief   Plugin for visualization of KVM exits.
 */

// C++
#include<iostream>

// trace-cmd
#include "trace-cmd/trace-cmd.h"

// KernelShark
#include "libkshark.h"
#include "libkshark-tepdata.h"
#include "plugins/kvm_combo.h"
#include "ComboPlotTools.hpp"
#include "KsPlugins.hpp"
#include "KVMCombo.hpp"

using namespace KsWidgetsLib;

/**
 * @brief Plugin's draw function.
 *
 * @param argv_c: A C pointer to be converted to KsCppArgV (C++ struct).
 * @param sdHost: Data stream identifier of the Host.
 * @param pidHost: Process Id of the virtual CPU process in the Host.
 * @param draw_action: Draw action identifier.
 */
void draw_kvm_combos(kshark_cpp_argv *argv_c,
		     int sdHost, int pidHost,
		     int draw_action)
{
	plugin_kvm_context *plugin_ctx = get_kvm_context(sdHost);
	if (!plugin_ctx)
		return;

	drawCombos(argv_c,
		   sdHost,
		   pidHost,
		   plugin_ctx->vm_entry_id,
		   plugin_ctx->vm_exit_id,
		   draw_action);
}

/**
 * @brief Create KsCPUCheckBoxWidget.
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param parent: The parent of this widget.
 */
KsVCPUCheckBoxWidget::KsVCPUCheckBoxWidget(QWidget *parent)
: KsCheckBoxTreeWidget(0, "vCPUs", parent)
{
	int height(FONT_HEIGHT * 1.5);
	QString style;

	style = QString("QTreeView::item { height: %1 ;}").arg(height);
	_tree.setStyleSheet(style);

	_initTree();
}

void KsVCPUCheckBoxWidget::update(int sdHost, VCPUVector vcpus)
{
	int nVCPUs = vcpus.count();
	KsPlot::ColorTable colors;

	_tree.clear();
	_id.resize(nVCPUs);
	_cb.resize(nVCPUs);
	colors = KsPlot::getCPUColorTable();

	for (int i = 0; i < nVCPUs; ++i) {
		QTreeWidgetItem *cpuItem = new QTreeWidgetItem;
		cpuItem->setText(0, "  ");
		cpuItem->setText(1, QString("vCPU %1").arg(vcpus.at(i).second));
		cpuItem->setCheckState(0, Qt::Checked);
		cpuItem->setBackgroundColor(0, QColor(colors[i].r(),
						      colors[i].g(),
						      colors[i].b()));
		_tree.addTopLevelItem(cpuItem);
		_id[i] = i;
		_cb[i] = cpuItem;
	}

	_adjustSize();
	setDefault(false);
}

#define DIALOG_NAME "KVM Combo plots"

#define LABEL_WIDTH	(FONT_WIDTH * 50)

/** Create default KsComboPlotDialog. */
KsComboPlotDialog::KsComboPlotDialog(QWidget *parent)
: _vcpuTree(this),
  _hostLabel("Host:", this),
  _hostFileLabel("", this),
  _guestLabel("Guest:", this),
  _guestStreamComboBox(this),
  _applyButton("Apply", this),
  _cancelButton("Cancel", this)
{
	kshark_context *kshark_ctx(nullptr);
	int buttonWidth;

	auto lamAddLine = [&] {
		QFrame* line = new QFrame();

		line->setFrameShape(QFrame::HLine);
		line->setFrameShadow(QFrame::Sunken);
		_topLayout.addWidget(line);
	};

	setWindowTitle(DIALOG_NAME);

	if (!kshark_instance(&kshark_ctx))
		return;

	_guestStreamComboBox.setMaximumWidth(LABEL_WIDTH);

	_streamMenuLayout.addWidget(&_hostLabel, 0, 0);
	_streamMenuLayout.addWidget(&_hostFileLabel, 0, 1);
	_streamMenuLayout.addWidget(&_guestLabel, 1, 0);
	_streamMenuLayout.addWidget(&_guestStreamComboBox, 1, 1);

	_topLayout.addLayout(&_streamMenuLayout);

	lamAddLine();

	_topLayout.addWidget(&_vcpuTree);

	lamAddLine();

	buttonWidth = STRING_WIDTH("--Cancel--");
	_applyButton.setFixedWidth(buttonWidth);
	_cancelButton.setFixedWidth(buttonWidth);

	_buttonLayout.addWidget(&_applyButton);
	_applyButton.setAutoDefault(false);

	_buttonLayout.addWidget(&_cancelButton);
	_cancelButton.setAutoDefault(false);

	_buttonLayout.setAlignment(Qt::AlignLeft);
	_topLayout.addLayout(&_buttonLayout);

	connect(&_applyButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	connect(&_cancelButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	/*
	 * Using the old Signal-Slot syntax because QComboBox::currentIndexChanged
	 * has overloads.
	 */
	connect(&_guestStreamComboBox,	SIGNAL(currentIndexChanged(const QString &)),
		this,			SLOT(_guestStreamChanged(const QString &)));

	setLayout(&_topLayout);
}

void KsComboPlotDialog::update(int sdHost, VCPUVector vcpus)
{
	kshark_context *kshark_ctx(nullptr);
	int sd, *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	_sdHost = sdHost;
	_vcpus = vcpus;
	KsUtils::setElidedText(&_hostFileLabel,
			       kshark_ctx->stream[sdHost]->file,
			       Qt::ElideLeft, LABEL_WIDTH);

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		if (sd == sdHost)
			continue;

		_guestStreamComboBox.addItem(kshark_ctx->stream[sd]->file,
					     sd);
	}

	if (!_applyButtonConnection) {
		_applyButtonConnection =
			connect(&_applyButton,	&QPushButton::pressed,
				this,		&KsComboPlotDialog::_applyPress);
	}

	_vcpuTree.update(sdHost, vcpus);
	free(streamIds);
}

void KsComboPlotDialog::_applyPress()
{
	QVector<int> cbVec = _vcpuTree.getCheckedIds();
	QVector<int> combo(4), allCombos;
	int nPlots(0);

	/*
	 * Disconnect _applyButton. This is done in order to protect
	 * against multiple clicks.
	 */
	disconnect(_applyButtonConnection);

	for (auto const &i: cbVec) {
		combo[0] = _sdHost;
		combo[1] = _vcpus.at(i).first;
		combo[2] = _guestStreamComboBox.currentData().toInt();
		combo[3] = _vcpus.at(i).second;
		allCombos.append(combo);
		++nPlots;
	}

	emit apply(nPlots, allCombos);
}

void KsComboPlotDialog::_guestStreamChanged(const QString &sdStr)
{

}

static int getVCPU(plugin_kvm_context *plugin_ctx,
		   kshark_trace_histo *histo,
		   int sdHost, int pid)
{
	int values[2] = {plugin_ctx->vm_entry_id, pid};
	const kshark_entry *entry;

	for (int b = 0; b < histo->n_bins; ++b) {
		entry = ksmodel_get_entry_front(histo,
						b, false,
						kshark_match_event_and_pid,
						sdHost, values,
						nullptr,
						nullptr);
		if (!entry)
			continue;

		return kshark_tep_read_event_field(entry, "vcpu_id", -1);
	}

	return -1;
}

HostMap getVCPUPids(kshark_context *kshark_ctx, kshark_trace_histo *histo)
{
	int sd, n_vcpus, *streamIds, *pids;
	plugin_kvm_context *plugin_ctx;
	HostMap hMap;

	streamIds = kshark_all_streams(kshark_ctx);
	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		plugin_ctx = get_kvm_context(sd);
		if (!plugin_ctx)
			continue;

		/* This stream continues KVM events. */
		n_vcpus = plugin_ctx->vcpu_pids->count;
		if (n_vcpus) {
			VCPUVector vcpus(n_vcpus);
			pids = kshark_hash_ids(plugin_ctx->vcpu_pids);
			for (int j = 0; j < n_vcpus; ++j) {
				vcpus[j].first = pids[j];
				vcpus[j].second = getVCPU(plugin_ctx,
							  histo,
							  sd, pids[j]);
			}

			free(pids);
			hMap[sd] = vcpus;
		}
	}

	free(streamIds);
	return hMap;
}

KsComboPlotDialog dialog;
QMetaObject::Connection dialogConnection;

static void showDialog(KsMainWindow *ks)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_trace_histo *histo;
	VCPUVector vcpus;
	HostMap hMap;
	int sdHost;

	if (!kshark_instance(&kshark_ctx))
		return;

	histo = ks->graphPtr()->glPtr()->model()->histo();
	hMap = getVCPUPids(kshark_ctx, histo);

	if (kshark_ctx->n_streams < 2 || hMap.count() != 1) {
		QString err("Data from one Host and at least one Guest is required.");
		QMessageBox msgBox;
		msgBox.critical(nullptr, "Error", err);

		return;
	}

	sdHost = hMap.begin().key();
	vcpus = hMap.begin().value();

	dialog.update(sdHost, vcpus);

	if (!dialogConnection) {
		dialogConnection =
			QObject::connect(&dialog,	&KsComboPlotDialog::apply,
					 ks->graphPtr(),&KsTraceGraph::comboReDraw);
	}

	dialog.show();
}

void plugin_kvm_add_menu(void *ks_ptr)
{
	KsMainWindow *ks = static_cast<KsMainWindow *>(ks_ptr);
	QString menu("Plots/");
	menu += DIALOG_NAME;
	ks->addPluginMenu(menu, showDialog);
}
