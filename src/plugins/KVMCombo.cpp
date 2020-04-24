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

void KsVCPUCheckBoxWidget::update(int GuestId,
				  kshark_host_guest_map *gMap, int gMapCount)
{
	KsPlot::ColorTable colors;
	int j;

	for (j = 0; j < gMapCount; j++)
		if (gMap[j].guest_id == GuestId)
			break;
	if (j == gMapCount)
		return;

	_tree.clear();
	_id.resize(gMap[j].vcpu_count);
	_cb.resize(gMap[j].vcpu_count);
	colors = KsPlot::getCPUColorTable();

	for (int i = 0; i < gMap[j].vcpu_count; ++i) {
		QString strCPU = QLatin1String("vCPU ") + QString::number(i);
		strCPU += (QLatin1String("\t<") + QLatin1String(gMap[j].guest_name) + QLatin1Char('>'));

		QTreeWidgetItem *cpuItem = new QTreeWidgetItem;
		cpuItem->setText(0, "  ");
		cpuItem->setText(1, strCPU);
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

#define DIALOG_NAME	"KVM Combo plots"

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

	_guestMapCount = 0;
	_guestMap = nullptr;
}

KsComboPlotDialog::~KsComboPlotDialog()
{
	kshark_tracecmd_free_hostguest_map(_guestMap, _guestMapCount);
}

void KsComboPlotDialog::update()
{
	kshark_context *kshark_ctx(nullptr);
	int ret;
	int sd;
	int i;

	if (!kshark_instance(&kshark_ctx))
		return;

	kshark_tracecmd_free_hostguest_map(_guestMap, _guestMapCount);
	_guestMap = nullptr;
	_guestMapCount = 0;
	ret = kshark_tracecmd_get_hostguest_mapping(&_guestMap);
	if (ret > 0)
		_guestMapCount = ret;

	KsUtils::setElidedText(&_hostFileLabel,
			       kshark_ctx->stream[_guestMap[0].host_id]->file,
			       Qt::ElideLeft, LABEL_WIDTH);

	_guestStreamComboBox.clear();
	for (i = 0; i < _guestMapCount; i++) {
		sd = _guestMap[i].guest_id;
		if (sd >= kshark_ctx->n_streams)
			continue;

		_guestStreamComboBox.addItem(kshark_ctx->stream[sd]->file,
					     sd);
	}

	if (!_applyButtonConnection) {
		_applyButtonConnection =
			connect(&_applyButton,	&QPushButton::pressed,
				this,		&KsComboPlotDialog::_applyPress);
	}

	sd = _guestStreamComboBox.currentData().toInt();
	_vcpuTree.update(sd, _guestMap, _guestMapCount);
}

void KsComboPlotDialog::_applyPress()
{
	QVector<int> cbVec = _vcpuTree.getCheckedIds();
	QVector<int> allCombosVec;
	KsComboPlot combo(2);
	int nPlots(0);
	int GuestId;
	int j;

	GuestId = _guestStreamComboBox.currentData().toInt();
	for (j = 0; j < _guestMapCount; j++)
		if (_guestMap[j].guest_id == GuestId)
			break;
	if (j == _guestMapCount)
		return;


	/*
	 * Disconnect _applyButton. This is done in order to protect
	 * against multiple clicks.
	 */
	disconnect(_applyButtonConnection);

	for (auto const &i: cbVec) {
		if (i >= _guestMap[j].vcpu_count)
			continue;

		allCombosVec.append(2);

		combo[0]._streamId = _guestMap[j].guest_id;
		combo[0]._id = i;
		combo[0]._type = KsPlot::KSHARK_CPU_DRAW |
				 KsPlot::KSHARK_GUEST_DRAW;

		combo[0] >> allCombosVec;

		combo[1]._streamId = _guestMap[j].host_id;
		combo[1]._id = _guestMap[j].cpu_pid[i];
		combo[1]._type = KsPlot::KSHARK_TASK_DRAW |
				 KsPlot::KSHARK_HOST_DRAW;

		combo[1] >> allCombosVec;
		++nPlots;
	}

	emit apply(nPlots, allCombosVec);
}

void KsComboPlotDialog::_guestStreamChanged(const QString &sdStr)
{
	int GuestId = _guestStreamComboBox.currentData().toInt();
	_vcpuTree.update(GuestId, _guestMap, _guestMapCount);
}

KsComboPlotDialog dialog;
QMetaObject::Connection dialogConnection;

static void showDialog(KsMainWindow *ks)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	if (kshark_ctx->n_streams < 2) {
		QString err("Data from one Host and at least one Guest is required.");
		QMessageBox msgBox;
		msgBox.critical(nullptr, "Error", err);

		return;
	}

	dialog.update();

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
