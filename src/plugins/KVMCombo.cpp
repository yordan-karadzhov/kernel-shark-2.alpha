// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KVMCombo.cpp
 *  @brief   Plugin for visualization of KVM exits.
 */

// C++
#include <iostream>

// trace-cmd
#include "trace-cmd/trace-cmd.h"

// KernelShark
#include "libkshark.h"
#include "libkshark-tepdata.h"
#include "plugins/kvm_combo.h"
#include "ComboPlotTools.hpp"
#include "KsPlugins.hpp"
#include "KVMComboDialog.hpp"

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

	drawVirtCombos(argv_c,
		       sdHost,
		       pidHost,
		       plugin_ctx->vm_entry_id,
		       plugin_ctx->vm_exit_id,
		       draw_action);
}

using namespace KsWidgetsLib;

static KsComboPlotDialog *combo_dialog(nullptr);
static QMetaObject::Connection combo_dialogConnection;

#define DIALOG_NAME	"KVM Combo plots"

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

	combo_dialog->update();

	if (!combo_dialogConnection) {
		combo_dialogConnection =
			QObject::connect(combo_dialog,	&KsComboPlotDialog::apply,
					 ks->graphPtr(),&KsTraceGraph::comboReDraw);
	}

	combo_dialog->show();
}

void *plugin_kvm_add_menu(void *ks_ptr)
{
	KsMainWindow *ks = static_cast<KsMainWindow *>(ks_ptr);
	QString menu("Plots/");
	menu += DIALOG_NAME;
	ks->addPluginMenu(menu, showDialog);

	if (!combo_dialog)
		combo_dialog = new KsComboPlotDialog();

	combo_dialog->_gui_ptr = ks;

	return combo_dialog;
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

void KsVCPUCheckBoxWidget::update(int guestId,
				  kshark_host_guest_map *gMap, int gMapCount)
{
	KsPlot::ColorTable colTable;
	QColor color;
	int j;

	for (j = 0; j < gMapCount; j++)
		if (gMap[j].guest_id == guestId)
			break;
	if (j == gMapCount)
		return;

	_tree.clear();
	_id.resize(gMap[j].vcpu_count);
	_cb.resize(gMap[j].vcpu_count);
	colTable = KsPlot::getCPUColorTable();

	for (int i = 0; i < gMap[j].vcpu_count; ++i) {
		QString strCPU = QLatin1String("vCPU ") + QString::number(i);
		strCPU += (QLatin1String("\t<") + QLatin1String(gMap[j].guest_name) + QLatin1Char('>'));

		QTreeWidgetItem *cpuItem = new QTreeWidgetItem;
		cpuItem->setText(0, "  ");
		cpuItem->setText(1, strCPU);
		cpuItem->setCheckState(0, Qt::Checked);
		color << colTable[i];
		cpuItem->setBackgroundColor(0, color);
		_tree.addTopLevelItem(cpuItem);
		_id[i] = i;
		_cb[i] = cpuItem;
	}

	_adjustSize();
	setDefault(false);
}

#define LABEL_WIDTH	(FONT_WIDTH * 50)

/** Create default KsComboPlotDialog. */
KsComboPlotDialog::KsComboPlotDialog(QWidget *parent)
: QDialog(parent),
  _vcpuTree(this),
  _hostLabel("Host:", this),
  _hostFileLabel("", this),
  _guestLabel("Guest:", this),
  _guestStreamComboBox(this),
  _applyButton("Apply", this),
  _cancelButton("Cancel", this),
  _currentGuestStream(0)
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
	KsPlot::ColorTable colTable;
	QString streamName;
	QColor color;
	int ret, sd, i;

	if (!kshark_instance(&kshark_ctx))
		return;

	kshark_tracecmd_free_hostguest_map(_guestMap, _guestMapCount);
	_guestMap = nullptr;
	_guestMapCount = 0;
	ret = kshark_tracecmd_get_hostguest_mapping(&_guestMap);
	if (ret <= 0) {
		QString err("Cannot find host / guest tracing into the loaded streams");
		QMessageBox msgBox;
		msgBox.critical(nullptr, "Error", err);
		return;
	} else {
		_guestMapCount = ret;
	}

	streamName = KsUtils::streamDescription(kshark_ctx->stream[_guestMap[0].host_id]);
	KsUtils::setElidedText(&_hostFileLabel,
			       streamName,
			       Qt::ElideLeft, LABEL_WIDTH);

	_guestStreamComboBox.clear();
	colTable = KsPlot::getStreamColorTable();
	for (i = 0; i < _guestMapCount; i++) {
		sd = _guestMap[i].guest_id;
		if (sd >= kshark_ctx->n_streams)
			continue;

		streamName = KsUtils::streamDescription(kshark_ctx->stream[sd]);
		_guestStreamComboBox.addItem(streamName, sd);
		color << colTable[sd];
		_guestStreamComboBox.setItemData(i, QBrush(color),
						    Qt::BackgroundRole);
	}

	if (!_applyButtonConnection) {
		_applyButtonConnection =
			connect(&_applyButton,	&QPushButton::pressed,
				this,		&KsComboPlotDialog::_applyPress);
	}

	sd = _guestStreamComboBox.currentData().toInt();
	_vcpuTree.update(sd, _guestMap, _guestMapCount);
	_setCurrentPlots(sd);
}

QVector<KsComboPlot> KsComboPlotDialog::_streamCombos(int guestId)
{
	QVector<int> cbVec = _vcpuTree.getCheckedIds();
	QVector <KsComboPlot> plots;
	KsComboPlot combo(2);
	int j;

	for (j = 0; j < _guestMapCount; j++)
		if (_guestMap[j].guest_id == guestId)
			break;

	if (j == _guestMapCount)
		return {};

	for (auto const &i: cbVec) {
		if (i >= _guestMap[j].vcpu_count)
			continue;

		combo[0]._streamId = _guestMap[j].guest_id;
		combo[0]._id = i;
		combo[0]._type = KsPlot::KSHARK_CPU_DRAW |
				 KsPlot::KSHARK_GUEST_DRAW;

		combo[1]._streamId = _guestMap[j].host_id;
		combo[1]._id = _guestMap[j].cpu_pid[i];
		combo[1]._type = KsPlot::KSHARK_TASK_DRAW |
				 KsPlot::KSHARK_HOST_DRAW;

		plots.append(combo);
	}

	return plots;
}

void KsComboPlotDialog::_applyPress()
{
	QVector<int> allCombosVec;
	int nPlots(0);
	int guestId;

	guestId = _guestStreamComboBox.currentData().toInt();
	_plotMap[guestId] = _streamCombos(guestId);

	for (auto const &stream: _plotMap)
		for (auto const &combo: stream) {
			allCombosVec.append(2);
			combo[0] >> allCombosVec;
			combo[1] >> allCombosVec;
			++nPlots;
		}

	emit apply(nPlots, allCombosVec);
}

void KsComboPlotDialog::_setCurrentPlots(int guestSd)
{
	QVector<KsComboPlot> currentCombos =_plotMap[guestSd];
	QVector<int> vcpuCBs(_guestMapCount, 0);

	for(auto const &p: currentCombos) {
		int vcpu = p[0]._id;
		vcpuCBs[vcpu] = 1;
	}

	_vcpuTree.set(vcpuCBs);
}

void KsComboPlotDialog::_guestStreamChanged(const QString &sdStr)
{
	int newGuestId = _guestStreamComboBox.currentData().toInt();
	QVector<int> vcpuCBs(_guestMapCount, 0);

	_plotMap[_currentGuestStream] = _streamCombos(_currentGuestStream);

	_vcpuTree.update(newGuestId, _guestMap, _guestMapCount);
	_setCurrentPlots(newGuestId);

	_currentGuestStream = newGuestId;
}
