// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2020 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
 */

/**
 *  @file    EventFieldDialog.cpp
 *  @brief   Dialog class used by the EventFieldPlot plugin.
 */

// C++
#include <iostream>
#include <vector>

// KernelShark
#include "KsMainWindow.hpp"
#include "LatencyPlotDialog.hpp"

#define DIALOG_NAME "Plot Latency"

LatencyPlotDialog::LatencyPlotDialog(QWidget *parent)
: QDialog(parent),
  _evtALabel("\tEvent A", this),
  _evtBLabel("\tEvent B", this),
  _applyButton("Apply", this),
  _resetButton("Reset", this),
  _cancelButton("Cancel", this)
{
	setWindowTitle(DIALOG_NAME);

	_fieldSelectLayout.addWidget(&_evtALabel, 0, 0);
	_fieldSelectLayout.addWidget(&_evtBLabel, 0, 1);

	_fieldSelectLayout.addWidget(&_efsWidgetA, 1, 0);
	_fieldSelectLayout.addWidget(&_efsWidgetB, 1, 1);
	_topLayout.addLayout(&_fieldSelectLayout);

	_buttonLayout.addWidget(&_applyButton);
	_applyButton.setAutoDefault(false);

	_buttonLayout.addWidget(&_resetButton);
	_resetButton.setAutoDefault(false);

	_buttonLayout.addWidget(&_cancelButton);
	_cancelButton.setAutoDefault(false);

	_buttonLayout.setAlignment(Qt::AlignLeft);
	_topLayout.addLayout(&_buttonLayout);

	connect(&_applyButton,	&QPushButton::pressed,
		this,		&LatencyPlotDialog::_apply);

	connect(&_applyButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	connect(&_resetButton,	&QPushButton::pressed,
		this,		&LatencyPlotDialog::_reset);

	connect(&_resetButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	connect(&_cancelButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	setLayout(&_topLayout);
}

void LatencyPlotDialog::update()
{
	_efsWidgetA.setStreamCombo();
	_efsWidgetB.setStreamCombo();
}

static LatencyPlotDialog *lp_dialog(nullptr);

void plugin_set_event_fields(struct plugin_latency_context *plugin_ctx)
{
	std::string buff;
	char *name;
	int ret;

	plugin_ctx->event_name[0] = plugin_ctx->event_name[1] = NULL;

	buff = lp_dialog->_efsWidgetA.eventName().toStdString();
	ret = asprintf(&name, "%s", buff.c_str());
	if (ret > 0)
		plugin_ctx->event_name[0] = name;

	buff = lp_dialog->_efsWidgetB.eventName().toStdString();
	ret = asprintf(&name, "%s", buff.c_str());
	if (ret > 0)
		plugin_ctx->event_name[1] = name;

	plugin_ctx->field_name[0] = plugin_ctx->field_name[1] = NULL;

	buff = lp_dialog->_efsWidgetA.fieldName().toStdString();
	ret = asprintf(&name, "%s", buff.c_str());
	if (ret > 0)
		plugin_ctx->field_name[0] = name;

	buff = lp_dialog->_efsWidgetB.fieldName().toStdString();
	ret = asprintf(&name, "%s", buff.c_str());
	if (ret > 0)
		plugin_ctx->field_name[1] = name;
}

void plugin_mark_entry(const kshark_entry *e, char mark)
{
	DualMarkerState st = DualMarkerState::A;
	if (mark == 'B')
		st = DualMarkerState::B;

	lp_dialog->_gui_ptr->markEntry(e, st);
}

void LatencyPlotDialog::_apply()
{
	auto work = KsWidgetsLib::KsDataWork::UpdatePlugins;
	int sdA = lp_dialog->_efsWidgetA.streamId();
	int sdB = lp_dialog->_efsWidgetB.streamId();

	/* The plugin needs to process the data and this may take time
	 * on large datasets. Show a "Work In Process" warning.
	 */
	_gui_ptr->getWipPtr()->show(work);
	_gui_ptr->registerPluginToStream("latency_plot", {sdA, sdB});
	_gui_ptr->getWipPtr()->hide(work);
}

void LatencyPlotDialog::_reset()
{
	auto work = KsWidgetsLib::KsDataWork::UpdatePlugins;
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	/*
	 * The plugin needs to process the data and this may take time
	 * on large datasets. Show a "Work In Process" warning.
	 */
	_gui_ptr->getWipPtr()->show(work);
	_gui_ptr->unregisterPluginFromStream("latency_plot",
					     KsUtils::getStreamIdList());
	_gui_ptr->getWipPtr()->hide(work);
}

static void showDialog(KsMainWindow *ks)
{
	lp_dialog->update();
	lp_dialog->show();
}

void *plugin_latency_add_menu(void *ks_ptr)
{
	if (!lp_dialog) {
		lp_dialog = new LatencyPlotDialog();
		lp_dialog->_gui_ptr = static_cast<KsMainWindow *>(ks_ptr);
	}

	QString menu("Tools/");
	menu += DIALOG_NAME;
	lp_dialog->_gui_ptr->addPluginMenu(menu, showDialog);

	printf("plugin_latency_add_menu %p\n", lp_dialog);
	return lp_dialog;
}
