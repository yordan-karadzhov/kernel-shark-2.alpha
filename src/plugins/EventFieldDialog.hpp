/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    EventFieldDialog.hpp
 *  @brief   Dialog class used by the EventFieldPlot plugin.
 */

#ifndef _KS_EFP_DIALOG_H
#define _KS_EFP_DIALOG_H

// Qt
#include <QtWidgets>

// KernelShark
#include "plugins/event_field_plot.h"

class KsMainWindow;
/**
 * The KsEFPDialog class provides a widget for selecting Trace event field to
 * be visualized.
 */
class KsEFPDialog : public QDialog
{
	Q_OBJECT
public:
	explicit KsEFPDialog(QWidget *parent = nullptr);

	void update();

	int streamId() const {return _streamComboBox.currentData().toInt();}

	QString eventName() const {return _eventComboBox.currentText();}

	QString fieldName() const {return _fieldComboBox.currentText();}

	val_select_func selectCondition(plugin_efp_context *plugin_ctx);

	KsMainWindow	*_gui_ptr;

private:
	QVBoxLayout	_topLayout;

	QHBoxLayout	_buttonLayout;

	QComboBox	_streamComboBox, _eventComboBox;

	QComboBox	_fieldComboBox, _selectComboBox;

	QLabel		_streamLabel, _eventLabel, _fieldLabel, _selectLabel;

	QPushButton	_applyButton, _resetButton, _cancelButton;

	void _setSelectCombo();

	void _setStreamCombo(kshark_context *kshark_ctx);

private slots:
	void _streamChanged(const QString &stream);

	void _eventChanged(const QString &event);

	void _apply();

	void _reset();
};

#endif
