/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2019 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KVMCombo.hpp
 *  @brief   Plugin for visualization of KVM exits.
 */

#ifndef _KS_COMBO_DIALOG_H
#define _KS_COMBO_DIALOG_H

#include "KsMainWindow.hpp"
#include "KsWidgetsLib.hpp"

typedef QVector<QPair<int, int>> VCPUVector;

typedef QMap<int, VCPUVector> HostMap;

/**
 * The KsVCPUCheckBoxWidget class provides a widget for selecting CPU plots to
 * show.
 */
struct KsVCPUCheckBoxWidget : public KsWidgetsLib::KsCheckBoxTreeWidget
{
	explicit KsVCPUCheckBoxWidget(QWidget *parent = nullptr);

	void update(int sdHost, VCPUVector vcpus);
};

/**
 * The KsComboPlotDialog class provides a widget for selecting Combo plots to
 * show.
 */
class KsComboPlotDialog : public QDialog
{
	Q_OBJECT
public:
	explicit KsComboPlotDialog(QWidget *parent = nullptr);

	void update(int sdHost, VCPUVector vcpus);

signals:
	/** Signal emitted when the "Apply" button is pressed. */
	void apply(int sd, QVector<int>);

private:
	int				_sdHost;

	VCPUVector			_vcpus;

	KsVCPUCheckBoxWidget		_vcpuTree;

	QVBoxLayout			_topLayout;

	QGridLayout			_streamMenuLayout;

	QHBoxLayout			_buttonLayout;

	QLabel				_hostLabel, _hostFileLabel, _guestLabel;

	QComboBox			_guestStreamComboBox;

	QPushButton			_applyButton, _cancelButton;

	QMetaObject::Connection		_applyButtonConnection;

	void _applyPress();

private slots:

	void _guestStreamChanged(const QString&);
};

#endif
