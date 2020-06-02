// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2018 VMware Inc, Yordan Karadzhov (VMware) <y.karadz@gmail.com>
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
#include "EventFieldDialog.hpp"

#define DIALOG_NAME "Plot Event Field"

static bool is_greater(unsigned long long max,
		       unsigned long long fieldVal)
{
	return fieldVal > max;
}

static bool is_smaller(unsigned long long min,
		       unsigned long long fieldVal)
{
	return fieldVal < min;
}

static bool ignore(unsigned long long,
		   unsigned long long)
{
	return false;
}

KsEFPDialog::KsEFPDialog(QWidget *parent)
: QDialog(parent),
  _streamLabel("Data stream", this),
  _eventLabel("Event (type in for searching)", this),
  _fieldLabel("Field", this),
  _selectLabel("Show", this),
  _applyButton("Apply", this),
  _resetButton("Reset", this),
  _cancelButton("Cancel", this)
{
	setWindowTitle(DIALOG_NAME);

	auto lamAddLine = [&] {
		QFrame* line = new QFrame();
		QSpacerItem *spacer = new QSpacerItem(1, FONT_HEIGHT / 2,
						      QSizePolicy::Expanding,
						      QSizePolicy::Minimum);
		line->setFrameShape(QFrame::HLine);
		line->setFrameShadow(QFrame::Sunken);
		_topLayout.addSpacerItem(spacer);
		_topLayout.addWidget(line);
	};

	_topLayout.addWidget(&_streamLabel);
	_topLayout.addWidget(&_streamComboBox);

	/*
	 * Using the old Signal-Slot syntax because QComboBox::currentIndexChanged
	 * has overloads.
	 */
	connect(&_streamComboBox,	SIGNAL(currentIndexChanged(const QString&)),
		this,			SLOT(_streamChanged(const QString&)));

	lamAddLine();

	_topLayout.addWidget(&_eventLabel);
	_topLayout.addWidget(&_eventComboBox);
	_eventComboBox.setEditable(true);
	_eventComboBox.view()->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
	_eventComboBox.setMaxVisibleItems(25);

	/*
	 * Using the old Signal-Slot syntax because QComboBox::currentIndexChanged
	 * has overloads.
	 */
	connect(&_eventComboBox,	SIGNAL(currentIndexChanged(const QString&)),
		this,			SLOT(_eventChanged(const QString&)));

	lamAddLine();

	_topLayout.addWidget(&_fieldLabel);
	_topLayout.addWidget(&_fieldComboBox);

	lamAddLine();

	_topLayout.addWidget(&_selectLabel);
	_setSelectCombo();
	_topLayout.addWidget(&_selectComboBox);

	lamAddLine();

	_buttonLayout.addWidget(&_applyButton);
	_applyButton.setAutoDefault(false);

	_buttonLayout.addWidget(&_resetButton);
	_resetButton.setAutoDefault(false);

	_buttonLayout.addWidget(&_cancelButton);
	_cancelButton.setAutoDefault(false);

	_buttonLayout.setAlignment(Qt::AlignLeft);
	_topLayout.addLayout(&_buttonLayout);

	connect(&_applyButton,	&QPushButton::pressed,
		this,		&KsEFPDialog::_apply);

	connect(&_applyButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	connect(&_resetButton,	&QPushButton::pressed,
		this,		&KsEFPDialog::_reset);

	connect(&_resetButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	connect(&_cancelButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	setLayout(&_topLayout);
}

void KsEFPDialog::_setSelectCombo()
{
	_selectComboBox.clear();
	_selectComboBox.addItem("max. value", 0);
	_selectComboBox.addItem("min. value", 1);
}

val_select_func KsEFPDialog::selectCondition(plugin_efp_context *plugin_ctx)
{
	int i = _selectComboBox.currentData().toInt();

	switch (i) {
	case 0:
		plugin_ctx->show_max = true;
		return is_greater;

	case 1:
		plugin_ctx->show_max = false;
		return is_smaller;

	default:
		return ignore;
	}
}

void KsEFPDialog::_setStreamCombo(kshark_context *kshark_ctx)
{
	int sd, *streamIds = kshark_all_streams(kshark_ctx);
	kshark_data_stream *stream;

	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		stream = kshark_ctx->stream[sd];
		if (_streamComboBox.findData(sd) < 0)
			_streamComboBox.addItem(QString(stream->file), sd);
	}
	free(streamIds);
}

void KsEFPDialog::_streamChanged(const QString &streamFile)
{
	int sd = _streamComboBox.currentData().toInt();
	kshark_context *kshark_ctx(NULL);
	kshark_data_stream *stream;
	kshark_entry entry;
	QStringList evtsList;
	int *eventIds;

	_eventComboBox.clear();
	if (!kshark_instance(&kshark_ctx))
		return;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	eventIds = kshark_get_all_event_ids(stream);
	entry.stream_id = stream->stream_id;
	entry.visible = 0xff;
	for (int i = 0; i < stream->n_events; ++i) {
		entry.event_id = eventIds[i];
		evtsList << QString(kshark_get_event_name(&entry));
	}

	qSort(evtsList);
	_eventComboBox.addItems(evtsList);
}

void KsEFPDialog::_eventChanged(const QString &eventName)
{
	int nFields, sd = _streamComboBox.currentData().toInt();
	kshark_context *kshark_ctx(NULL);
	kshark_data_stream *stream;
	kshark_entry entry;
	QStringList fieldsList;
	std::string buff;
	char **fields;

	_fieldComboBox.clear();
	if (!kshark_instance(&kshark_ctx))
		return;

	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	buff = eventName.toStdString();
	entry.event_id = stream->interface.find_event_id(stream, buff.c_str());
	nFields = stream->interface.get_all_field_names(stream, &entry, &fields);

	auto lamGetType = [&] (int i) {
		return stream->interface.get_event_field_type(stream, &entry,
							      fields[i]);
	};

	for (int i = 0; i < nFields; ++i) {
		if (lamGetType(i))
			fieldsList << fields[i];

		free(fields[i]);
	}

	qSort(fieldsList);
	_fieldComboBox.addItems(fieldsList);
}

void KsEFPDialog::update()
{
	kshark_context *kshark_ctx(NULL);

	if (!kshark_instance(&kshark_ctx))
		return;

	_setStreamCombo(kshark_ctx);
}

static KsEFPDialog *efp_dialog(nullptr);

int plugin_get_stream_id()
{
	return efp_dialog->streamId();
}

void plugin_set_event_name(plugin_efp_context *plugin_ctx)
{
	QString buff = efp_dialog->eventName();
	char *event;

	if (asprintf(&event, "%s", buff.toStdString().c_str()) >= 0) {
		plugin_ctx->event_name = event;
		return;
	}

	plugin_ctx->event_name = NULL;
}

void plugin_set_field_name(plugin_efp_context *plugin_ctx)
{
	QString buff = efp_dialog->fieldName();
	char *field;

	if (asprintf(&field, "%s", buff.toStdString().c_str()) >= 0) {
		plugin_ctx->field_name = field;
		return;
	}

	plugin_ctx->field_name = NULL;
}

void plugin_set_select_condition(plugin_efp_context *plugin_ctx)
{
	plugin_ctx->condition = efp_dialog->selectCondition(plugin_ctx);
}

void KsEFPDialog::_apply()
{
	auto work = KsWidgetsLib::KsDataWork::UpdatePlugins;

	/* The plugin needs to process the data and this may take time
	 * on large datasets. Show a "Work In Process" warning.
	 */
	_gui_ptr->getWipPtr()->show(work);
	_gui_ptr->registerPluginToStream("event_field_plot",
					 {plugin_get_stream_id()});
	_gui_ptr->getWipPtr()->hide(work);
}

void KsEFPDialog::_reset()
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

	_gui_ptr->unregisterPluginFromStream("event_field_plot",
					     KsUtils::getStreamIdList());

	_gui_ptr->getWipPtr()->hide(work);
}

static void showDialog(KsMainWindow *ks)
{
	efp_dialog->update();
	efp_dialog->show();
}

void *plugin_efp_add_menu(void *ks_ptr)
{
	if (!efp_dialog) {
		efp_dialog = new KsEFPDialog();
		efp_dialog->_gui_ptr = static_cast<KsMainWindow *>(ks_ptr);
	}

	QString menu("Tools/");
	menu += DIALOG_NAME;
	efp_dialog->_gui_ptr->addPluginMenu(menu, showDialog);

	printf("plugin_efp_add_menu %p\n", efp_dialog);
	return efp_dialog;
}
