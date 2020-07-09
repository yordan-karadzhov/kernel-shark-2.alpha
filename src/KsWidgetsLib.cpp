// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsWidgetsLib.cpp
 *  @brief   Defines small widgets and dialogues used by the KernelShark GUI.
 */

// C
#include <unistd.h>

// KernelShark
#include "libkshark-tepdata.h"
#include "KsCmakeDef.hpp"
#include "KsPlotTools.hpp"
#include "KsWidgetsLib.hpp"

namespace KsWidgetsLib
{

/**
 * @brief Create KsProgressBar.
 *
 * @param message: Text to be shown.
 * @param parent: The parent of this widget.
 */
KsProgressBar::KsProgressBar(QString message, QWidget *parent)
: QWidget(parent),
  _sb(this),
  _pb(&_sb),
  _notDone(false) {
	setWindowTitle("KernelShark");
	setLayout(new QVBoxLayout);
	setFixedHeight(KS_PROGBAR_HEIGHT);
	setFixedWidth(KS_PROGBAR_WIDTH);
	_pb.setOrientation(Qt::Horizontal);
	_pb.setTextVisible(false);
	_pb.setRange(0, KS_PROGRESS_BAR_MAX);
	_pb.setValue(1);

	_sb.addPermanentWidget(&_pb, 1);

	layout()->addWidget(new QLabel(message));
	layout()->addWidget(&_sb);

	setWindowFlags(Qt::WindowStaysOnTopHint);

	show();
}

KsProgressBar::~KsProgressBar()
{
	_notDone = false;
	usleep(10000);
}

/** @brief Set the state of the progressbar.
 *
 * @param i: A value ranging from 0 to KS_PROGRESS_BAR_MAX.
 */
void KsProgressBar::setValue(int i) {
	_pb.setValue(i);
	QApplication::processEvents();
}

void KsProgressBar::workInProgress()
{
	int progress, inc;
	bool inv = false;

	progress = inc = 5;
	_notDone = true;
	while (_notDone) {
		if (progress > KS_PROGRESS_BAR_MAX ||
		    progress <= 0) {
			inc = -inc;
			inv = !inv;
			_pb.setInvertedAppearance(inv);
		}

		setValue(progress);
		progress += inc;
		usleep(30000);
	}
}

KsWorkInProgress::KsWorkInProgress(QWidget *parent)
: QWidget(parent),
  _icon(this),
  _message("work in progress", this)
{
	QIcon statusIcon = QIcon::fromTheme("dialog-warning");
	_icon.setPixmap(statusIcon.pixmap(.8 * FONT_HEIGHT));
}


void KsWorkInProgress::show(KsDataWork w)
{
	_works.insert(w);
	if (_works.size() == 1) {
		_icon.show();
		_message.show();

		if (w != KsDataWork::RenderGL &&
		    w != KsDataWork::ResizeGL)
			QApplication::processEvents();
	}
}

void KsWorkInProgress::hide(KsDataWork w)
{
	_works.remove(w);
	if (_works.isEmpty()) {
		_icon.hide();
		_message.hide();

		if (w != KsDataWork::RenderGL &&
		    w != KsDataWork::ResizeGL)
			QApplication::processEvents();
	}
}

bool KsWorkInProgress::isBusy(KsDataWork w) const
{
	if (w == KsDataWork::AnyWork)
		return _works.isEmpty()? false : true;

	return _works.contains(w)? true : false;
}

void KsWorkInProgress::addToStatusBar(QStatusBar *sb)
{
	sb->addPermanentWidget(&_icon);
	sb->addPermanentWidget(&_message);
	_icon.hide();
	_message.hide();
}

/**
 * @brief Create KsMessageDialog.
 *
 * @param message: Text to be shown.
 * @param parent: The parent of this widget.
 */
KsMessageDialog::KsMessageDialog(QString message, QWidget *parent)
: QDialog(parent),
  _text(message, this),
  _closeButton("Close", this)
{
	resize(KS_MSG_DIALOG_WIDTH, KS_MSG_DIALOG_HEIGHT);

	_layout.addWidget(&_text);
	_layout.addWidget(&_closeButton);

	connect(&_closeButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	this->setLayout(&_layout);
}

/**
 * @brief Launch a File exists dialog. Use this function to ask the user
 * before overwriting an existing file.
 *
 * @param fileName: the name of the file.
 *
 * @returns True if the user wants to overwrite the file. Otherwise
 */
bool fileExistsDialog(QString fileName)
{
	QString msg("A file ");
	QMessageBox msgBox;

	msg += fileName;
	msg += " already exists.";
	msgBox.setText(msg);
	msgBox.setInformativeText("Do you want to replace it?");

	msgBox.setStandardButtons(QMessageBox::Save | QMessageBox::Cancel);
	msgBox.setDefaultButton(QMessageBox::Cancel);

	return (msgBox.exec() == QMessageBox::Save);
}

/** Create KsTimeOffsetDialog. */
KsTimeOffsetDialog::KsTimeOffsetDialog(QWidget *parent)
{
	kshark_context *kshark_ctx(nullptr);
	int  *streamIds;

	auto lamApply = [&] (double val) {
		int sd = _streamCombo.currentText().toInt();
		emit apply(sd, val);
		close();
	};

	auto lamSetDefault = [&] (const QString &val) {
		kshark_context *kshark_ctx(nullptr);
		struct kshark_data_stream *stream;
		double offset;
		int sd;

		if (!kshark_instance(&kshark_ctx))
			return;

		sd = val.toInt();
		stream = kshark_get_data_stream(kshark_ctx, sd);
		if (!stream)
			return;

		offset = stream->calib_array[0] * 1e-3;
		_input.setDoubleValue(offset);
	};

	if (!kshark_instance(&kshark_ctx))
		return;

	this->setLayout(new QVBoxLayout);

	streamIds = kshark_all_streams(kshark_ctx);
	if (kshark_ctx->n_streams > 1) {
		for (int i = 0; i < kshark_ctx->n_streams; ++i)
			if (streamIds[i] != 0)
				_streamCombo.addItem(QString::number(streamIds[i]));


		layout()->addWidget(&_streamCombo);
	}

	free(streamIds);

	_input.setInputMode(QInputDialog::DoubleInput);
	_input.setDoubleRange(-1e16, 1e16);
	_input.setDoubleDecimals(3);
	_input.setLabelText("Offset [usec]:");
	lamSetDefault(_streamCombo.currentText());

	layout()->addWidget(&_input);

	connect(&_input,	&QInputDialog::doubleValueSelected,
		lamApply);

	connect(&_input,	&QDialog::rejected,
		this,		&QWidget::close);


	connect(&_streamCombo,	&QComboBox::currentTextChanged,
		lamSetDefault);

	show();
}

/**
 * @brief Create KsCheckBoxWidget.
 *
 * @param sd: Data stream identifier.
 * @param name: The name of this widget.
 * @param parent: The parent of this widget.
 */
KsCheckBoxWidget::KsCheckBoxWidget(int sd, const QString &name,
				   QWidget *parent)
: QWidget(parent),
  _sd(sd),
  _allCb("all"),
  _cbWidget(this),
  _cbLayout(&_cbWidget),
  _topLayout(this),
  _allCbAction(nullptr),
  _stramLabel("", this),
  _name(name),
  _nameLabel(name + ":  ")
{
	setWindowTitle(_name);
	_setStream(sd);
	setMinimumHeight(SCREEN_HEIGHT / 2);

	connect(&_allCb,	&QCheckBox::clicked,
		this,		&KsCheckBoxWidget::_checkAll);

	_cbWidget.setLayout(&_cbLayout);

	if (!_stramLabel.text().isEmpty())
		_topLayout.addWidget(&_stramLabel);

	_tb.addWidget(&_nameLabel);
	_allCbAction = _tb.addWidget(&_allCb);

	_topLayout.addWidget(&_tb);

	_topLayout.addWidget(&_cbWidget);
	_topLayout.setContentsMargins(0, 0, 0, 0);

	setLayout(&_topLayout);
	_allCb.setCheckState(Qt::Checked);
}

/**
 * Set the default state for all checkboxes (including the "all" checkbox).
 */
void KsCheckBoxWidget::setDefault(bool st)
{
	Qt::CheckState state = Qt::Unchecked;

	if (st)
		state = Qt::Checked;

	_allCb.setCheckState(state);
	_checkAll(state);
}

/** . */
void KsCheckBoxWidget::_setStream(uint8_t sd)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;

	if (!kshark_instance(&kshark_ctx))
		return;

	_sd = sd;
	stream = kshark_get_data_stream(kshark_ctx, sd);
	if (!stream)
		return;

	_streamName = QString(stream->file);

	KsUtils::setElidedText(&_stramLabel, _streamName,
			       Qt::ElideLeft, width());
	QApplication::processEvents();
}

/** Get a vector containing the indexes of all checked check boxes. */
QVector<int> KsCheckBoxWidget::getCheckedIds()
{
	int n = _id.size();
	QVector<int> vec;

	for (int i = 0; i < n; ++i)
		if (_checkState(i) == Qt::Checked)
			vec.append(_id[i]);

	return vec;
}

/** Get a vector containing the state of all checkboxes. */
QVector<int> KsCheckBoxWidget::getStates()
{
	int n = _id.size();
	QVector<int> vec(n);

	for (int i = 0; i < n; ++i)
		vec[i] = !!_checkState(i);

	return vec;
}

/**
 * @brief Set the state of the checkboxes.
 *
 * @param v: Vector containing the state values for all checkboxes.
 */
void KsCheckBoxWidget::set(QVector<int> v)
{
	Qt::CheckState state;
	int nChecks;

	nChecks = (v.size() < _id.size()) ? v.size() : _id.size();

	/* Start with the "all" checkbox being checked. */
	_allCb.setCheckState(Qt::Checked);
	for (int i = 0; i < nChecks; ++i) {
		if (v[i]) {
			state = Qt::Checked;
		} else {
			/*
			 * At least one checkbox is unchecked. Uncheck
			 * "all" as well.
			 */
			state = Qt::Unchecked;
			_allCb.setCheckState(state);
		}

		_setCheckState(i, state);
	}
	_verify();
}

void KsCheckBoxWidget::_checkAll(bool st)
{
	Qt::CheckState state = Qt::Unchecked;
	int n = _id.size();

	if (st) state = Qt::Checked;

	for (int i = 0; i < n; ++i) {
		_setCheckState(i, state);
	}

	_verify();
}

/**
 * @brief Create KsCheckBoxDialog.
 *
 * @param cbws: A vector of KsCheckBoxWidgets to be nested in this dialog.
 * @param parent: The parent of this widget.
 */
KsCheckBoxDialog::KsCheckBoxDialog(QVector<KsCheckBoxWidget *> cbws, QWidget *parent)
: QDialog(parent),
  _applyIds(true),
  _checkBoxWidgets(cbws),
  _applyButton("Apply", this),
  _cancelButton("Cancel", this)
{
	int buttonWidth;

	if (!cbws.isEmpty())
		setWindowTitle(cbws[0]->name());

	for (auto const &w: _checkBoxWidgets)
		_cbLayout.addWidget(w);
	_topLayout.addLayout(&_cbLayout);

	buttonWidth = STRING_WIDTH("--Cancel--");
	_applyButton.setFixedWidth(buttonWidth);
	_cancelButton.setFixedWidth(buttonWidth);

	_buttonLayout.addWidget(&_applyButton);
	_applyButton.setAutoDefault(false);

	_buttonLayout.addWidget(&_cancelButton);
	_cancelButton.setAutoDefault(false);

	_buttonLayout.setAlignment(Qt::AlignLeft);
	_topLayout.addLayout(&_buttonLayout);

	_applyButtonConnection =
		connect(&_applyButton,	&QPushButton::pressed,
			this,		&KsCheckBoxDialog::_applyPress);

	connect(&_applyButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	connect(&_cancelButton,	&QPushButton::pressed,
		this,		&QWidget::close);

	this->setLayout(&_topLayout);
}

void KsCheckBoxDialog::_applyPress()
{
	QVector<int> vec;

	/*
	 * Disconnect _applyButton. This is done in order to protect
	 * against multiple clicks.
	 */
	disconnect(_applyButtonConnection);

	_preApplyAction();

	for (auto const &w: _checkBoxWidgets) {
		if (_applyIds)
			vec = w->getCheckedIds();
		else
			vec = w->getStates();
		emit apply(w->sd(), vec);
	}

	_postApplyAction();
}

/**
 * @brief Create KsCheckBoxTable.
 *
 * @param parent: The parent of this widget.
 */
KsCheckBoxTable::KsCheckBoxTable(QWidget *parent)
: QTableWidget(parent)
{
	setShowGrid(false);
	horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
	horizontalHeader()->setStretchLastSection(true);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setEditTriggers(QAbstractItemView::NoEditTriggers);
	setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	verticalHeader()->setVisible(false);

	connect(this, &QTableWidget::cellDoubleClicked,
		this, &KsCheckBoxTable::_doubleClicked);
}

/**
 * @brief Initialize the table.
 *
 * @param headers: The headers of the individual columns.
 * @param size: The number of rows.
 */
void KsCheckBoxTable::init(QStringList headers, int size)
{
	QHBoxLayout *cbLayout;
	QWidget *cbWidget;

	setColumnCount(headers.count());
	setRowCount(size);
	setHorizontalHeaderLabels(headers);

	_cb.resize(size);

	for (int i = 0; i < size; ++i) {
		cbWidget = new QWidget();
		_cb[i] = new QCheckBox(cbWidget);
		cbLayout = new QHBoxLayout(cbWidget);

		cbLayout->addWidget(_cb[i]);
		cbLayout->setAlignment(Qt::AlignCenter);
		cbLayout->setContentsMargins(0, 0, 0, 0);

		cbWidget->setLayout(cbLayout);
		setCellWidget(i, 0, cbWidget);
	}
}

/** Reimplemented event handler used to receive key press events. */
void KsCheckBoxTable::keyPressEvent(QKeyEvent *event)
{
	if (event->key() == Qt::Key_Return) {
		for (auto &s: selectedItems()) {
			if (s->column() == 1)
				emit changeState(s->row());
		}
	}

	QApplication::processEvents();
	QTableWidget::keyPressEvent(event);
}

/** Reimplemented event handler used to receive mouse press events. */
void KsCheckBoxTable::mousePressEvent(QMouseEvent *event)
{
	if (event->button() == Qt::RightButton) {
		for (auto &i: selectedItems())
			i->setSelected(false);

		return;
	}

	QApplication::processEvents();
	QTableWidget::mousePressEvent(event);
}

void KsCheckBoxTable::_doubleClicked(int row, int col)
{
	emit changeState(row);
	for (auto &i: selectedItems())
		i->setSelected(false);
}

/**
 * @brief Create KsCheckBoxTableWidget.
 *
 * @param sd: Data stream identifier.
 * @param name: The name of this widget.
 * @param parent: The parent of this widget.
 */
KsCheckBoxTableWidget::KsCheckBoxTableWidget(int sd, const QString &name,
					     QWidget *parent)
: KsCheckBoxWidget(sd, name, parent),
  _table(this)
{
	connect(&_table,	&KsCheckBoxTable::changeState,
		this,		&KsCheckBoxTableWidget::_changeState);
}

/** Initialize the KsCheckBoxTable and its layout. */
void KsCheckBoxTableWidget::_initTable(QStringList headers, int size)
{
	_table.init(headers, size);

	for (auto const & cb: _table._cb) {
		connect(cb,	&QCheckBox::clicked,
			this,	&KsCheckBoxTableWidget::_update);
	}

	_cbLayout.setContentsMargins(1, 1, 1, 1);
	_cbLayout.addWidget(&_table);
}

/** Adjust the size of this widget according to its content. */
void KsCheckBoxTableWidget::_adjustSize()
{
	int width;

	_table.setVisible(false);
	_table.resizeColumnsToContents();
	_table.setVisible(true);

	width = _table.horizontalHeader()->length() +
		FONT_WIDTH * 3 +
		style()->pixelMetric(QStyle::PM_ScrollBarExtent);

	_cbWidget.resize(width, _cbWidget.height());

	setMinimumWidth(_cbWidget.width() +
			_cbLayout.contentsMargins().left() +
			_cbLayout.contentsMargins().right() +
			_topLayout.contentsMargins().left() +
			_topLayout.contentsMargins().right());
}

void  KsCheckBoxTableWidget::_update(bool state)
{
	/* If a Checkbox is being unchecked. Unchecked "all" as well. */
	if (!state)
		_allCb.setCheckState(Qt::Unchecked);
}

void KsCheckBoxTableWidget::_changeState(int row)
{
	if (_table._cb[row]->checkState() == Qt::Checked)
		_table._cb[row]->setCheckState(Qt::Unchecked);
	else
		_table._cb[row]->setCheckState(Qt::Checked);

	_allCb.setCheckState(Qt::Checked);
	for (auto &c: _table._cb) {
		if (c->checkState() == Qt::Unchecked) {
			_allCb.setCheckState(Qt::Unchecked);
			break;
		}
	}
}

static void update_r(QTreeWidgetItem *item, Qt::CheckState state)
{
	int n;

	item->setCheckState(0, state);

	n = item->childCount();
	for (int i = 0; i < n; ++i)
		update_r(item->child(i), state);
}

/**
 * @brief Create KsCheckBoxTree.
 *
 * @param parent: The parent of this widget.
 */
KsCheckBoxTree::KsCheckBoxTree(QWidget *parent)
: QTreeWidget(parent)
{
	setColumnCount(2);
	setHeaderHidden(true);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

	connect(this, &KsCheckBoxTree::itemDoubleClicked,
		this, &KsCheckBoxTree::_doubleClicked);
}

/** Reimplemented event handler used to receive key press events. */
void KsCheckBoxTree::keyPressEvent(QKeyEvent *event)
{
	if (event->key() == Qt::Key_Return) {
		/* Loop over all selected child items and change
		* there states. */
		for (auto &s: selectedItems()) {
			if(s->childCount()) {
				if (s->isExpanded())
					continue;
			}

			if (s->checkState(0) == Qt::Unchecked)
				s->setCheckState(0, Qt::Checked);
			else
				s->setCheckState(0, Qt::Unchecked);

			if(s->childCount()) {
				update_r(s, s->checkState(0));
			}
		}
	}

	emit verify();
	QTreeWidget::keyPressEvent(event);
}

void KsCheckBoxTree::_doubleClicked(QTreeWidgetItem *item, int col)
{
	if (item->checkState(0) == Qt::Unchecked)
		item->setCheckState(0, Qt::Checked);
	else
		item->setCheckState(0, Qt::Unchecked);

	for (auto &i: selectedItems())
		i->setSelected(false);

	emit itemClicked(item, col);
}

/** Reimplemented event handler used to receive mouse press events. */
void KsCheckBoxTree::mousePressEvent(QMouseEvent *event)
{
	if (event->button() == Qt::RightButton) {
		for (auto &i: selectedItems())
			i->setSelected(false);
		return;
	}

	QApplication::processEvents();
	QTreeWidget::mousePressEvent(event);
}

/**
 * @brief Create KsCheckBoxTreeWidget.
 *
 * @param name: The name of this widget.
 * @param sd: Data stream identifier.
 * @param parent: The parent of this widget.
 */
KsCheckBoxTreeWidget::KsCheckBoxTreeWidget(int sd, const QString &name,
					   QWidget *parent)
: KsCheckBoxWidget(sd, name, parent),
  _tree(this)
{
	connect(&_tree,	&KsCheckBoxTree::verify,
		this,	&KsCheckBoxTreeWidget::_verify);
}

/** Initialize the KsCheckBoxTree and its layout. */
void KsCheckBoxTreeWidget::_initTree()
{
	_tree.setSelectionMode(QAbstractItemView::MultiSelection);

	connect(&_tree, &QTreeWidget::itemClicked,
		this,	&KsCheckBoxTreeWidget::_update);

	_cbLayout.setContentsMargins(1, 1, 1, 1);
	_cbLayout.addWidget(&_tree);
}

/** Adjust the size of this widget according to its content. */
void KsCheckBoxTreeWidget::_adjustSize()
{
	int width, n = _tree.topLevelItemCount();

	if (n == 0)
		return;

	for (int i = 0; i < n; ++i)
		_tree.topLevelItem(i)->setExpanded(true);

	_tree.resizeColumnToContents(0);
	if (_tree.topLevelItem(0)->child(0)) {
		width = _tree.visualItemRect(_tree.topLevelItem(0)->child(0)).width();
	} else {
		width = _tree.visualItemRect(_tree.topLevelItem(0)).width();
	}

	width += FONT_WIDTH * 3 + style()->pixelMetric(QStyle::PM_ScrollBarExtent);
	_cbWidget.resize(width, _cbWidget.height());

	for (int i = 0; i < n; ++i)
		_tree.topLevelItem(i)->setExpanded(false);

	setMinimumWidth(_cbWidget.width() +
			_cbLayout.contentsMargins().left() +
			_cbLayout.contentsMargins().right() +
			_topLayout.contentsMargins().left() +
			_topLayout.contentsMargins().right());
}

void KsCheckBoxTreeWidget::_update(QTreeWidgetItem *item, int column)
{
	/* Get the new state of the item. */
	Qt::CheckState state = item->checkState(0);

	/* Recursively update all items below this one. */
	update_r(item, state);

	/*
	 * Update all items above this one including the "all"
	 * check box.
	 */
	_verify();
}

void KsCheckBoxTreeWidget::_verify()
{
	/*
	 * Set the state of the top level items according to the
	 * state of the childs.
	 */
	QTreeWidgetItem *topItem, *childItem;

	for(int t = 0; t < _tree.topLevelItemCount(); ++t) {
		topItem = _tree.topLevelItem(t);
		if (topItem->childCount() == 0)
			continue;

		topItem->setCheckState(0, Qt::Checked);
		for (int c = 0; c < topItem->childCount(); ++c) {
			childItem = topItem->child(c);
			if (childItem->checkState(0) == Qt::Unchecked)
				topItem->setCheckState(0, Qt::Unchecked);
		}
	}

	_allCb.setCheckState(Qt::Checked);
	for (auto &c: _cb) {
		if (c->checkState(0) == Qt::Unchecked) {
			_allCb.setCheckState(Qt::Unchecked);
			break;
		}
	}
}

/**
 * @brief Create KsCPUCheckBoxWidget.
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param parent: The parent of this widget.
 */
KsCPUCheckBoxWidget::KsCPUCheckBoxWidget(kshark_data_stream *stream, QWidget *parent)
: KsCheckBoxTreeWidget(stream->stream_id, "CPUs", parent)
{
	int height(FONT_HEIGHT * 1.5);
	KsPlot::ColorTable colors;
	QString style;

	style = QString("QTreeView::item { height: %1 ;}").arg(height);
	_tree.setStyleSheet(style);

	_initTree();

	_id.resize(stream->n_cpus);
	_cb.resize(stream->n_cpus);
	colors = KsPlot::getCPUColorTable();

	for (int i = 0; i < stream->n_cpus; ++i) {
		QTreeWidgetItem *cpuItem = new QTreeWidgetItem;
		cpuItem->setText(0, "  ");
		cpuItem->setText(1, QString("CPU %1").arg(i));
		cpuItem->setCheckState(0, Qt::Checked);
		cpuItem->setBackgroundColor(0, QColor(colors[i].r(),
						      colors[i].g(),
						      colors[i].b()));
		_tree.addTopLevelItem(cpuItem);
		_id[i] = i;
		_cb[i] = cpuItem;
	}

	_adjustSize();
}

/**
 * @brief Create KsEventsCheckBoxWidget.
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param parent: The parent of this widget.
 */
KsEventsCheckBoxWidget::KsEventsCheckBoxWidget(kshark_data_stream *stream,
					       QWidget *parent)
: KsCheckBoxTreeWidget(stream->stream_id, "Events", parent)
{
	int *eventIds = kshark_get_all_event_ids(stream);

	if(!eventIds)
		return;

	switch (stream->format) {
	case KS_TEP_DATA:
		_makeTepEventItems(stream, eventIds);
		return;

	default:
		_makeItems(stream, eventIds);
		return;
	}
}

void KsEventsCheckBoxWidget::_makeItems(kshark_data_stream *stream,
					int *eventIds)
{
	QTreeWidgetItem *evtItem;
	QString evtName;
	kshark_entry entry;

	_initTree();
	_tree.setColumnWidth(0, 30 * FONT_WIDTH);
	_id.resize(stream->n_events);
	_cb.resize(stream->n_events);

	entry.stream_id = stream->stream_id;
	entry.visible = 0xff;
	for (int i = 0; i < stream->n_events; ++i) {
		entry.event_id = _id[i] = eventIds[i];
		evtName = kshark_get_event_name(&entry);

		evtItem = new QTreeWidgetItem;
		evtItem->setText(0, evtName);
		evtItem->setCheckState(0, Qt::Checked);
		evtItem->setFlags(evtItem->flags() |
				  Qt::ItemIsUserCheckable);
		_tree.addTopLevelItem(evtItem);
		_cb[i] = evtItem;
	}
}

void KsEventsCheckBoxWidget::_makeTepEventItems(kshark_data_stream *stream,
						int *eventIds)
{
	QTreeWidgetItem *sysItem, *evtItem;
	QString sysName, evtName;
	QStringList name;
	int i(0);

	_initTree();
	_id.resize(stream->n_events);
	_cb.resize(stream->n_events);
	while (i < stream->n_events) {
		name = KsUtils::getTepEvtName(stream->stream_id,
					      eventIds[i]);
		sysName = name[0];
		sysItem = new QTreeWidgetItem;
		sysItem->setText(0, sysName);
		sysItem->setCheckState(0, Qt::Checked);
		_tree.addTopLevelItem(sysItem);

		while (sysName == name[0]) {
			evtName = name[1];
			evtItem = new QTreeWidgetItem;
			evtItem->setText(0, evtName);
			evtItem->setCheckState(0, Qt::Checked);
			evtItem->setFlags(evtItem->flags() |
					  Qt::ItemIsUserCheckable);

			sysItem->addChild(evtItem);

			_id[i] = eventIds[i];
			_cb[i] = evtItem;
			if (++i == stream->n_events)
				break;

			name = KsUtils::getTepEvtName(stream->stream_id,
						      eventIds[i]);
		}
	}

	_tree.sortItems(0, Qt::AscendingOrder);
	_adjustSize();
}

/**
 * @brief Get a list of all checked events. If the whole system is selected
 *	  (the top level checkbox is checked), only the name of the system is
 *	  added to the list.
 *
 * @param option: If True, "-e" is added as prefix to each element of the list.
 *
 * @returns A list of checked events or systems.
 */
QStringList KsEventsCheckBoxWidget::getCheckedEvents(bool option)
{
	QTreeWidgetItem *sysItem, *evtItem;
	QStringList list;
	QString optStr;
	int nSys, nEvts;

	if (option)
		optStr = "-e";

	nSys = _tree.topLevelItemCount();
	for(int t = 0; t < nSys; ++t) {
		sysItem = _tree.topLevelItem(t);
		if (sysItem->checkState(0) == Qt::Checked) {
			list << optStr + sysItem->text(0);
		} else {
			nEvts = sysItem->childCount();
			for (int c = 0; c < nEvts; ++c) {
				evtItem = sysItem->child(c);
				if (evtItem->checkState(0) == Qt::Checked) {
					list << optStr +
						sysItem->text(0) +
						":" +
						evtItem->text(0);
				}
			}
		}
	}

	return list;
}

/** Remove a System from the Checkbox tree. */
void KsEventsCheckBoxWidget::removeSystem(QString name) {
	auto itemList = _tree.findItems(name, Qt::MatchFixedString, 0);
	int index;

	if (itemList.isEmpty())
		return;

	index = _tree.indexOfTopLevelItem(itemList[0]);
	if (index >= 0)
		_tree.takeTopLevelItem(index);
}

/**
 * @brief Create KsTasksCheckBoxWidget.
 *
 * @param stream: Input location for a Trace data stream pointer.
 * @param cond: If True make a "Show Task" widget. Otherwise make "Hide Task".
 * @param parent: The parent of this widget.
 */
KsTasksCheckBoxWidget::KsTasksCheckBoxWidget(kshark_data_stream *stream,
					     bool cond, QWidget *parent)
: KsCheckBoxTableWidget(stream->stream_id, "Tasks", parent),
  _cond(cond)
{
	QTableWidgetItem *pidItem, *comItem;
	KsPlot::ColorTable colors;
	QStringList headers;
	kshark_entry entry;
	const char *comm;
	int nTasks, pid;

	if (_cond)
		headers << "Show" << "Pid" << "Task";
	else
		headers << "Hide" << "Pid" << "Task";

	_id = KsUtils::getPidList(stream->stream_id);
	nTasks = _id.count();
	_initTable(headers, nTasks);
	colors = KsPlot::getTaskColorTable();
	entry.stream_id = stream->stream_id;
	entry.visible = 0xff;
	for (int i = 0; i < nTasks; ++i) {
		entry.pid = pid = _id[i];
		pidItem = new QTableWidgetItem(tr("%1").arg(pid));
		_table.setItem(i, 1, pidItem);

		comm = kshark_get_task(&entry);

		comItem = new QTableWidgetItem(tr(comm));

		pidItem->setBackgroundColor(QColor(colors[pid].r(),
						   colors[pid].g(),
						   colors[pid].b()));

		if (_id[i] == 0)
			pidItem->setTextColor(Qt::white);

		_table.setItem(i, 2, comItem);
	}

	_adjustSize();
}

/**
 * @brief Create KsPluginCheckBoxWidget.
 *
 * @param sd: Data stream identifier.
 * @param pluginList: A list of plugin names.
 * @param parent: The parent of this widget.
 */
KsPluginCheckBoxWidget::KsPluginCheckBoxWidget(int sd, QStringList pluginList,
					       QWidget *parent)
: KsCheckBoxTableWidget(sd, "Manage plugins", parent)
{
	QTableWidgetItem *nameItem, *infoItem;
	QStringList headers;
	int nPlgins;

	headers << "Load" << "Name" << "Info";

	nPlgins = pluginList.count();
	_initTable(headers, nPlgins);
	_id.resize(nPlgins);

	for (int i = 0; i < nPlgins; ++i) {
		if (pluginList[i] < 30) {
			nameItem = new QTableWidgetItem(pluginList[i]);
		} else {
			QLabel l;
			KsUtils::setElidedText(&l, pluginList[i],
					       Qt::ElideLeft,
					       FONT_WIDTH * 30);
			nameItem = new QTableWidgetItem(l.text());
		}

		_table.setItem(i, 1, nameItem);
		infoItem = new QTableWidgetItem(" -- ");
		_table.setItem(i, 2, infoItem);
		_id[i] = i;
	}

	_adjustSize();
}

void KsPluginCheckBoxWidget::setInfo(int row, QString info)
{
	QTableWidgetItem *infoItem = _table.item(row, 2);
	infoItem->setText(info);
}

void KsPluginCheckBoxWidget::setActive(QVector<int> rows, bool a)
{
	for (auto const &r: rows) {
		QTableWidgetItem *infoItem = _table.item(r, 2);
		if (a) {
			infoItem->setText("- Active");
			infoItem->setForeground(QBrush(QColor(0, 220, 80)));
		} else {
			infoItem->setText("- Not Active");
			infoItem->setForeground(QBrush(QColor(255, 50, 50)));
		}
	}
}

void KsPluginsCheckBoxDialog::_postApplyAction()
{
	emit _data->updateWidgets(_data);
}

KsDStreamCheckBoxWidget::KsDStreamCheckBoxWidget(QWidget *parent)
: KsCheckBoxTableWidget(-1, "Select Data stream", parent)
{
	kshark_context *kshark_ctx(nullptr);
	kshark_data_stream *stream;
	QTableWidgetItem *nameItem;
	int *streamIds, nStreams;
	QStringList headers;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);
	nStreams = kshark_ctx->n_streams;

	headers << "Apply" << "To stream";
	_initTable(headers, nStreams);
	_id.resize(nStreams);

	for (int i = 0; i < nStreams; ++i) {
		stream = kshark_ctx->stream[streamIds[i]];
		QString name(stream->file);
		if (name < 40) {
			nameItem = new QTableWidgetItem(name);
		} else {
			QLabel l;
			KsUtils::setElidedText(&l, name,
					       Qt::ElideLeft,
					       FONT_WIDTH * 40);
			nameItem = new QTableWidgetItem(l.text());
		}

		_table.setItem(i, 1, nameItem);
		_id[i] = stream->stream_id;
	}

	_adjustSize();
	free(streamIds);
}


KsEventFieldSelectWidget::KsEventFieldSelectWidget(QWidget *parent)
: QWidget(parent),
  _streamLabel("Data stream", this),
  _eventLabel("Event (type in for searching)", this),
  _fieldLabel("Field", this)
{
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

	setLayout(&_topLayout);
}

void KsEventFieldSelectWidget::setStreamCombo()
{
	kshark_context *kshark_ctx(NULL);
	kshark_data_stream *stream;
	int sd, *streamIds;

	if (!kshark_instance(&kshark_ctx))
		return;

	streamIds = kshark_all_streams(kshark_ctx);

	for (int i = 0; i < kshark_ctx->n_streams; ++i) {
		sd = streamIds[i];
		stream = kshark_ctx->stream[sd];
		if (_streamComboBox.findData(sd) < 0)
			_streamComboBox.addItem(QString(stream->file), sd);
	}
	free(streamIds);
}

void KsEventFieldSelectWidget::_streamChanged(const QString &streamFile)
{
	int sd = _streamComboBox.currentData().toInt();
	kshark_context *kshark_ctx(NULL);
	kshark_data_stream *stream;
	kshark_entry entry;
	QStringList evtsList;
	int *eventIds;
	char *buff;

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
		buff = kshark_get_event_name(&entry);
		evtsList << QString(buff);
		free(buff);
	}

	free(eventIds);

	std::sort(evtsList.begin(), evtsList.end());
	_eventComboBox.addItems(evtsList);
}

void KsEventFieldSelectWidget::_eventChanged(const QString &eventName)
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

	free(fields);

	std::sort(fieldsList.begin(), fieldsList.end());

	_fieldComboBox.addItems(fieldsList);
}

}; // KsWidgetsLib
