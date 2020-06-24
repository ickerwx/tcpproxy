#!/usr/bin/env python
import sys,time
from PyQt5.QtWidgets import QApplication, QTableWidget, QTableWidgetItem, QHBoxLayout, QSplitter, QFrame, QVBoxLayout, QMainWindow, QTextEdit, QPlainTextEdit, QAction, QWidget, qApp, QFileDialog, QTabWidget, QPushButton, QToolBar, QHeaderView

from PyQt5.QtGui import QIcon, QColor, QBrush, QPalette
from PyQt5.QtCore import Qt, pyqtSlot, QThread, pyqtSignal

from tcpproxy_cli import TCPProxyClient
import redis,json,base64,hexdump,re
import difflib

class TCPProxyPaneConvs(QTableWidget):
    fields = [ "src", "dst",  "dstport", "packets", "bytes" , "hostname", "tags" ]
    signal = pyqtSignal('PyQt_PyObject')
    
    def __init__(self):
        super().__init__()
        self.initUI(("Source","Destination","Port","Packets","Bytes","Hostname","Tags"))
        
    def initUI(self, headers):
        self.setColumnCount(len(headers))
        self.setRowCount(0)
        self.setSortingEnabled(True)
        self.setWordWrap(False)
        self.setHorizontalHeaderLabels(headers)
        
        self.doubleClicked.connect(self.on_click)

    def load(self, convs):
        self.setRowCount(len(convs))
        i = 0
        for conv in convs:
            self.setConv(i,conv)
            i += 1
            
        self.horizontalHeader().resizeSections(QHeaderView.ResizeToContents)
    
    bytes = {}
    packets = {}
    
    def getHash(self, conv):
        return "/".join([conv["src"],conv["dst"],conv["dstport"],conv["hostname"],conv["tags"]])
    
    def decode(self, conv):
        for field in self.fields:
            if isinstance(conv[field], bytes):
                conv[field] = conv[field].decode("utf-8")
            elif isinstance(conv[field], int):
                conv[field] = str(conv[field])
            elif isinstance(conv[field], list):
                if len(conv[field]) > 0:
                    if isinstance(conv[field][0], bytes):
                        conv[field] = b" ".join(conv[field]).decode("utf-8")
                    else:
                        conv[field] = " ".join(conv[field])
                else:
                    conv[field] = ""
        return conv

    def setConv(self, index, conv):
        print("SetConv:")
        print(conv)
        conv = self.decode(conv)
        i = 0
        for field in self.fields:
            # IF int, set item as numeric for better sorting
            if field in ["dstport", "packets", "bytes"]:
                print(conv)
                item = QTableWidgetItem()
                item.setData(Qt.EditRole, int(conv[field]))
                self.setItem(index, i, item)
            else:
                self.setItem(index, i, QTableWidgetItem(conv[field]))
            self.item(index,i).setFlags(self.item(index,i).flags() & ~Qt.ItemIsEditable)
            i += 1
        
        hash = self.getHash(conv)
        self.packets[hash] = self.item(index,3)
        self.bytes[hash] = self.item(index,4)
    
    def clear(self):
        self.bytes = {}
        self.packets = {}
        self.setRowCount(0)
    
    def getDataSize(self, msg):
        return len(base64.b64decode(msg["data"]))

    def add(self, msg):
        if not msg["hostname"]:
           msg["hostname"] = "undefined"
        msg["packets"] = "0"
        msg["bytes"] = "0"
        msg = self.decode(msg)
        hash = self.getHash(msg)
        if hash not in self.bytes:
            i = self.rowCount()
            self.setRowCount(i + 1)
            self.setConv(i, msg)
        
        try:
            nbpackets = int(self.packets[hash].text())
            self.packets[hash].setText(str(nbpackets + 1))
            nbbytes = int(self.bytes[hash].text())
            self.bytes[hash].setText(str(nbbytes + self.getDataSize(msg)))
        except Exception as ex:
            print("Dont crash: exception when trying to manipulate QT object for hash %s: %s" % (hash, ex.__str__()))


    @pyqtSlot()
    def on_click(self):
        for item in self.selectedItems():
            key = self.fields[item.column()]
            data = item.text()
            self.signal.emit((key, data))
            item.setSelected(False)
            self.setColumnBackground(item.column(), QBrush(QColor(250,218,94)),data)
            
    def setColumnBackground(self, column, brush, filter = None):
        for i in range (0, self.rowCount()):
            if not filter or filter == self.item(i, column).text():
                self.item(i, column).setBackground(brush)
                
    def clearBackground(self, column = -1):
        if column >= 0:
            for i in range (0, self.rowCount()):
                self.item(i, column).setBackground(QBrush(QColor(255,255,255)))
        else:
            for i in range (0, self.columnCount()-1):
                self.clearBackground(i)

class DebugThread(QThread):
    signal = pyqtSignal('PyQt_PyObject')
    
    def __init__(self, hostname):
        self.running = False 
        self.hostname = hostname
        self.client = TCPProxyClient(self.hostname)
        QThread.__init__(self)
        
    def run(self):
        self.running = True
        self.client.register_debug()
        while self.running:
            try:
                for msg in self.client.debug_iter(timeout=1):
                    self.signal.emit(msg)
            except redis.exceptions.ConnectionError as ex:
                print("Error connecting to Redis")
                print(ex)
                time.sleep(10)
                self.client = TCPProxyClient(self.hostname)
                self.client.register_debug()

class InspectThread(QThread):
    signal = pyqtSignal('PyQt_PyObject')
    
    def __init__(self, hostname):
        self.running = False 
        self.hostname = hostname
        self.client = TCPProxyClient(self.hostname)
        QThread.__init__(self)
        
    def run(self):
        self.running = True
        self.client.register_inspect()
        while self.running:
            try:
                for msg in self.client.inspect_iter(timeout=1):
                    self.signal.emit(msg)
            except redis.exceptions.ConnectionError as ex:
                print("Error connecting to Redis")
                print(ex)
                time.sleep(10)
                self.client = TCPProxyClient(self.hostname)
                self.client.register_inspect()

class TCPProxyPaneFile(QTableWidget):
    
    fields = [ "key", "encoding",  "data" ]

    def __init__(self, filetype="root"):
        super().__init__()
        self.initUI(("Redis Key", "Encoding", "Data"))
        self.filetype = filetype
        
    def initUI(self, headers):
        self.setColumnCount(len(headers))
        self.setRowCount(0)
        self.setWordWrap(False)

        self.setHorizontalHeaderLabels(headers)
        
    def load(self, dataset):
        self.setRowCount(len(dataset))
        i = 0
        for item in dataset:
            self.setDataItem(i,item)
            i += 1
            
        self.horizontalHeader().resizeSections(QHeaderView.ResizeToContents)
    
    def setDataItem(self, index, data):
        i=0
        for field in self.fields:
            if field == "data":
                text = self.decodeDataHeader(data)
                self.setItem(index, i, QTableWidgetItem(text))
            else:
                self.setItem(index, i, QTableWidgetItem(data[field]))
            i += 1

    def decodeDataHeader(self, data):
        if data["encoding"] in ["x509", "text"]:
            data = data["data"].decode("utf-8")
            data = data.split("\n")[0]
            return data
        elif data["encoding"] in ["base64"]:
            data = base64.b64decode(data["data"])
            data = data.split(b"\n")[0]
            return data.decode("utf-8")
        else:
            return ""
    
    def add(self):
        row = self.rowCount()
        self.setRowCount(row + 1)

        self.setDataItem(row, { "key":"temp","encoding":"base64","data":"" })
        
    def getSelectedKey(self):
        for item in self.selectedItems():
            row = item.row()
            key = self.item(row, 0).text()
            if self.filetype == "root":
                return key
            else:
                encoding = self.item(row, 1).text()
                return self.filetype + ":" + encoding +":" + key
    
    def setRule(self, index, rule):
        i=0
        for field in self.fields[0:6]:
            self.setItem(index, i, QTableWidgetItem(str(rule[field])))
            i += 1
            
        self.setItem(index, i, QTableWidgetItem(" ".join(rule["rules"])))
        
class TCPProxyPaneData(QTableWidget):
    
    fields = [ "id", "level", "src", "srcport", "c2s", "dst", "dstport","hostname","tags","data" ]
    
    def __init__(self):
        super().__init__()
        self.initUI(("Id", "Level", "Source","Port","Dir","Destination","Port","Hostname","Tags","Data"))
        
    def initUI(self, headers):
        self.setColumnCount(len(headers))
        self.setRowCount(0)
        self.setWordWrap(False)
        self.setSortingEnabled(True)

        self.setHorizontalHeaderLabels(headers)

    def add(self, data, i):
        self.setRowCount(self.rowCount() + 1)
        self.setData(self.rowCount()-1, data, i)
        
    def resize(self):
        self.horizontalHeader().resizeSections(QHeaderView.ResizeToContents)
        
    def setIntItem(self, index, i, value):
        item = QTableWidgetItem()
        item.setData(Qt.EditRole, int(value))
        self.setItem(index, i, item)

    def setData(self, index, data, id):
        if "level" not in data:
            data["level"] = "DEBUG"
            
        ifield=0
        for field in self.fields:
            if field == "id":
                self.setIntItem(index, ifield, id)
            elif field == "c2s":
                self.setItem(index, ifield, QTableWidgetItem("<" if "c2s" in data and data["c2s"] else ">"))
            elif field == "data":
                unidata = ""
                try:
                    if field in data:
                        rawdata = base64.b64decode(data[field])
                        rawdata = rawdata.split(b"\n")[0]
                        unidata = rawdata.decode("utf-8")
                except UnicodeDecodeError as ex:
                    print ("Cannot decode data to unicode:"+ex.__str__())
                self.setItem(index, ifield, QTableWidgetItem(unidata))
            elif isinstance(data[field], int):
                self.setIntItem(index, ifield, data[field])
            else:
                self.setItem(index, ifield, QTableWidgetItem(data[field]))
            
            self.item(index,ifield).setFlags(self.item(index,ifield).flags() & ~Qt.ItemIsEditable)
            
            ifield += 1

        if data["level"] in ["INFO"]:
            self.item(index, 1).setBackground(QBrush(QColor(250,218,94)))
        elif data["level"] in ["WARNING"]:
            self.item(index, 1).setBackground(QBrush(QColor(255,165,0)))
        elif data["level"] in ["ERROR"]:
            self.item(index, 1).setBackground(QBrush(QColor(255,69,0)))
        elif data["level"] in ["INSPECT"]:
            self.item(index, 1).setBackground(QBrush(QColor(192,192,192)))
        elif data["level"] in ["INSPECTED"]:
            self.item(index, 1).setBackground(QBrush(QColor(0,204,102)))

class TCPProxyPaneRules(QTableWidget):
    
    fields = ["src", "dst", "hostname", "dstport", "c2s", "s2c", "rules"]
    
    def __init__(self):
        super().__init__()
        self.initUI(("Source", "Dest","Hostname","Port","C2S","S2C","Rules"))
        
    def initUI(self, headers):
        self.setColumnCount(len(headers))
        self.setRowCount(0)
        self.setWordWrap(False)

        self.setHorizontalHeaderLabels(headers)
        
        self.doubleClicked.connect(self.on_click)
        
    def load(self, rules):
        self.setRowCount(len(rules))
        i = 0
        for rule in rules:
            self.setRule(i,rule)
            i += 1
            
        self.horizontalHeader().resizeSections(QHeaderView.ResizeToContents)

    def add(self):
        row = None
        for item in self.selectedItems():
            row = item.row() + 1
            self.insertRow(row)
            break
            
        if row == None:
            row = self.rowCount()
            self.setRowCount(row + 1)

        self.setRule(row, { "src":".*","dst":".*","hostname":"None","dstport":"0-65535","c2s":"True","s2c":"True","rules":["stats"] })
        self.horizontalHeader().resizeSections(QHeaderView.ResizeToContents)
    
    def setRule(self, index, rule):
        i=0
        for field in self.fields[0:6]:
            #if field not in rule:
            #    self.setItem(index, i, QTableWidgetItem(str(".*")))
            #else:
            self.setItem(index, i, QTableWidgetItem(str(rule[field])))
            i += 1
            
        self.setItem(index, i, QTableWidgetItem(" ".join(rule["rules"])))
        
    def getRule(self, index):
        rule = {}
        i = 0
        for field in self.fields:
            rule[field] = self.item(index, i).text()
            if rule[field] == "None":
                rule[field] = None
            elif rule[field] in ["True", "False"]:
                rule[field] = rule[field] == "True"
            elif field == "rules":
                rule[field] = rule[field].split(" ")
            i += 1
            
        return rule

    def getRules(self):
        rules = []
        for i in  range(0, self.rowCount()):
            rules.append(self.getRule(i))
            
        return rules
        
    def delete(self):
        for item in self.selectedItems():
            row = item.row()
            self.removeRow(row)
            break
        
    @pyqtSlot()
    def on_click(self):
        pass
    
class TCPProxyPanes(QWidget):
    def __init__(self):
        super().__init__()        
        self.initUI()
        
    def initUI(self):
        hbox = QHBoxLayout(self)

        self.convs = TCPProxyPaneConvs()
        self.convs.setFrameShape(QFrame.StyledPanel)
 
        self.tab_stats = QTabWidget()
        self.tab_stats.insertTab(0, self.convs, "Conversations")
 
        self.rules = TCPProxyPaneRules()
        self.rules.setFrameShape(QFrame.StyledPanel)
        
        self.modules = QTextEdit()
        self.modules.setFrameShape(QFrame.StyledPanel)

        self.files = TCPProxyPaneFile("file")
        self.files.setFrameShape(QFrame.StyledPanel)
        
        self.certs = TCPProxyPaneFile("root")
        self.certs.setFrameShape(QFrame.StyledPanel)
        
        self.tab_settings = QTabWidget()
        self.tab_settings.insertTab(0, self.rules, "Rules")
        self.tab_settings.insertTab(1, self.modules, "Modules")
        self.tab_settings.insertTab(2, self.files, "Files")
        self.tab_settings.insertTab(2, self.certs, "Certs")

        self.data = TCPProxyPaneData()
        self.data.setFrameShape(QFrame.StyledPanel)
        
        self.tab_msg = QTabWidget()
        
        self.strmsg = QPlainTextEdit()
        self.strmsg.setFrameShape(QFrame.StyledPanel)
        self.strmsg.blockSignals(True)
        font = self.strmsg.font()
        font.setFamily("Courier New")
        self.strmsg.setFont(font)
        self.tab_msg.insertTab(0, self.strmsg, "String")
        
        self.hexmsg = QPlainTextEdit()
        self.hexmsg.setFrameShape(QFrame.StyledPanel)
        self.hexmsg.blockSignals(True)
        font = self.hexmsg.font()
        font.setFamily("Courier New")
        self.hexmsg.setFont(font)
        self.tab_msg.insertTab(1, self.hexmsg, "Hex")

        self.gzipmsg = QPlainTextEdit()
        self.gzipmsg.setFrameShape(QFrame.StyledPanel)
        self.gzipmsg.blockSignals(True)
        font = self.gzipmsg.font()
        font.setFamily("Courier New")
        self.gzipmsg.setFont(font)
        self.tab_msg.insertTab(2, self.gzipmsg, "Gzip Decode")

        splitter1 = QSplitter(Qt.Horizontal)
        splitter1.addWidget(self.tab_stats)
        splitter1.addWidget(self.tab_settings)

        splitter2 = QSplitter(Qt.Vertical)
        splitter2.addWidget(splitter1)

        splitter3 = QSplitter(Qt.Vertical)
        splitter3.addWidget(splitter2)
        splitter3.addWidget(self.data)
        splitter3.addWidget(self.tab_msg)

        hbox.addWidget(splitter3)
        self.setLayout(hbox)

class TCPProxyApp(QMainWindow):
    def __init__(self, argv):
        super().__init__()
        
        if len(sys.argv) > 1:
            self.tcpproxy_host = sys.argv[1]
        else:
            self.tcpproxy_host = "127.0.0.1"
            
        self.tcpproxy = None
        self.debugger = None
        self.data = []
        self.data_filter = {}
        self.selected_widget = None
        self.selected_rawdata = None

        self.initUI()
        
    def initUI(self):
        
        self.menubar = self.menuBar()
        self.statusBar().showMessage('Not connected')
        
        self.panes = TCPProxyPanes()
        
        self.initMenuData()
        self.initMenuRules()
        self.initMenuStats()
        self.initMenuActions()
        
        self.setCentralWidget(self.panes)
        
        self.resize(800,600)
        self.setWindowTitle("TCPProxy GUI")
        
        self.setWindowIcon(QIcon('icons/tcpproxy.png'))
        
        self.show()

    def initMenuData(self):
        self.panes.data.itemSelectionChanged.connect(self.on_data_selected)
        
        menu = self.menubar.addMenu('&Data')
        toolbar = self.addToolBar('Data')

        connAct = QAction(QIcon('icons/conn.png'), '&Connect', self)
        connAct.setStatusTip('Connect to Redis DB')
        connAct.triggered.connect(self.on_connect)

        dconnAct = QAction(QIcon('icons/disconn.png'), '&Disconnect', self)
        dconnAct.setStatusTip('Disconnect debugger')
        dconnAct.triggered.connect(self.on_disconnect_debugger)

        clearAct = QAction(QIcon('icons/trash.png'), '&Clear', self)
        clearAct.setStatusTip('Clear debugger data')
        clearAct.triggered.connect(self.on_clear_data)

        saveAct = QAction(QIcon('icons/save.png'), '&Save data to file', self)
        saveAct.setStatusTip('Save debugger data')
        saveAct.triggered.connect(self.on_save_data)

        loadAct = QAction(QIcon('icons/dump.png'), '&Load data file', self)
        loadAct.setStatusTip('Load debugger data')
        loadAct.triggered.connect(self.on_load_data)
        
        saveFilteredinAct = QAction(QIcon('icons/save.png'), '&Save filtered-in data to file', self)
        saveFilteredinAct.setStatusTip('Save filtered-in debugger data')
        saveFilteredinAct.triggered.connect(self.on_save_filteredin_data)

        menu.addAction(connAct)
        toolbar.addAction(connAct)

        menu.addAction(dconnAct)
        toolbar.addAction(dconnAct)

        menu.addAction(clearAct)
        toolbar.addAction(clearAct)
        
        menu.addAction(loadAct)
        toolbar.addAction(loadAct)
        
        menu.addAction(saveAct)
        toolbar.addAction(saveAct)
        menu.addAction(saveFilteredinAct)

    def initMenuStats(self):

        menu = self.menubar.addMenu('&Stats')
        toolbar = self.addToolBar('Stats')

        filterAct = QAction(QIcon('icons/filter.png'), '&Unfilter', self)
        filterAct.setStatusTip('Disable Data Filter')
        filterAct.triggered.connect(self.on_clear_filter)

        reloadAct = QAction(QIcon('icons/reload.png'), '&Reload', self)
        reloadAct.setStatusTip('Reload Conversations')
        reloadAct.triggered.connect(self.on_reload_convs)

        clearAct = QAction(QIcon('icons/trash.png'), '&Clear', self)
        clearAct.setStatusTip('Clear Conversations')
        clearAct.triggered.connect(self.on_clear_convs)

        menu.addAction(reloadAct)
        toolbar.addAction(reloadAct)

        menu.addAction(clearAct)
        toolbar.addAction(clearAct)

        menu.addAction(filterAct)
        toolbar.addAction(filterAct)

        actiontoolbar = QToolBar("Stats", self)
        actiontoolbar.addAction(reloadAct)
        actiontoolbar.addAction(clearAct)
        actiontoolbar.addAction(filterAct)
        
        self.panes.tab_stats.setCornerWidget(actiontoolbar)

    def initMenuActions(self):
        self.panes.certs.itemSelectionChanged.connect(self.on_cert_selected)
        self.panes.files.itemSelectionChanged.connect(self.on_file_selected)
        self.panes.strmsg.textChanged.connect(self.on_strtext_changed)
        self.panes.hexmsg.textChanged.connect(self.on_hextext_changed)

        menu = self.menubar.addMenu('&Actions')
        toolbar = self.addToolBar('Actions')
        
        addCertAct = QAction(QIcon('icons/add.png'), '&Add Cert', self)
        addCertAct.setStatusTip('Add Cert to Redis')
        addCertAct.triggered.connect(self.on_add_cert)

        addFileAct = QAction(QIcon('icons/add.png'), '&Add File', self)
        addFileAct.setStatusTip('Add File to Redis')
        addFileAct.triggered.connect(self.on_add_file)

        menu.addAction(addCertAct)
        toolbar.addAction(addCertAct)
        
        menu.addAction(addFileAct)
        toolbar.addAction(addFileAct)
        
        submitDataAct = QAction(QIcon('icons/commit.png'), '&Commit data to Redis', self)
        submitDataAct.setStatusTip('Submit/Commit data to Redis')
        submitDataAct.triggered.connect(self.on_commit_data)

        menu.addAction(submitDataAct)
        toolbar.addAction(submitDataAct)

        submitDataButton = QPushButton(QIcon('icons/commit.png'), '', self)
        submitDataButton.clicked.connect(self.on_commit_data)
        self.panes.tab_msg.setCornerWidget(submitDataButton)
        
        actiontoolbar = QToolBar("Actions", self)
        reloadItemAction = QAction(QIcon('icons/reload.png'), '&Reload Items', self)
        reloadItemAction.setStatusTip('Reload Items')
        reloadItemAction.triggered.connect(self.on_reload_item)

        addItemAction = QAction(QIcon('icons/add.png'), '&Add Item', self)
        addItemAction.setStatusTip('Add Item')
        addItemAction.triggered.connect(self.on_add_item)

        deleteItemAction = QAction(QIcon('icons/delete.png'), '&Delete Item', self)
        deleteItemAction.setStatusTip('Delete Item')
        deleteItemAction.triggered.connect(self.on_delete_item)

        saveItemAction = QAction(QIcon('icons/commit.png'), '&Save Item', self)
        saveItemAction.setStatusTip('Save Item')
        saveItemAction.triggered.connect(self.on_save_item)

        actiontoolbar.addAction(reloadItemAction)
        actiontoolbar.addAction(addItemAction)
        actiontoolbar.addAction(deleteItemAction)
        actiontoolbar.addAction(saveItemAction)
        
        self.panes.tab_settings.setCornerWidget(actiontoolbar)

    def initMenuRules(self):
        
        self.panes.convs.signal.connect(self.on_filter_added)
        
        menu = self.menubar.addMenu('&Rules')
        toolbar = self.addToolBar('Rules')
        
        reloadAct = QAction(QIcon('icons/reload.png'), '&Reload Rules', self)
        reloadAct.setStatusTip('Reload Rules')
        reloadAct.triggered.connect(self.on_reload_rules)
        
        addAct = QAction(QIcon('icons/add.png'), '&Add Rule', self)
        addAct.setStatusTip('Add Rule')
        addAct.triggered.connect(self.on_add_rule)

        saveAct = QAction(QIcon('icons/commit.png'), '&Commit Rules', self)
        saveAct.setStatusTip('Commit Rules')
        saveAct.triggered.connect(self.on_save_rules)
        
        deleteAct = QAction(QIcon('icons/delete.png'), '&Delete Rule', self)
        deleteAct.setStatusTip('Delete Rule')
        deleteAct.triggered.connect(self.on_delete_rule)

        saveRulesetAct = QAction(QIcon('icons/save.png'), '&Dump ruleset to file', self)
        saveRulesetAct.setStatusTip('Dump rules to file')
        saveRulesetAct.triggered.connect(self.on_dump_ruleset)

        loadRulesetAct = QAction(QIcon('icons/dump.png'), '&Load ruleset from file', self)
        loadRulesetAct.setStatusTip('Load ruleset from file')
        loadRulesetAct.triggered.connect(self.on_load_ruleset)

        menu.addAction(reloadAct)
        toolbar.addAction(reloadAct)
        
        menu.addAction(addAct)
        toolbar.addAction(addAct)
        
        menu.addAction(saveAct)
        toolbar.addAction(saveAct)
        
        menu.addAction(deleteAct)
        toolbar.addAction(deleteAct)

        menu.addAction(saveRulesetAct)
        menu.addAction(loadRulesetAct)

    @pyqtSlot()
    def on_reload_item(self):
        if self.panes.tab_settings.currentIndex() == 0:
            self.on_reload_rules()
        elif self.panes.tab_settings.currentIndex() ==  1:
            self.on_reload_modules()
        elif self.panes.tab_settings.currentIndex() ==  2:
            self.on_reload_certs()
        elif self.panes.tab_settings.currentIndex() ==  3:
            self.on_reload_files()
    
    @pyqtSlot()
    def on_add_item(self):
        if self.panes.tab_settings.currentIndex() == 0:
            self.on_add_rule()
        elif self.panes.tab_settings.currentIndex() ==  2:
            self.on_add_cert()
        elif self.panes.tab_settings.currentIndex() ==  3:
            self.on_add_file()

    @pyqtSlot()
    def on_save_item(self):
        if self.panes.tab_settings.currentIndex() == 0:
            self.on_save_rules()
        elif self.panes.tab_settings.currentIndex() ==  2:
            if self.selected_widget == self.panes.certs:
                self.on_commit_data()
            else:
                self.statusBar().showMessage('Ignored saving cert when no cert data is loaded.')
        elif self.panes.tab_settings.currentIndex() ==  3:
            if self.selected_widget == self.panes.files:
                self.on_commit_data()
            else:
                self.statusBar().showMessage('Ignored saving file when no file data is loaded.')

    @pyqtSlot()
    def on_delete_item(self):
        if self.panes.tab_settings.currentIndex() == 0:
            self.on_delete_rule()
        elif self.panes.tab_settings.currentIndex() ==  2:
            self.on_delete_cert()
        elif self.panes.tab_settings.currentIndex() ==  3:
            self.statusBar().showMessage('Deleting file not implemented yet.')

    @pyqtSlot()
    def on_connect(self):
        try:
            self.tcpproxy =  TCPProxyClient(self.tcpproxy_host)
        
            self.on_reload_rules()
            self.on_reload_convs()
            self.on_connect_debugger()
            self.on_reload_modules()
            self.on_reload_certs()
            self.on_reload_files()

            self.statusBar().showMessage('Connected debugger to TCPProxy on %s' % self.tcpproxy_host)
        except redis.exceptions.ConnectionError as ex:
            self.statusBar().showMessage('Failed to connect debugger to %s' % self.tcpproxy_host)
            print(ex)
        
    @pyqtSlot()
    def on_disconnect(self):
        self.on_disconnect_debugger()
        self.tcpproxy = None

    @pyqtSlot()
    def on_toggle_intercept(self):
        self.statusBar().showMessage('Changing Intercept to %s' % str(not self.tcpproxy_host.is_intercepting()))
        self.statusBar().showMessage('Changing Intercept to %s' % str(not self.tcpproxy_host.is_intercepting()))

    @pyqtSlot()
    def on_add_rule(self):
        if self.tcpproxy:
            self.panes.rules.add()
        else:
            self.statusBar().showMessage('Cannot add rule. Not connected to Redis')

    @pyqtSlot()
    def on_add_cert(self):
        if self.tcpproxy:
            self.panes.certs.add()
        else:
            self.statusBar().showMessage('Cannot add cert. Not connected to Redis')
        
    @pyqtSlot()
    def on_add_file(self):
        if self.tcpproxy:
            self.panes.files.add()
        else:
            self.statusBar().showMessage('Cannot add file. Not connected to Redis')

    @pyqtSlot()
    def on_save_rules(self):
        if self.tcpproxy:
            rules =  self.panes.rules.getRules()
            self.tcpproxy.save_rules(rules)
            self.statusBar().showMessage('Rules successfully saved to Redis')
        else:
            self.statusBar().showMessage('Cannot save rule. Not connected to Redis')

    @pyqtSlot()
    def on_delete_rule(self):
        if self.tcpproxy:
            self.panes.rules.delete()
        else:
            self.statusBar().showMessage('Cannot delete rule. Not connected to Redis')

    @pyqtSlot()
    def on_delete_cert(self):
        if self.tcpproxy:
            key = self.selected_widget.getSelectedKey()
            if key:
                print ("Trying to delete cert for key %s from redis" % key)
                self.tcpproxy.delete_key(key)
                self.on_reload_certs()
            else:
                self.statusBar().showMessage('No certificate selected. Cannot delete.') 
        else:
            self.statusBar().showMessage('Cannot delete certificate. Not connected to Redis')

    @pyqtSlot()
    def on_reload_rules(self):
        if self.tcpproxy:
            rules = self.tcpproxy.get_rules()
            self.statusBar().showMessage('Loaded %d rules from Redis' % len(rules))
            print(rules)
            self.panes.rules.load(rules)
        else:
            self.statusBar().showMessage('Cannot reload rules. Not connected to Redis')

    @pyqtSlot()
    def on_dump_ruleset(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save ruleset file")
        try:
            fp = open(filename, 'w')
            fp.write(json.dumps(self.panes.rules.getRules()))
            fp.close()
            self.statusBar().showMessage('Ruleset saved to file')
        except Exception as ex:
            self.statusBar().showMessage('Error when saving ruleset to file: %s' % ex.__str__())

    @pyqtSlot()
    def on_load_ruleset(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Load ruleset file")
        try:
            fp = open(filename, 'r')
            rules = json.loads(fp.read())
            fp.close()
            self.panes.rules.load(rules)
            self.statusBar().showMessage('Ruleset loaded from file')
        except Exception as ex:
            self.statusBar().showMessage('Error when loading ruleset from file: %s' % ex.__str__())

    @pyqtSlot()
    def on_reload_certs(self):
        if self.tcpproxy:
            certs=[]
            for key in self.tcpproxy.get_certs():
                certs.append({"key":key.decode("utf-8"),"data":self.tcpproxy.get_key(key),"encoding":"x509"})
            for key in self.tcpproxy.get_key_iter("*:key"):
                certs.append({"key":key.decode("utf-8"),"data":self.tcpproxy.get_key(key),"encoding":"text"})
            for key in self.tcpproxy.get_key_iter("*:*:key"):
                certs.append({"key":key.decode("utf-8"),"data":self.tcpproxy.get_key(key),"encoding":"text"})

            self.statusBar().showMessage('Loaded %d certs from Redis' % len(certs))
            self.panes.certs.load(certs)
        else:
            self.statusBar().showMessage('Cannot reload certs. Not connected to Redis')

    @pyqtSlot()
    def on_reload_files(self):
        if self.tcpproxy:
            files=[]
            for key in self.tcpproxy.get_key_iter("file:*"):
                parsed = key.decode("utf-8").split(":", 2)
                files.append({"key":parsed[2], "data":self.tcpproxy.get_key(key), "encoding":parsed[1]})
                
            self.statusBar().showMessage('Loaded %d files from Redis' % len(files))
            self.panes.files.load(files)
        else:
            self.statusBar().showMessage('Cannot reload files. Not connected to Redis')

    @pyqtSlot()
    def on_reload_modules(self):
        if self.tcpproxy:
            modules = ""
            i = 0
            for m,mhelp in self.tcpproxy.get_modules_help():
                modules += "<b>"+m.decode("utf-8") + ": </b>"
                modules += mhelp.replace("\n","<br />").replace("\t","&nbsp;&nbsp;&nbsp;&nbsp;")
                modules += "<br />"
                if not mhelp.endswith("\n"):
                    modules += "<br />"
                i += 1
                
            self.statusBar().showMessage('Loaded %d modules descriptions from Redis' % i)
            self.panes.modules.setText(modules)
        else:
            self.statusBar().showMessage('Cannot reload modules descriptions. Not connected to Redis')

    @pyqtSlot()
    def on_reload_convs(self):
        if self.tcpproxy:
            self.statusBar().showMessage('Reloading conversations from Redis...')
            convs = self.tcpproxy.get_stats("stats:summary")
            self.statusBar().showMessage('Loaded %d conversations from Redis' % len(convs))
            self.panes.convs.load(convs)
            self.on_clear_filter()
        else:
            self.statusBar().showMessage('Cannot reload conversations. Not connected to Redis')
            
    @pyqtSlot()
    def on_clear_convs(self):
        if self.tcpproxy:
            self.statusBar().showMessage('Clearing conversations from Redis...')
            self.panes.convs.clear()
            self.tcpproxy.clear_conversations()
            self.statusBar().showMessage('Conversations cleared')
        else:
            self.statusBar().showMessage('Cannot reload conversations. Not connected to Redis')

    @pyqtSlot()
    def on_clear_data(self):
        self.statusBar().showMessage('Clearing data pane...')
        self.panes.data.setRowCount(0)
        self.data = []
        self.statusBar().showMessage('Data pane cleared')

    def on_filter_added(self, filter):
        if filter[0] not in self.data_filter:
            self.data_filter[filter[0]] = [filter[1]]
        else:
            self.data_filter[filter[0]].append(filter[1])
            
        self.panes.data.setRowCount(0)
        self.on_reload_data()

    @pyqtSlot()
    def on_clear_filter(self):
        if self.data_filter:
            self.data_filter = {}
            self.panes.data.setRowCount(0)
            self.panes.convs.clearBackground()
            self.on_reload_data()
        
    @pyqtSlot()
    def on_reload_data(self):
        print (self.data_filter)
        i = 0
        for msg in self.data:
            self.panes.convs.add(msg)
        for msg in self.data_filter_iter():
            self.panes.data.add(msg, i)
            i += 1
            
        self.panes.data.resize()
        
    def data_filter_iter(self, item=None):
        if item:
            data = [item]
        else:
            data = self.data
        for msg in data:
            if len(self.data_filter) <= 0:
                yield msg
            else:
                load = True
                for key,valuelist in self.data_filter.items():
                    if not key in msg or not str(msg[key]) in valuelist:
                        load=False
                if load:
                    yield msg

    def on_file_selected(self):
        if self.tcpproxy:
            self.selected_widget = self.panes.files
            key = self.selected_widget.getSelectedKey()
            if key:
                print ("Loading data for key %s from redis" % key)
                data = self.tcpproxy.get_key(key)
                print("data:")
                print(data)
                encoding = key.split(":")[1]
                self.fill_edition(data, encoding)
        else:
            self.statusBar().showMessage('Cannot load file data. Not connected to Redis')

    def on_cert_selected(self):
        if self.tcpproxy:
            self.selected_widget = self.panes.certs
            key = self.selected_widget.getSelectedKey()
            if key:
                print ("Loading data for key %s from redis" % key)
                data = self.tcpproxy.get_key(key)
                encoding = key.split(":")[1]
                self.fill_edition(data, encoding)
        else:
            self.statusBar().showMessage('Cannot load file data. Not connected to Redis')

    def on_data_selected(self):
        self.selected_widget = self.panes.data
        for item in self.panes.data.selectedItems():
            
            id = int(self.panes.data.item(item.row(), 0).text())
            print("Data row selected: %d id: %d" % (item.row(), id))
        
            self.fill_edition(self.data[id]["data"], "base64")

    @pyqtSlot()
    def on_commit_data(self):
        if self.tcpproxy:
            if self.selected_widget:
                if self.selected_widget == self.panes.data:
                    item = None
                    for item in self.panes.data.selectedItems():
                        item = item
                    id = int(self.panes.data.item(item.row(), 0).text())
                    print("Data row commited %d id: %d" % (item.row(), id))
                    self.data[id]["orig"] = self.data[id]["data"]
                    self.data[id]["level"] = "INSPECTED"
                    self.data[id]["data"] = base64.b64encode(self.selected_rawdata).decode("utf-8")
                    self.panes.data.item(item.row(), 1).setBackground(QBrush(QColor(0,204,102)))
                    self.panes.data.item(item.row(), 1).setText("INSPECTED")
                    self.tcpproxy.commit_inspected_msg(self.data[id])
                    print("Packet sent to debugger.")
                else:
                    key = self.selected_widget.getSelectedKey()
                    if key:
                        encoding = key.split(":")[1]
                        data = self.selected_rawdata
                        if encoding == "base64":
                            data = base64.b64encode(rawdata)
                        print ("sending %s : %s" %(key, data))
                        self.tcpproxy.set_key(key, data)
                        self.statusBar().showMessage('Data saved to Redis.')
                    else:
                        self.statusBar().showMessage('No data selected. Cannot commit.')
            else:
                self.statusBar().showMessage('No data selected. Cannot commit.')
        else:
            self.statusBar().showMessage('Cannot submit data. Not connected to Redis')

    def fill_edition(self, data, encoding):
        if data is not None:
            if encoding == "base64":
                data = base64.b64decode(data)
            self.selected_rawdata = data
            self.reload_hexpane()
            self.reload_strpane()
            self.reload_gzippane()
        else:
            self.clear_edition()

    def clear_edition(self):
        self.selected_rawdata = ""
        self.panes.strmsg.blockSignals(True)
        self.panes.strmsg.clear()
        self.panes.hexmsg.blockSignals(True)
        self.panes.hexmsg.clear()
        self.panes.gzipmsg.blockSignals(True)
        self.panes.gzipmsg.clear()

    def reload_strpane(self):
        self.panes.strmsg.blockSignals(True)
        self.panes.strmsg.clear()
        try:
            data = self.selected_rawdata.decode("utf-8")
            self.panes.strmsg.setPlainText(data)
        except UnicodeDecodeError as ex:
            pass
        self.panes.strmsg.blockSignals(False)
    
    def reload_hexpane(self):
        self.panes.hexmsg.blockSignals(True)
        self.panes.hexmsg.clear()
        hexdata = hexdump.hexdump(self.selected_rawdata, result='return')
        self.panes.hexmsg.setPlainText(hexdata)
        self.panes.hexmsg.blockSignals(False)

    def reload_gzippane(self):
        import zlib
        self.panes.gzipmsg.blockSignals(True)
        self.panes.gzipmsg.clear()
        
        httpdata = self.selected_rawdata.split(b"\r\n\r\n",2)
        if len(httpdata) != 2:
            httpdata = self.selected_rawdata.split(b"\n\n",2)
        
        # 8-15 : Compression level
        # zlib.MAX_WBITS : zlib format = RFC 1950 = http deflate
        # -zlib.MAX_WBITS : deflate format = RFC 1951 = unzip deflate (negative means no gzip header)
        # 16 + zlib.MAX_WBITS : gzip format = RFC 1952
        data = ""
        info = []
        for args in [0, zlib.MAX_WBITS, -zlib.MAX_WBITS, 16+zlib.MAX_WBITS]:
            try:
                data = zlib.decompress(self.selected_rawdata,args)
                break
            except Exception as ex:
                print("INFO: Exception when trying to decompress data with arg %d: %s" % (args, ex.__str__()))
                
            if len(httpdata) == 2:
                try:
                    data = zlib.decompress(httpdata[1],args)
                    info.append("Decompressed HTTP Data")
                    break
                except Exception as ex:
                    print("INFO: Exception when trying to decompress http data with arg %d: %s" % (args, ex.__str__()))

        if len(data) > 0:
            try:
                displaydata = data.decode("utf-8")
            except UnicodeDecodeError as ex:
                info.append("Binary result hexdump")
                displaydata = hexdump.hexdump(data, result='return')
            data = "/".join(info)
            if len(data) > 0:
                data += "\n"
            data += displaydata
            self.panes.gzipmsg.setPlainText(data)

        self.panes.gzipmsg.blockSignals(False)

    def diff_data(self, old, new):
        s = difflib.SequenceMatcher(None,old,new)
        edit = old
        for tag, i1, i2, j1, j2 in s.get_opcodes():
            print("%7s a[%d:%d] (%s) b[%d:%d] (%s)" % (tag, i1, i2,  old[i1:i2], j1, j2, new[j1:j2]))
            if tag == "insert":
                print ("Insert %s at [%d]" % (new[j1:j2],  i1))
                edit = old[0:i1]+new[j1:j2]+old[i1:]
            elif tag == "replace":
                print ("Replace %s at [%d:%d]" % (new[j1:j2], i1,i2))
                edit = old[0:i1]+new[j1:j2]+old[i2:]
            elif tag == "delete":
                print ("Delete [%d:%d] (%s)"% (i1,i2,old[0:i1]))
                edit = old[0:i1]+old[i2:]
        return edit

    @pyqtSlot()
    def on_strtext_changed(self):
        unistr = self.panes.strmsg.toPlainText()
        if unistr:
            changed = unistr.encode("utf-8")
            edit = self.diff_data(self.selected_rawdata, changed)
            print ("Changed data to:",edit)
            self.selected_rawdata = changed
            self.reload_hexpane()

    @pyqtSlot()
    def on_hextext_changed(self):
        hexstr = self.panes.hexmsg.toPlainText()
        if len(hexstr) > 0:
            try:
                changed =hexdump.restore(hexstr)
            except ValueError as ex:
                print("Invalid Hex data: %s" % ex.__str__())
                p = self.panes.hexmsg.palette()
                p.setColor(QPalette.Base, QColor(250,218,94))
                self.panes.hexmsg.setPalette(p)
                return
            p = self.panes.hexmsg.palette()
            p.setColor(QPalette.Base, QColor(255,255,255))
            self.panes.hexmsg.setPalette(p)
            print ("Data loaded from hexdump:",changed)
            edit = self.diff_data(self.selected_rawdata, changed)
            print ("Changed data to:",edit)
            self.selected_rawdata = edit
            self.reload_strpane()

    @pyqtSlot()
    def on_save_data(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Data File")
        fp = open(filename, 'w')
        fp.write(json.dumps(self.data))
        fp.close()

    @pyqtSlot()
    def on_save_filteredin_data(self):
        data = []
        for msg in self.data_filter_iter():
            data.append(msg)
        filename, _ = QFileDialog.getSaveFileName(self, "Save Data File")
        fp = open(filename, 'w')
        fp.write(json.dumps(data))
        fp.close()

    @pyqtSlot()
    def on_load_data(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Load Data File")
        fp = open(filename, 'r')
        self.data = json.loads(fp.read())
        fp.close()
        self.panes.data.setRowCount(0)
        self.on_clear_filter()
        self.on_reload_data()

    @pyqtSlot()
    def on_connect_debugger(self):
        self.statusBar().showMessage('Connecting debugger...')
        self.debugger = DebugThread(self.tcpproxy_host)
        self.debugger.signal.connect(self.on_received_debug)
        self.debugger.start()
        self.inspecter = InspectThread(self.tcpproxy_host)
        self.inspecter.signal.connect(self.on_received_inspect)
        self.inspecter.start()
        
    def on_received_debug(self, msg):
        self.data.append(msg)
        self.panes.convs.add(msg)
        for msg in self.data_filter_iter(msg):
            self.panes.data.add(msg, len(self.data)-1)
        self.panes.data.resize()

    def on_received_inspect(self, msg):
        msg["level"] = "INSPECT"
        self.data.append(msg)
        for msg in self.data_filter_iter(msg):
            self.panes.data.add(msg, len(self.data)-1)
        self.panes.data.resize()

    @pyqtSlot()
    def on_disconnect_debugger(self):
        if self.debugger:
            self.debugger.running = False
            self.inspecter.running = False
            self.statusBar().showMessage('Disconnected debugger')
        else:
            self.statusBar().showMessage('No debugger connected')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    proxygui = TCPProxyApp(sys.argv)
    sys.exit(app.exec_())
