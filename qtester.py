#coding:utf-8
import sys
from gevent import monkey
monkey.patch_all()
from PyQt4 import QtCore, QtGui,uic
# from PyQt4.QtCore import QSettings,QVariant

from gevent import socket
from pyrad import packet,tools
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
from pyrad.packet import AccessRequest
import time
import hashlib
import six
import gevent
import binascii
import pprint

md5_constructor = hashlib.md5

status_vars = {'start':1,'stop':2,'update':3,'on':7,'off':8}

class AuthPacket2(AuthPacket):
    def __init__(self, code=AccessRequest, id=None, secret=six.b(''),
            authenticator=None, **attributes):
        AuthPacket.__init__(self, code, id, secret, authenticator, **attributes)   

    def ChapEcrypt(self,password):
        if not self.authenticator:
            self.authenticator = self.CreateAuthenticator()
        if not self.id:
            self.id = self.CreateID()
        if isinstance(password, six.text_type):
            password = password.strip().encode('utf-8')

        result = six.b(chr(self.id))

        _pwd =  md5_constructor("%s%s%s"%(chr(self.id),password,self.authenticator)).digest()
        for i in range(16):
            result += _pwd[i]
        return result

app_running = True

app = QtGui.QApplication(sys.argv)
form_class, base_class = uic.loadUiType('tester.ui')

def mainloop(app):
    while app_running:
        app.processEvents()
        while app.hasPendingEvents():
            app.processEvents()
            gevent.sleep()
        gevent.sleep()


class TesterWin(QtGui.QMainWindow,form_class):
    def __init__(self, *args):
        super(TesterWin, self).__init__(*args)
        self.setupUi(self)
        self.init_client()
        self.running = False

    def init_client(self):
        self.dict=Dictionary("dictionary")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,10240000)
        self.sock.settimeout(self.timeout.value()) 


    @property
    def server(self):
        return self.server_addr.text()

    @property
    def authport(self):
        return int(self.auth_port.text() or 1812)

    @property
    def acctport(self):
        return int(self.acct_port.text() or 1813)
    @property
    def authsecret(self):
        return six.b(str(self.auth_secret.text() or 'secret'))
    
    @property
    def acctsecret(self):
        return six.b(str(self.acct_secret.text() or 'secret'))

    def encode_attr(self,key,val):
        if self.dict.has_key(key):
            typ = self.dict[key].type
            if typ == 'integer' or typ == 'date':
                val = int(val)
            else:
                val = str(val)
            return val     
        else:
            self.logger("unknow attr %s"%key)                 

    def decode_attr(self,key,value):
        if self.dict.has_key(key):
            typ = self.dict[key].type
            return tools.DecodeAttr(typ,value)
        else:
            self.logger("unknow attr %s"%key)              

    def logger(self,msg):
        self.log_view.append(msg)

    def get_acct_type(self):
        if self.acct_start.isChecked():
            return status_vars['start']
        elif self.acct_stop.isChecked():
            return status_vars['stop']
        elif self.acct_update.isChecked():
            return status_vars['update']    
        elif self.acct_on.isChecked():
            return status_vars['on']
        elif self.acct_off.isChecked():
            return status_vars['off']

    def build_auth_request(self):
        req = AuthPacket2(secret=self.authsecret,dict=self.dict)
        for _row in range(self.auth_attr_table.rowCount()):
            attr_name_item = self.auth_attr_table.item(_row,0)
            attr_val_item = self.auth_attr_table.item(_row,1)
            flag_item =  self.auth_attr_table.item(_row,2)
            attr_name = attr_name_item and str(attr_name_item.text())
            attr_val = attr_val_item and str(attr_val_item.text())
            flag = flag_item and flag_item.text()
            if attr_name and attr_val and flag == '1':
                val = self.encode_attr(attr_name,attr_val)
                if not val:
                    continue
                if attr_name == 'CHAP-Password':
                    req["CHAP-Password"] = req.ChapEcrypt(val)
                elif  attr_name == 'User-Password':
                    req["User-Password"] = req.PwCrypt(val)   
                else:
                    req[attr_name] = val
        return req

    def build_acct_request(self):
        req = packet.AcctPacket(dict=self.dict,secret=self.acctsecret)
        for _row in range(self.acct_attr_table.rowCount()):
            attr_name_item = self.acct_attr_table.item(_row,0)
            attr_val_item = self.acct_attr_table.item(_row,1)
            flag_item =  self.acct_attr_table.item(_row,2)
            attr_name = attr_name_item and str(attr_name_item.text())
            attr_val = attr_val_item and str(attr_val_item.text())
            flag = flag_item and flag_item.text()
            if attr_name and attr_val and flag == '1':
                val = self.encode_attr(attr_name,attr_val)
                if val :
                    req[attr_name] = val
        return req

    def sendauth(self,req):
        if self.is_debug.isChecked():
            attr_keys = req.keys()
            self.logger(u"\nsend an authentication request to %s"%self.server)
            self.logger(pprint.pformat(req))     
        self.sock.sendto(req.RequestPacket(),(self.server,self.authport)) 
        app.processEvents()

    def sendacct(self):
        req = self.build_acct_request()
        req['Acct-Status-Type'] = self.get_acct_type()
        if  self.is_debug.isChecked():
            attr_keys = req.keys()
            self.logger("\nsend an accounting request")
            self.logger(pprint.pformat(req))              
        self.sock.sendto(req.RequestPacket(),(self.server,self.acctport)) 
        app.processEvents()

    def on_recv(self,times):
        _times = 0
        stat_time = time.time()
        while self.running:
            app.processEvents()
            if _times == times:
                break
            try:
                msg, addr = self.sock.recvfrom(8192)
                _times += 1
                self.lasttime = time.time()

                if self.lasttime - stat_time > 2:
                    self.logger("\nCurrent received %s response"%_times)
                    stat_time = self.lasttime
                if msg:
                    self.reply += 1
                    if self.is_debug.isChecked():
                        try:
                            resp = packet.Packet(packet=msg,dict=self.dict)
                            attr_keys = resp.keys()
                            self.logger("\nReceived an response:")
                            self.logger("id:%s" % resp.id)
                            self.logger("code:%s" % resp.code)
                            self.logger("Attributes: ")        
                            for attr in attr_keys:
                                self.logger( ":::: %s: %s" % (attr, self.decode_attr(attr,resp[attr][0])))     
                        except Exception as e:
                            self.logger('\nerror %s'%str(e))
            except:
                break

        sectimes = self.lasttime - self.starttime
        if times > 1:
            percount = self.reply /sectimes
            self.logger("\nTotal time (sec):%s"%round(sectimes,4))
            self.logger("response total:%s"%self.reply)
            self.logger("request per second:%s"%percount)
        self.stop()

    def run(self,times):
        if self.running:
            return
        if times > 1:
            self.is_debug.setChecked(False)
            self.logger("\nTotal request:%s"%times)            
        self.send_auth_cmd.setEnabled(False) 
        self.send_acct_cmd.setEnabled(False)               
        self.running = True
        self.starttime = time.time()
        self.reply = 0
        self.lasttime = 0   
        gevent.spawn(self.on_recv,times)  

    def stop(self):
        self.running = False     
        self.send_auth_cmd.setEnabled(True) 
        self.send_acct_cmd.setEnabled(True)         

    @QtCore.pyqtSlot()
    def on_send_auth_cmd_clicked(self):
        times = self.auth_times.value()
        self.run(times)
        req = self.build_auth_request()
        for _ in xrange(times):
            app.processEvents()
            if not self.running:
                break            
            gevent.spawn(self.sendauth,req)


    @QtCore.pyqtSlot()
    def on_send_acct_cmd_clicked(self):
        times = self.acct_times.value()
        self.run(times)
        for _ in xrange(times):
            app.processEvents()
            if not self.running:
                break
            gevent.spawn(self.sendacct)

    @QtCore.pyqtSlot()
    def on_clearlog_cmd_clicked(self):
        self.log_view.clear()

    def closeEvent(self, event):
        global app_running
        app_running = False
        try:
            gevent.killall(timeout=2)
        except:
            pass
        event.accept()


if __name__ == "__main__":
    form = TesterWin()
    form.show()
    gevent.joinall([gevent.spawn(mainloop, app)])