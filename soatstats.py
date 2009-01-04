#!/usr/bin/python
#
# 2008 Aleksei Gorny, mentored by Mike Perry

import dircache
import operator
import os
import pickle
import sys
import time

import sets
from sets import Set

#
# Data storage
#

# data locations

data_dir = './data/soat/'
ssl_certs_dir = data_dir + 'ssl/certs/'
http_tags_dir = data_dir + 'http/tags/'

# constants

TEST_SUCCESS = 0
TEST_INCONCLUSIVE = 1
TEST_FAILURE = 2

# classes to use with pickle to dump test results into files

class TestResult(object):
    ''' Parent class for all test result classes '''
    def __init__(self, exit_node, site, status):
        self.exit_node = exit_node
        self.site = site
        self.timestamp = time.time()
        self.status = status

class SSLTestResult(TestResult):
    ''' Represents the result of an openssl test '''
    def __init__(self, exit_node, ssl_site, cert_file, status):
        super(SSLTestResult, self).__init__(exit_node, ssl_site, status)
        self.cert = cert_file

class HttpTestResult(TestResult):
    ''' Represents the result of a http test '''
    def __init__(self, exit_node, website, tag_prints, status):
        super(HttpTestResult, self).__init__(exit_node, website, status)
        self.tag_prints = tag_prints

class SSHTestResult(TestResult):
    ''' Represents the result of an ssh test '''
    def __init__(self, exit_node, ssh_site, status):
        super(SSHTestResult, self).__init__(exit_node, ssh_site, status)

class DNSTestResult(TestResult):
    ''' Represents the result of a dns test '''
    def __init__(self, exit_node, dns_site, status):
        super(DNSTestResult, self).__init__(exit_node, dns_site, status)

class DNSRebindTestResult(TestResult):
    ''' Represents the result of a dns rebind test '''
    def __init__(self, exit_node, dns_rebind_site, status):
        super(DNSRebindTestResult, self).__init__(exit_node, dns_rebind_site, status)

class SMTPTestResult(TestResult):
    ''' Represents the result of an smtp test '''
    def __init__(self, exit_node, smtp_site, status):
        super(SMTPTestResult, self).__init__(exit_node, smtp_site, status)

class IMAPTestResult(TestResult):
    ''' Represents the result of an imap test '''
    def __init__(self, exit_node, imap_site, status):
        super(IMAPTestResult, self).__init__(exit_node, imap_site, status)

class POPTestResult(TestResult):
    ''' Represents the result of a pop test '''
    def __init__(self, exit_node, pop_site, status):
        super(POPTestResult, self).__init__(exit_node, pop_site, status)

class DataHandler:
    ''' Class for saving and managing test result data '''
    def filterResults(self, results, protocols=[], show_good=False, 
            show_bad=False, show_inconclusive=False):
        ''' filter results based on protocol and success level ''' 

        protocol_filters = []
        status_filters = []

        for protocol in protocols:
            protocol_filters.append(lambda x, p=protocol: x.__class__.__name__.lower()[:-10].endswith(p))
        if show_good:
            status_filters.append(lambda x: x.status == TEST_SUCCESS)
        if show_bad:
            status_filters.append(lambda x: x.status == TEST_FAILURE)
        if show_inconclusive:
            status_filters.append(lambda x: x.status == TEST_INCONCLUSIVE)

        if len(protocol_filters) == 0 or len(status_filters) == 0:
            return []
       
        protocol_filter = lambda x: reduce(operator.__or__, [f(x) for f in protocol_filters])
        status_filter = lambda x: reduce(operator.__or__, [f(x) for f in status_filters])

        return [x for x in results if (protocol_filter(x) and status_filter(x))]
        
    def filterByNode(self, results, id):
        ''' filter by node'''
        return filter(lambda x: x.exit_node == id, results)

    def getAll(self):
        ''' get all available results'''
        return self.__getResults(data_dir)

    def getSsh(self):
        ''' get results of ssh tests '''
        return self.__getResults(data_dir + 'ssh/')
        
    def getHttp(self):
        ''' get results of http tests '''
        return self.__getResults(data_dir + 'http/')

    def getSsl(self):
        ''' get results of ssl tests '''
        return self.__getResults(data_dir + 'ssl/')

    def getSmtp(self):
        ''' get results of smtp tests '''
        return self.__getResults(data_dir + 'smtp/')

    def getPop(self):
        ''' get results of pop tests '''
        return self.__getResults(data_dir + 'pop/')

    def getImap(self):
        ''' get results of imap tests '''
        return self.__getResults(data_dir + 'imap/')

    def getDns(self):
        ''' get results of basic dns tests '''
        return self.__getResults(data_dir + 'dns')

    def getDnsRebind(self):
        ''' get results of dns rebind tests '''
        return self.__getResults(data_dir + 'dnsbrebind/')

    def __getResults(self, dir):
        ''' 
        recursively traverse the directory tree starting with dir
        gather test results from files ending with .result
        '''
        results = []

        for root, dirs, files in os.walk(dir):
            for file in files:
                if file.endswith('result'):
                    fh = open(os.path.join(root, file))
                    result = pickle.load(fh)
                    results.append(result)

        return results

    def safeFilename(self, str):
        ''' 
        remove characters illegal in some systems 
        and trim the string to a reasonable length
        '''
        replaced = (str.replace('/','_').replace('\\','_').replace('?','_').replace(':','_').
            replace('|','_').replace('*','_').replace('<','_').replace('>','_').replace('"',''))
        return replaced[:200]

    def saveResult(self, result):
        ''' generic method for saving test results '''
        address = ''
        if result.__class__.__name__ == 'HttpTestResult':
            address = self.safeFilename(result.site[7:])
        elif result.__class__.__name__ == 'SSLTestResult':
            address = self.safeFilename(result.site[8:])
        elif 'TestResult' in result.__class__.__name__:
            address = self.safeFilename(result.site)
        else:
            raise Exception, 'This doesn\'t seems to be a result instance.'

        dir = data_dir + result.__class__.__name__[:-10].lower() + '/'
        if result.status == TEST_SUCCESS:
            dir += 'successful/'
        if result.status == TEST_INCONCLUSIVE:
            dir += 'inconclusive/'
        if result.status == TEST_FAILURE:
            dir += 'failed/'
        
        result_file = open(dir + `result.exit_node` + address + '.result', 'w')
        pickle.dump(result, result_file)
        result_file.close()
    
#
# Displaying stats on the console
#

class StatsConsole:
    ''' Class to display statistics from CLI'''
    
    def Listen(self):
        while 1:
            input = raw_input(">>>")
            if input == 'e' or input == 'exit':
                exit()
            elif input == 's' or input == 'summary':
                self.Summary()
            elif input == 'h' or input == 'help' or len(input) > 6:
                self.Help() 
            else:
                self.Reply(input)
    
    def Summary(self):
        dh = DataHandler()
        data = dh.getAll()
        
        nodeSet = Set([])
        sshSet = Set([])
        sslSet = Set([])
        httpSet = Set([])
        smtpSet = Set([])
        popSet = Set([])
        imapSet = Set([])
        dnsSet = Set([])
        dnsrebindSet = Set([])

        total = len(data)
        good = bad = inconclusive = 0
        ssh = http = ssl = pop = imap = smtp = dns = dnsrebind = 0

        for result in data:
            nodeSet.add(result.exit_node)
            
            if result.status == 0:
                good += 1
            elif result.status == 1:
                inconclusive += 1
            elif result.status == 2:
                bad += 1
            
            if result.__class__.__name__ == 'SSHTestResult':
                sshSet.add(result.exit_node)
                ssh += 1
            elif result.__class__.__name__ == 'HttpTestResult':
                httpSet.add(result.exit_node)
                http += 1
            elif result.__class__.__name__ == 'SSLTestResult':
                sslSet.add(result.exit_node)
                ssl += 1
            elif result.__class__.__name__ == 'IMAPTestResult':
                imapSet.add(result.exit_node)
                imap += 1
            elif result.__class__.__name__ == 'POPTestResult':
                popSet.add(result.exit_node)
                pop += 1
            elif result.__class__.__name__ == 'SMTPTestResult':
                smtpSet.add(result.exit_node)
                smtp += 1
            elif result.__class__.__name__ == 'DNSTestResult':
                dnsSet.add(result.exit_node)
                dns += 1
            elif result.__class__.__name__ == 'DNSRebindTestResult':
                dnsrebindSet.add(result.exit_node)
                dnsrebind += 1

        swidth = 25
        nwidth = 10
        width = swidth + nwidth

        header_format = '%-*s%*s'
        format = '%-*s%*i'

        print '=' * width
        print header_format % (swidth, 'Parameter', nwidth, 'Count')
        print '-' * width

        stats = [
            ('Tests completed', total),
            ('Nodes tested', len(nodeSet)),
            ('Nodes SSL-tested', len(sslSet)),
            ('Nodes HTTP-tested', len(httpSet)),
            ('Nodes SSH-tested', len(sshSet)),
            ('Nodes POP-tested', len(popSet)),
            ('Nodes IMAP-tested', len(imapSet)),
            ('Nodes SMTP-tested', len(smtpSet)),
            ('Nodes DNS-tested', len(dnsSet)),
            ('Nodes DNSRebind-tested', len(dnsrebindSet)),
            ('Failed tests', bad),
            ('Succeeded tests', good),
            ('Inconclusive tests', inconclusive),
            ('SSH tests', ssh),
            ('HTTP tests', http),
            ('SSL tests', ssl),
            ('POP tests', pop),
            ('IMAP tests', imap),
            ('SMTP tests', smtp),
            ('DNS tests', dns),
            ('DNS rebind tests', dnsrebind)
        ]

        for (k,v) in stats:
            print format % (swidth, k, nwidth, v)
        print '=' * width

    def Reply(self, input):

        good = bad = inconclusive = False
        protocols = []

        if 'a' in input:
            good = bad = inconclusive = True
            protocols.extend(["ssh", "http", "ssl", "imap", "pop", "smtp"])
        else:
            good = 'g' in input
            bad = 'b' in input
            inconclusive = 'i' in input

            if 's' in input:
                protocols.append("ssh")
            if 'h' in input:
                protocols.append("http")
            if 'l' in input:
                protocols.append("ssl")
            if 'p' in input:
                protocols.append("imap")
            if 'o' in input:
                protocols.append("pop")
            if 't' in input:
                protocols.append("smtp")
            if 'd' in input:
                protocols.append("dns")
            if 'r' in input:
                protocols.append("dnsrebind")

        dh = DataHandler()
        data = dh.getAll()
        filtered = dh.filterResults(data, protocols, good, bad, inconclusive)

        nodewidth = 45
        typewidth = 10
        sitewidth = 30
        timewidth = 30
        statuswidth = 6
        width = nodewidth + typewidth + sitewidth + timewidth + statuswidth

        format = '%-*s%-*s%-*s%-*s%-*s'

        print '=' * width 
        print format % (nodewidth, 'Exit node', typewidth, 'Test type', sitewidth, 'Remote site', 
                timewidth, 'Time', statuswidth, 'Status')
        print '-' * width
        for result in filtered:
            print format % (nodewidth, `result.exit_node`, 
                    typewidth, result.__class__.__name__[:-10],
                    sitewidth, result.site, 
                    timewidth, time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(result.timestamp)), 
                    statuswidth, `result.status`)
        print '=' * width

    def Help(self):
        print ''
        print 'Options:'
        print '* summmary (s) - display a short summary about all tests done so far'
        print '* exit (e) - terminate the program'
        print '* help (h) - display this help text'
        print '* all (a) - list all the results'
        print '* (shlgbi) - display a filtered list of test results. Letters are optional and mean the following:'
        print '  s - show ssh results'
        print '  h - show http results'
        print '  l - show ssl results'
        print '  g - show good results'
        print '  b - show bad results'
        print '  i - show inconclusive results'
        print '  p - show imap results'
        print '  o - show pop results'
        print '  t - show smtp results'
        print '  d - show dns results'
        print '  r - show dnsrebind results'
        print ''

#
# Displaying stats in a graphical setting (first check if we have wx)
#

nowx = False
try:
    import wx
    from wx.lib.mixins.listctrl import ListCtrlAutoWidthMixin, ColumnSorterMixin
except:
    nowx = True

if not nowx:

    class ListMixin(wx.ListCtrl, ListCtrlAutoWidthMixin, ColumnSorterMixin):
        def __init__(self, parent, map):
            wx.ListCtrl.__init__(self, parent, -1, style=wx.LC_REPORT)
            ListCtrlAutoWidthMixin.__init__(self)
            ColumnSorterMixin.__init__(self, len(map))
            self.itemDataMap = map

        def GetListCtrl(self):
            return self

    # menu item ids
    ID_EXIT = 1

    ID_SHOW_GOOD = 11
    ID_SHOW_BAD = 12
    ID_SHOW_UNSURE = 13

    ID_SHOW_SSL = 21
    ID_SHOW_HTTP = 22
    ID_SHOW_SSH = 23
    ID_SHOW_SMTP = 24
    ID_SHOW_IMAP = 25
    ID_SHOW_POP = 26
    ID_SHOW_DNS = 27
    ID_SHOW_DNSREBIND = 28

    ID_NODE = 31

    class MainFrame(wx.Frame):
        ''' the main application window for displaying statistics with a GUI'''
        def __init__(self):
            wx.Frame.__init__(self, None, title="Soat test results", size=(900,500))
         
            # get the data

            self.dataHandler = DataHandler()
            self.dataList = self.dataHandler.getAll()
            self.filteredList = self.dataList

            # display it
        
            self.CreateStatusBar()
            self.initMenuBar()
            self.initContent()

            self.Center()
            self.Show()
    
        def initMenuBar(self):
            fileMenu = wx.Menu()
            fileMenu.Append(ID_EXIT, "E&xit", "Exit the program")
        
            viewMenu = wx.Menu()
            self.showGood = viewMenu.Append(ID_SHOW_GOOD, 'Show &Good', 'Show sucessful test results', kind=wx.ITEM_CHECK)
            self.showBad = viewMenu.Append(ID_SHOW_BAD, 'Show &Bad', 'Show unsucessful test results', kind=wx.ITEM_CHECK)
            self.showUnsure = viewMenu.Append(ID_SHOW_UNSURE, 'Show &Inconclusive', 'Show inconclusive test results', kind=wx.ITEM_CHECK)
            viewMenu.AppendSeparator()
            self.showSSL = viewMenu.Append(ID_SHOW_SSL, 'Show SS&L', 'Show SSL test results', kind=wx.ITEM_CHECK)
            self.showHTTP = viewMenu.Append(ID_SHOW_HTTP, 'Show &HTTP', 'Show HTTP test results', kind=wx.ITEM_CHECK)
            self.showSSH = viewMenu.Append(ID_SHOW_SSH, 'Show &SSH', 'Show SSH test results', kind=wx.ITEM_CHECK)
            viewMenu.AppendSeparator()
            self.showSMTP = viewMenu.Append(ID_SHOW_SMTP, 'Show SMTP', 'Show SMTP test results', kind=wx.ITEM_CHECK)
            self.showIMAP = viewMenu.Append(ID_SHOW_IMAP, 'Show IMAP', 'Show IMAP test results', kind=wx.ITEM_CHECK)
            self.showPOP = viewMenu.Append(ID_SHOW_POP, 'Show POP', 'Show POP test results', kind=wx.ITEM_CHECK)
            viewMenu.AppendSeparator()
            self.showDNS = viewMenu.Append(ID_SHOW_DNS, 'Show DNS', 'Show DNS test results', kind=wx.ITEM_CHECK)
            self.showDNSRebind = viewMenu.Append(ID_SHOW_DNSREBIND, 'Show DNSRebind', 'Show DNS rebind test results', kind=wx.ITEM_CHECK)
            viewMenu.AppendSeparator()
            viewMenu.Append(ID_NODE, '&Find node...', 'View test results for a given node [NOT IMPLEMENTED]')
    
            menuBar = wx.MenuBar()
            menuBar.Append(fileMenu,"&File")
            menuBar.Append(viewMenu,"&View")

            self.SetMenuBar(menuBar)

            wx.EVT_MENU(self, ID_EXIT, self.OnExit)

            wx.EVT_MENU(self, ID_SHOW_GOOD, self.GenerateFilteredList)
            wx.EVT_MENU(self, ID_SHOW_BAD, self.GenerateFilteredList)
            wx.EVT_MENU(self, ID_SHOW_UNSURE, self.GenerateFilteredList)
            viewMenu.Check(ID_SHOW_GOOD, True)
            viewMenu.Check(ID_SHOW_BAD, True)
            viewMenu.Check(ID_SHOW_UNSURE, True)
            
            for i in range(ID_SHOW_SSL, ID_SHOW_DNSREBIND + 1):
                viewMenu.Check(i, True)
                wx.EVT_MENU(self, i, self.GenerateFilteredList)

        def initContent(self): 
            base = wx.Panel(self, -1)
            sizer = wx.GridBagSizer(0,0)

            box = wx.StaticBox(base, -1, 'Summary')
            boxSizer = wx.StaticBoxSizer(box, wx.HORIZONTAL)

            total = wx.StaticText(base, -1, 'Total tests: ' + `len(self.filteredList)`)
            boxSizer.Add(total, 0, wx.LEFT | wx.TOP | wx.BOTTOM, 10)

            nodes = wx.StaticText(base, -1, 'Nodes scanned: ' + `len(Set([x.exit_node for x in self.filteredList]))`)
            boxSizer.Add(nodes, 0, wx.LEFT | wx.TOP | wx.BOTTOM , 10)

            bad = wx.StaticText(base, -1, 'Failed tests: ' + `len([x for x in self.filteredList if x.status == 2])`)
            boxSizer.Add(bad, 0, wx.LEFT | wx.TOP | wx.BOTTOM, 10)

            suspicious = wx.StaticText(base, -1, 'Inconclusive tests: ' + `len([x for x in self.filteredList if x.status == 1])`)
            boxSizer.Add(suspicious, 0, wx.ALL, 10)

            sizer.Add(boxSizer, (0,0), (1, 5), wx.EXPAND | wx.ALL, 15)

            dataMap = {}
            self.fillDataMap(dataMap)
        
            self.listCtrl = ListMixin(base, dataMap)
            self.listCtrl.InsertColumn(0, 'exit node', width=380)
            self.listCtrl.InsertColumn(1, 'type', width=70)
            self.listCtrl.InsertColumn(2, 'site', width=180)
            self.listCtrl.InsertColumn(3, 'time', width=180)
            self.listCtrl.InsertColumn(4, 'status', wx.LIST_FORMAT_CENTER, width=50)

            self.fillListCtrl(dataMap)
        
            sizer.Add(self.listCtrl, (1,0), (1,5), wx.EXPAND | wx.LEFT | wx.BOTTOM | wx.RIGHT, border=15)

            sizer.AddGrowableCol(3)
            sizer.AddGrowableRow(1)

            base.SetSizerAndFit(sizer)

        # make a nasty dictionary from the current self.filteredList object so columns would be sortable
        def fillDataMap(self, dataMap):
            for i in range(len(self.filteredList)):
                dataMap.update([(i,(self.filteredList[i].exit_node, 
                                self.filteredList[i].__class__.__name__[:-10],
                                self.filteredList[i].site, 
                                time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(self.filteredList[i].timestamp)), 
                                self.filteredList[i].status))])

        # fill the result listing with data
        def fillListCtrl(self, dataMap):
            if self.listCtrl.GetItemCount() > 0:
                self.listCtrl.DeleteAllItems()

            for k, i in dataMap.items():
                index = self.listCtrl.InsertStringItem(sys.maxint, `i[0]`)
                self.listCtrl.SetStringItem(index, 1, i[1])
                self.listCtrl.SetStringItem(index, 2, `i[2]`) 
                self.listCtrl.SetStringItem(index, 3, i[3])
                self.listCtrl.SetStringItem(index, 4, `i[4]`)
                self.listCtrl.SetItemData(index,k)

        def OnExit(self,e):
            self.Close(True)

        def GenerateFilteredList(self, e): 
            protocols = []
            if self.showSSH.IsChecked():
                protocols.append("ssh") 
            if self.showHTTP.IsChecked():
                protocols.append("http")
            if self.showSSL.IsChecked():
                protocols.append("ssl")
            if self.showIMAP.IsChecked():
                protocols.append("imap")
            if self.showPOP.IsChecked():
                protocols.append("pop")
            if self.showSMTP.IsChecked():
                protocols.append("smtp")
            if self.showDNS.IsChecked():
                protocols.append("dns")
            if self.showDNSRebind.IsChecked():
                protocols.append("dnsrebind")

            self.filteredList = list(self.dataHandler.filterResults(self.dataList, protocols, 
                self.showGood.IsChecked(), self.showBad.IsChecked(), self.showUnsure.IsChecked()))

            dataMap = {}
            self.fillDataMap(dataMap)
            self.fillListCtrl(dataMap)
            self.listCtrl.RefreshItems(0, len(dataMap)) 

if __name__ == "__main__":
    if len(sys.argv) == 1:
        console = StatsConsole()
        console.Listen()
    elif len(sys.argv) == 2 and sys.argv[1] == 'wx':
        if nowx:
            print 'wxpython doesn\'t seem to be installed on your system'
            print 'you can use the console interface instead (see help)'
        else:
            app = wx.App(0)
            MainFrame()
            app.MainLoop()
    else:
        print ''
        print 'This app displays results of tests carried out by soat.py (in a user-friendly way).'
        print ''
        print 'Usage:'
        print 'python soatstats.py - app starts console-only'
        print 'python soatstats.py wx - app starts with a wxpython gui'
        print ''
