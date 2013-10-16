import bisect
from Foundation import NSAutoreleasePool, NSObject, NSThread
from PyObjCTools import AppHelper
import struct

class Capture(NSObject):
    def __new__(cls, device):
        return cls.alloc().initWithDevice_(device)

    def initWithDevice_(self, device):
        self = self.init()
        self.state = CaptureState.DETACHED
        self.device = device
        self._delegate = None
        self.session = None
        self.script = None
        self.modules = Modules()
        self.calls = Calls(self.modules)
        return self

    def delegate(self):
        return self._delegate

    def setDelegate_(self, delegate):
        self._delegate = delegate

    def attachToProcess_triggerPort_(self, process, triggerPort):
        assert self.state == CaptureState.DETACHED
        self.updateState_(CaptureState.ATTACHING)
        NSThread.detachNewThreadSelector_toTarget_withObject_('doAttachWithParams:', self, (process.pid, triggerPort))

    def detach(self):
        assert self.state == CaptureState.ATTACHED
        session = self.session
        script = self.script
        self.session = None
        self.script = None
        self.updateState_(CaptureState.DETACHED)
        NSThread.detachNewThreadSelector_toTarget_withObject_('doDetachWithParams:', self, (session, script))

    def updateState_(self, newState):
        self.state = newState
        self._delegate.captureStateDidChange()

    def doAttachWithParams_(self, params):
        pid, triggerPort = params
        pool = NSAutoreleasePool.alloc().init()
        session = None
        script = None
        error = None
        try:
            session = self.device.attach(pid)
            session.on('detached', self._onSessionDetached)
            script = session._session.create_script(SCRIPT_TEMPLATE % {
                'trigger_port': triggerPort
            })
            script.on('message', self._onScriptMessage)
            script.load()
        except Exception, e:
            if session is not None:
                try:
                    session.detach()
                except:
                    pass
                session = None
            script = None
            error = e
        AppHelper.callAfter(self.attachDidCompleteWithSession_script_error_, session, script, error)
        del pool

    def doDetachWithParams_(self, params):
        session, script = params
        pool = NSAutoreleasePool.alloc().init()
        try:
            script.unload()
        except:
            pass
        try:
            session.detach()
        except:
            pass
        del pool

    def attachDidCompleteWithSession_script_error_(self, session, script, error):
        if self.state == CaptureState.ATTACHING:
            self.session = session
            self.script = script
            if error is None:
                self.updateState_(CaptureState.ATTACHED)
            else:
                self.updateState_(CaptureState.DETACHED)
                self.delegate.captureFailedToAttachWithError_(error)

    def sessionDidDetach(self):
        if self.state == CaptureState.ATTACHING or self.state == CaptureState.ATTACHED:
            self.session = None
            self.updateState_(CaptureState.DETACHED)

    def sessionDidReceiveMessage_data_(self, message, data):
        if message['type'] == 'send':
            stanza = message['payload']
            name = stanza['name']
            fromAddress = stanza['from']
            if fromAddress == "/process/modules" and name == '+sync':
                self.modules.sync(stanza['payload'])
            elif fromAddress == "/stalker/events" and name == '+add':
                self.calls.add_(data)
            elif fromAddress == "/interceptor/functions" and name == '+add':
                pass
            else:
                print "Woot! Got stanza: %s from=%s" % (stanza['name'], stanza['from'])
        else:
            print "Unhandled message:", message

    def _onSessionDetached(self):
        AppHelper.callAfter(self.sessionDidDetach)

    def _onScriptMessage(self, message, data):
        AppHelper.callAfter(self.sessionDidReceiveMessage_data_, message, data)

class CaptureState:
    DETACHED = 1
    ATTACHING = 2
    ATTACHED = 3

class Modules:
    def __init__(self):
        self._modules = []
        self._indices = []

    def sync(self, payload):
        modules = []
        for item in payload['items']:
            modules.append(Module(item['name'], int(item['address'], 16), item['size']))
        modules.sort(lambda x, y: x.address - y.address)
        self._modules = modules
        self._indices = [ m.address for m in modules ]

    def lookup(self, addr):
        idx = bisect.bisect(self._indices, addr)
        if idx == 0:
            return None
        m = self._modules[idx - 1]
        if addr >= m.address + m.size:
            return None
        return m

class Module:
    def __init__(self, name, address, size):
        self.name = name
        self.address = address
        self.size = size

    def __repr__(self):
        return "(%d, %d, %s)" % (self.address, self.size, self.name)

class Calls(NSObject):
    def __new__(cls, modules):
        return cls.alloc().initWithModules_(modules)

    def initWithModules_(self, modules):
        self = self.init()
        self.modules = modules
        self.targetModules = []
        self._targetModuleByAddress = {}
        self._delegate = None
        return self

    def delegate(self):
        return self._delegate

    def setDelegate_(self, delegate):
        self._delegate = delegate

    def add_(self, data):
        for offset in range(0, len(data), 16):
            [t, location, target, depth] = struct.unpack("IIII", data[offset:offset + 16])
            tm = self.getTargetModuleByModule_(self.modules.lookup(target))
            if tm is not None:
                tm.total += 1
                tf = tm.getTargetFunctionByAddress_(target)
                tf.total += 1
        self.targetModules.sort(key=lambda tm: tm.total, reverse=True)
        for tm in self.targetModules:
            tm.functions.sort(key=lambda f: f.total, reverse=True)
        self._delegate.callsDidChange()

    def getTargetModuleByModule_(self, module):
        if module is None:
            return None
        tm = self._targetModuleByAddress.get(module.address, None)
        if tm is None:
            tm = TargetModule(module)
            self.targetModules.append(tm)
            self._targetModuleByAddress[module.address] = tm
        return tm

    def outlineView_numberOfChildrenOfItem_(self, outlineView, item):
        if item is None:
            return len(self.targetModules)
        elif isinstance(item, TargetModule):
            return len(item.functions)
        else:
            return 0

    def outlineView_isItemExpandable_(self, outlineView, item):
        if item is None:
            return False
        elif isinstance(item, TargetModule):
            return len(item.functions) > 0
        else:
            return False

    def outlineView_child_ofItem_(self, outlineView, index, item):
        if item is None:
            return self.targetModules[index]
        elif isinstance(item, TargetModule):
            return item.functions[index]
        else:
            return None

    def outlineView_objectValueForTableColumn_byItem_(self, outlineView, tableColumn, item):
        if isinstance(item, TargetModule):
            if tableColumn.identifier() == 'name':
                return item.module.name
            else:
                return item.total
        else:
            if tableColumn.identifier() == 'name':
                return item.name
            else:
                return item.total

class TargetModule(NSObject):
    def __new__(cls, module):
        return cls.alloc().initWithModule_(module)

    def initWithModule_(self, module):
        self = self.init()
        self.module = module
        self.functions = []
        self._functionByAddress = {}
        self.total = 0
        return self

    def getTargetFunctionByAddress_(self, address):
        f = self._functionByAddress.get(address, None)
        if f is None:
            f = TargetFunction(self, address - self.module.address)
            self.functions.append(f)
            self._functionByAddress[address] = f
        return f

class TargetFunction(NSObject):
    def __new__(cls, module, offset):
        return cls.alloc().initWithModule_offset_(module, offset)

    def initWithModule_offset_(self, module, offset):
        self = self.init()
        self.name = "sub_%x" % offset
        self.module = module
        self.offset = offset
        self.total = 0
        return self

SCRIPT_TEMPLATE = """
Stalker.trustThreshold = 2000;
Stalker.queueCapacity = 1000000;
Stalker.queueDrainInterval = 50;

var initialize = function initialize() {
    sendModules(function () {
        interceptReadFunction('recv');
        interceptReadFunction('read$UNIX2003');
        interceptReadFunction('readv$UNIX2003');
    });
};

var sendModules = function sendModules(callback) {
    var modules = [];
    Process.enumerateModules({
        onMatch: function onMatch(name, address, size, path) {
            modules.push({ name: name, address: "0x" + address.toString(16), size: size });
        },
        onComplete: function onComplete() {
            send({ name: '+sync', from: "/process/modules", payload: { items: modules } });
            callback();
        }
    });
};

var stalkedThreadId = null;
var interceptReadFunction = function interceptReadFunction(functionName) {
    Interceptor.attach(Module.findExportByName('libSystem.B.dylib', functionName), {
        onEnter: function(args) {
            this.fd = args[0].toInt32();
        },
        onLeave: function (retval) {
            var fd = this.fd;
            if (Socket.type(fd) === 'tcp') {
                var address = Socket.peerAddress(fd);
                if (address !== null && address.port === %(trigger_port)d) {
                    send({ name: '+add', from: "/interceptor/functions", payload: { items: [{ name: functionName }] } });
                    if (stalkedThreadId === null) {
                        stalkedThreadId = Process.getCurrentThreadId();
                        Stalker.follow(stalkedThreadId, {
                            events: {
                                call: true
                            },
                            onReceive: function onReceive(events) {
                                send({ name: '+add', from: "/stalker/events", payload: { size: events.length } }, events);
                            }
                        });
                    }
                }
            }
        }
    });
}

setTimeout(initialize, 0);
"""
