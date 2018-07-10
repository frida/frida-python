class Module(object):
    def __init__(self, name, base_address, size, path):
        self.name = name
        self.base_address = base_address
        self.size = size
        self.path = path

    def __repr__(self):
        return "Module(name=\"%s\", base_address=0x%x, size=%d, path=\"%s\")" % (self.name, self.base_address, self.size, self.path)

    def __hash__(self):
        return self.base_address.__hash__()

    def __cmp__(self, other):
        return self.base_address.__cmp__(other.base_address)

    def __eq__(self, other):
        return self.base_address == other.base_address

    def __ne__(self, other):
        return self.base_address != other.base_address


class Function(object):
    def __init__(self, name, absolute_address):
        self.name = name
        self.absolute_address = absolute_address

    def __str__(self):
        return self.name

    def __repr__(self):
        return "Function(name=\"%s\", absolute_address=0x%x)" % (self.name, self.absolute_address)

    def __hash__(self):
        return self.absolute_address.__hash__()

    def __cmp__(self, other):
        return self.absolute_address.__cmp__(other.absolute_address)

    def __eq__(self, other):
        return self.absolute_address == other.absolute_address

    def __ne__(self, other):
        return self.absolute_address != other.absolute_address


class ModuleFunction(Function):
    def __init__(self, module, name, relative_address, exported):
        super(ModuleFunction, self).__init__(name, module.base_address + relative_address)
        self.module = module
        self.relative_address = relative_address
        self.exported = exported

    def __repr__(self):
        return "ModuleFunction(module=\"%s\", name=\"%s\", relative_address=0x%x)" % (self.module.name, self.name, self.relative_address)


class ObjCMethod(Function):
    def __init__(self, mtype, cls, method, address):
        self.mtype = mtype
        self.cls = cls
        self.method = method
        self.address = address
        super(ObjCMethod, self).__init__(self.display_name(), address)

    def display_name(self):
        return '{mtype}[{cls} {method}]'.format(mtype=self.mtype, cls=self.cls, method=self.method)

    def __repr__(self):
        return "ObjCMethod(mtype=\"%s\", cls=\"%s\", method=\"%s\", address=0x%x)" % (self.mtype, self.cls, self.method, self.address)
