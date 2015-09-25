# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import binascii
import os
import platform
import re
import subprocess
import threading
import time

from frida.core import Module, ModuleFunction, ObjCMethod


class TracerProfileBuilder(object):
    _RE_REL_ADDRESS = re.compile("(?P<module>[^\s!]+)!(?P<offset>(0x)?[0-9a-fA-F]+)")

    def __init__(self):
        self._spec = []

    def include_modules(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('include', 'module', m))
        return self

    def exclude_modules(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('exclude', 'module', m))
        return self

    def include(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('include', 'function', f))
        return self

    def exclude(self, *function_name_globs):
        for f in function_name_globs:
            self._spec.append(('exclude', 'function', f))
        return self

    def include_relative_address(self, *address_rel_offsets):
        for f in address_rel_offsets:
            m = TracerProfileBuilder._RE_REL_ADDRESS.search(f)
            if m is None:
                continue
            self._spec.append(('include', 'relative_function', {
                'module': m.group('module'),
                'offset': int(m.group('offset'), base=16)
            }))

    def include_imports(self, *module_name_globs):
        for m in module_name_globs:
            self._spec.append(('include', 'imports', m))
        return self

    def include_objc_method(self, *function_name_globs):
        for f in function_name_globs:
            match = re.search(r"([+*-])\[(\S+)\s+(\S+)\]", f)
            if not match:
                raise Exception("Format: -[NS*Number foo:bar:], +[Foo foo*] or *[Bar baz]")
            mtype, cls, name = match.groups()
            self._spec.append(('include', 'objc_method', {
                'type': mtype,
                'cls': cls,
                'name': name
            }))

    def build(self):
        return TracerProfile(self._spec)

class TracerProfile(object):
    _BLACKLIST = set([
        "libSystem.B.dylib!dyld_stub_binder"
    ])

    def __init__(self, spec):
        self._spec = spec

    def resolve(self, session, log_handler=None):
        script = session.create_script(name="profile-resolver", source=self._create_resolver_script())
        script.set_log_handler(log_handler)
        result = [None, None]
        completed = threading.Event()
        def on_message(message, data):
            assert message['type'] == 'send'
            stanza = message['payload']
            if stanza['name'] == '+result':
                result[0] = stanza['payload']
            else:
                result[1] = Exception(stanza['payload'])
            completed.set()
        script.on('message', on_message)
        script.load()
        script.post_message(self._spec)
        completed.wait()
        if result[1] is not None:
            raise result[1]

        data = result[0]

        modules = {}
        for module_id, m in data['modules'].items():
            module = Module(m['name'], int(m['base'], 16), m['size'], m['path'], session)
            modules[int(module_id)] = module

        working_set = []
        for target in data['targets']:
            module_id = target.get('module')
            if module_id is not None:
                module = modules[module_id]
                relative_address = int(target["address"], 16) - module.base_address
                exported = not target.get('private', False)
                mf = ModuleFunction(module, target["name"], relative_address, exported)
                if not self._is_blacklisted(mf):
                    working_set.append(mf)
            else:
                objc = target['objc']
                method = objc['method']
                of = ObjCMethod(method['type'], objc['className'], method['name'], int(target['address'], 16))
                working_set.append(of)
        return working_set

    def _is_blacklisted(self, module_function):
        key = module_function.module.name + "!" + module_function.name
        return key in TracerProfile._BLACKLIST

    def _create_resolver_script(self):
        return r""""use strict";

recv(spec => {
    try {
        send({
            name: '+result',
            payload: resolve(spec)
        });
    } catch (e) {
        send({
            name: '+error',
            payload: e.stack
        });
    }
});

function resolve(spec) {
    const workingSet = spec.reduce((workingSet, item) => {
        const operation = item[0];
        const scope = item[1];
        const param = item[2];
        switch (scope) {
            case 'module':
                if (operation === 'include')
                    workingSet = includeModule(param, workingSet);
                else if (operation === 'exclude')
                    workingSet = excludeModule(param, workingSet);
                break;
            case 'function':
                if (operation === 'include')
                    workingSet = includeFunction(param, workingSet);
                else if (operation === 'exclude')
                    workingSet = excludeFunction(param, workingSet);
                break;
            case 'relative_function':
                if (operation === 'include')
                    workingSet = includeRelativeFunction(param, workingSet);
                break;
            case 'imports':
                if (operation === 'include')
                    workingSet = includeImports(param, workingSet);
                break;
            case 'objc_method':
                if (operation === 'include')
                    workingSet = includeObjCMethod(param, workingSet);
                break;
        }
        return workingSet;
    }, {});

    const modules = {};
    const targets = [];
    for (let address in workingSet) {
        if (workingSet.hasOwnProperty(address)) {
            const target = workingSet[address];
            const moduleId = target.module;
            if (moduleId !== undefined && !modules.hasOwnProperty(moduleId)) {
                const m = allModules()[moduleId];
                delete m._cachedFunctionExports;
                modules[moduleId] = m;
            }
            targets.push(target);
        }
    }
    return {
        modules: modules,
        targets: targets
    };
}

function includeModule(pattern, workingSet) {
    const mm = new Minimatch(pattern);
    const modules = allModules();
    for (let moduleIndex = 0; moduleIndex !== modules.length; moduleIndex++) {
        const module = modules[moduleIndex];
        if (mm.match(module.name)) {
            const functions = allFunctionExports(module);
            for (let functionIndex = 0; functionIndex !== functions.length; functionIndex++) {
                const func = functions[functionIndex];
                workingSet[func.address.toString()] = func;
            }
        }
    }
    return workingSet;
}

function excludeModule(pattern, workingSet) {
    const mm = new Minimatch(pattern);
    const modules = allModules();
    for (let address in workingSet) {
        if (workingSet.hasOwnProperty(address)) {
            const target = workingSet[address];
            const moduleId = target.module;
            if (moduleId !== undefined) {
                const module = modules[moduleId];
                if (mm.match(module.name))
                    delete workingSet[address];
            }
        }
    }
    return workingSet;
}

function includeFunction(pattern, workingSet) {
    const mm = new Minimatch(pattern);
    const modules = allModules();
    for (let moduleIndex = 0; moduleIndex !== modules.length; moduleIndex++) {
        const functions = allFunctionExports(modules[moduleIndex]);
        for (let functionIndex = 0; functionIndex !== functions.length; functionIndex++) {
            const func = functions[functionIndex];
            if (mm.match(func.name))
                workingSet[func.address.toString()] = func;
        }
    }
    return workingSet;
}

function excludeFunction(pattern, workingSet) {
    const mm = new Minimatch(pattern);
    for (let address in workingSet) {
        if (workingSet.hasOwnProperty(address)) {
            const target = workingSet[address];
            if (mm.match(target.name))
                delete workingSet[address];
        }
    }
    return workingSet;
}

function includeRelativeFunction(func, workingSet) {
    const relativeToModule = func.module;
    const modules = allModules();
    for (let moduleIndex = 0; moduleIndex !== modules.length; moduleIndex++) {
        const module = modules[moduleIndex];
        if (module.path === relativeToModule || module.name === relativeToModule) {
            const relativeAddress = ptr(func.offset);
            const absoluteAddress = module.base.add(relativeAddress);
            workingSet[absoluteAddress] = {
                name: "sub_" + relativeAddress.toString(16),
                address: absoluteAddress,
                module: moduleIndex,
                private: true
            };
        }
    }
    return workingSet;
}

function includeImports(pattern, workingSet) {
    const modules = [];
    if (pattern === null) {
        modules.push(allModules()[0]);
    } else {
        const mm = new Minimatch(pattern);
        for (let module of allModules()) {
            if (mm.match(module.name)) {
                modules.push(module);
                break;
            }
        }
    }

    for (let module of modules) {
        const functions = allFunctionImports(module);
        for (let func of functions)
            workingSet[func.address.toString()] = func;
    }

    return workingSet;
}

let cachedObjCState = null;
function includeObjCMethod(method, workingSet) {
    if (!ObjC.available)
        throw new Error("Objective C runtime is not available");

    if (cachedObjCState === null)
        cachedObjCState = getObjCState();
    const api = cachedObjCState.api;
    const classInfo = cachedObjCState.classInfo;

    const type = method.type;
    const clsMm = new Minimatch(method.cls);
    const methodMm = new Minimatch(method.name);

    function addImps(clsPtr) {
        const info = classInfo[clsPtr];
        const name = info.name;

        for (let i = 0; i != 2; i++) {
            const currentType = i === 0? '-': '+';
            const methods = i === 0? info.instanceMethods: info.classMethods;
            if (type !== currentType && type !== '*') {
                continue;
            }

            for (let methodName in methods) {
                if (methodMm.match(methodName)) {
                    const impPtr = methods[methodName];
                    if (!workingSet[impPtr]) {
                        workingSet[impPtr] = {
                            objc: {
                                className: name,
                                method: {
                                    type: currentType,
                                    name: methodName
                                }
                            },
                            address: impPtr
                        };
                    }
                }
           }
        }

        const subclasses = info.subclasses;
        for (let i = 0; i !== subclasses.length; i++)
            addImps(subclasses[i]);
    }

    for (let className in ObjC.classes) {
        if (clsMm.match(className)) {
            addImps(ObjC.classes[className].handle.toString());
        }
    }

    return workingSet;
}

function getObjCState() {
    const api = {};
    const apiSpec = {
        class_getSuperclass: 1,
        class_copyMethodList: 2,
        object_getClass: 1,
        method_getName: 1,
        method_getImplementation: 1,
        sel_getName: 1
    };
    Object.keys(apiSpec).forEach(name => {
        const funPtr = Module.findExportByName("libobjc.A.dylib", name);
        const argCount = apiSpec[name];
        const argTypes = [];
        for (let i = 0; i !== argCount; i++)
            argTypes.push('pointer');
        api[name] = new NativeFunction(funPtr, 'pointer', argTypes);
    });

    const freePtr = Module.findExportByName("libSystem.B.dylib", "free");
    const free = new NativeFunction(freePtr, 'void', ['pointer']);

    const methodCountPtr = Memory.alloc(4);
    function addMethods(clsHandle, methodObj) {
        const methods = api.class_copyMethodList(clsHandle, methodCountPtr);
        const methodCount = Memory.readU32(methodCountPtr);
        for (let i = 0; i !== methodCount; i++) {
            const method = Memory.readPointer(methods.add(i * Process.pointerSize));
            const sel = api.method_getName(method);
            const methodName = Memory.readUtf8String(api.sel_getName(sel));
            const imp = api.method_getImplementation(method);
            const impPtr = imp.toString();

            methodObj[methodName] = impPtr;
        }

        free(methods);
    }

    const classInfo = {};
    const classes = ObjC.classes;
    for (let className in classes) {
        const klass = classes[className];
        const clsHandle = klass.handle;
        const clsPtr = clsHandle.toString();
        classInfo[clsPtr] = {
            name: className,
            subclasses: [],
            instanceMethods: {},
            classMethods: {}
        };

        addMethods(clsHandle, classInfo[clsPtr].instanceMethods);
        addMethods(api.object_getClass(clsHandle), classInfo[clsPtr].classMethods);
    }
    for (let className in classes) {
        const clsHandle = classes[className].handle;
        const clsPtr = clsHandle.toString();
        const superCls = api.class_getSuperclass(clsHandle);
        if (!superCls.isNull()) {
            const superClsPtr = superCls.toString();
            classInfo[superClsPtr].subclasses.push(clsPtr);
        }
    }

    return {
        api: api,
        classInfo: classInfo
    };
}

let cachedModules = null;
function allModules() {
    if (cachedModules === null) {
        cachedModules = Process.enumerateModulesSync();
        cachedModules._idByPath = cachedModules.reduce((mappings, module, index) => {
            mappings[module.path] = index;
            return mappings;
        }, {});
    }
    return cachedModules;
}

function allFunctionImports(module) {
    if (!module.hasOwnProperty('_cachedFunctionImports')) {
        const moduleIdByPath = allModules()._idByPath;
        module._cachedFunctionImports = Module.enumerateImportsSync(module.path)
            .filter(isResolvedFunctionImport)
            .map(imp => {
                const value = {
                    name: imp.name,
                    address: imp.address
                };
                if (imp.hasOwnProperty('module')) {
                    const moduleId = moduleIdByPath[imp.module];
                    if (moduleId !== undefined) {
                        value.module = moduleId;
                    }
                }
                return value;
            });
    }

    return module._cachedFunctionImports;
}

function allFunctionExports(module) {
    if (!module.hasOwnProperty('_cachedFunctionExports')) {
        const moduleId = allModules().indexOf(module);
        module._cachedFunctionExports = Module.enumerateExportsSync(module.path)
            .filter(isFunctionExport)
            .map(exp => {
                exp.module = moduleId;
                return exp;
            });
    }

    return module._cachedFunctionExports;
}

function isResolvedFunctionImport(imp) {
    return imp.type === 'function' && imp.hasOwnProperty('address');
}

function isFunctionExport(exp) {
    return exp.type === 'function';
}


// MINIMATCH BEGIN
//
// Copyright 2009, 2010, 2011 Isaac Z. Schlueter.
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
const GLOBSTAR = Minimatch.GLOBSTAR = {};
const qmark = '[^/]';
const star = qmark + '*?';
const twoStarDot = '(?:(?!(?:\\\/|^)(?:\\.{1,2})($|\\\/)).)*?';
const twoStarNoDot = '(?:(?!(?:\\\/|^)\\.).)*?';
const reSpecials = charSet('().*{}+?[]^$\\!');

function charSet(s) {
    return s.split("").reduce((set, c) => {
        set[c] = true;
        return set;
    }, {});
}

const slashSplit = /\/+/;

function ext(a, b) {
    a = a || {};
    b = b || {};
    const t = {};
    Object.keys(b).forEach(k => {
        t[k] = b[k];
    });
    Object.keys(a).forEach(k => {
        t[k] = a[k];
    });
    return t;
}

function Minimatch(pattern, options) {
    if (!options)
        options = {};
    pattern = pattern.trim();

    this.options = options;
    this.set = [];
    this.pattern = pattern;
    this.regexp = null;
    this.negate = false;
    this.comment = false;
    this.empty = false;

    this.make();
}

Minimatch.prototype.make = function () {
    if (this._made)
        return;

    const pattern = this.pattern;
    const options = this.options;

    if (!options.nocomment && pattern.charAt(0) === '#') {
        this.comment = true;
        return;
    }
    if (!pattern) {
        this.empty = true;
        return;
    }

    this.parseNegate();

    let set = this.globSet = [this.pattern];

    set = this.globParts = set.map(s => {
        return s.split(slashSplit);
    });

    set = set.map((s, si, set) => {
        return s.map(this.parse, this);
    });

    set = set.filter(s => {
        return s.indexOf(false) === -1;
    });

    this.set = set;
};

Minimatch.prototype.parseNegate = function () {
    const pattern = this.pattern;
    let negate = false;
    const options = this.options;
    let negateOffset = 0;

    if (options.nonegate)
        return;

    for (let i = 0, l = pattern.length; i < l && pattern.charAt(i) === '!'; i++) {
        negate = !negate;
        negateOffset++;
    }

    if (negateOffset)
        this.pattern = pattern.substr(negateOffset);
    this.negate = negate;
};

const SUBPARSE = {};
Minimatch.prototype.parse = function (pattern, isSub) {
    const options = this.options;

    if (!options.noglobstar && pattern === '**')
        return GLOBSTAR;
    if (pattern === '')
        return '';

    let re = '';
    let hasMagic = !!options.nocase;
    let escaping = false;
    const patternListStack = [];
    let stateChar;
    let inClass = false;
    let reClassStart = -1;
    let classStart = -1;
    let plType, cs;
    const patternStart = pattern.charAt(0) === '.' ? '' : options.dot ? '(?!(?:^|\\\/)\\.{1,2}(?:$|\\\/))' : '(?!\\.)';

    function clearStateChar () {
        if (stateChar) {
            switch (stateChar) {
                case '*':
                    re += star;
                    hasMagic = true;
                    break;
                case '?':
                    re += qmark;
                    hasMagic = true;
                    break;
                default:
                    re += '\\' + stateChar;
                    break;
            }
            stateChar = false;
        }
    }

    for (let i = 0, len = pattern.length, c; (i < len) && (c = pattern.charAt(i)); i++) {
        if (escaping && reSpecials[c]) {
            re += '\\' + c;
            escaping = false;
            continue;
        }

        switch (c) {
            case '/':
                return false;

            case '\\':
                clearStateChar();
                escaping = true;
                continue;

            case '?':
            case '*':
            case '+':
            case '@':
            case '!':
                if (inClass) {
                    if (c === '!' && i === classStart + 1)
                        c = '^';
                    re += c;
                    continue;
                }

                clearStateChar();
                stateChar = c;

                if (options.noext)
                    clearStateChar();

                continue;

            case '(': {
                if (inClass) {
                    re += '(';
                    continue;
                }

                if (!stateChar) {
                    re += '\\(';
                    continue;
                }

                plType = stateChar;
                patternListStack.push({ type: plType, start: i - 1, reStart: re.length });
                re += stateChar === '!' ? '(?:(?!' : '(?:';
                stateChar = false;

                continue;
            }
            case ')': {
                if (inClass || !patternListStack.length) {
                    re += '\\)';
                    continue;
                }

                clearStateChar();
                hasMagic = true;
                re += ')';
                plType = patternListStack.pop().type;
                switch (plType) {
                    case '!':
                        re += '[^/]*?)';
                        break;
                    case '?':
                    case '+':
                    case '*':
                        re += plType;
                        break;
                    case '@':
                        break;
                }

                continue;
            }
            case '|':
                if (inClass || !patternListStack.length || escaping) {
                    re += '\\|';
                    escaping = false;
                    continue;
                }

                clearStateChar();
                re += '|';

                continue;

            case '[':
                clearStateChar();

                if (inClass) {
                    re += '\\' + c;
                    continue;
                }

                inClass = true;
                classStart = i;
                reClassStart = re.length;
                re += c;

                continue;

            case ']':
                if (i === classStart + 1 || !inClass) {
                    re += '\\' + c;
                    escaping = false;
                    continue;
                }

                if (inClass) {
                    cs = pattern.substring(classStart + 1, i);
                    try {
                        new RegExp('[' + cs + ']');
                    } catch (er) {
                        const sp = this.parse(cs, SUBPARSE);
                        re = re.substr(0, reClassStart) + '\\[' + sp[0] + '\\]';
                        hasMagic = hasMagic || sp[1];
                        inClass = false;
                        continue;
                    }
                }

                hasMagic = true;
                inClass = false;
                re += c;

                continue;

            default:
                clearStateChar();

                if (escaping)
                    escaping = false;
                else if (reSpecials[c] && !(c === '^' && inClass))
                    re += '\\';

                re += c;
        }
    }

    if (inClass) {
        cs = pattern.substr(classStart + 1);
        const sp = this.parse(cs, SUBPARSE);
        re = re.substr(0, reClassStart) + '\\[' + sp[0];
        hasMagic = hasMagic || sp[1];
    }

    for (let pl = patternListStack.pop(); pl; pl = patternListStack.pop()) {
        let tail = re.slice(pl.reStart + 3);
        tail = tail.replace(/((?:\\{2})*)(\\?)\|/g, (_, $1, $2) => {
            if (!$2)
                $2 = '\\';

            return $1 + $1 + $2 + '|';
        });

        const t = pl.type === '*' ? star : pl.type === '?' ? qmark : '\\' + pl.type;
        hasMagic = true;
        re = re.slice(0, pl.reStart) + t + '\\(' + tail;
    }

    clearStateChar();
    if (escaping)
        re += '\\\\';

    let addPatternStart = false;
    switch (re.charAt(0)) {
        case '.':
        case '[':
        case '(':
            addPatternStart = true;
    }

    if (re !== '' && hasMagic)
        re = '(?=.)' + re;

    if (addPatternStart)
        re = patternStart + re;

    if (isSub === SUBPARSE)
        return [re, hasMagic];

    if (!hasMagic)
        return globUnescape(pattern);

    const flags = options.nocase ? 'i' : '';
    const regExp = new RegExp('^' + re + '$', flags);

    regExp._glob = pattern;
    regExp._src = re;

    return regExp;
};

Minimatch.prototype.makeRe = function () {
    if (this.regexp || this.regexp === false)
        return this.regexp;

    const set = this.set;

    if (!set.length) {
        this.regexp = false;
        return this.regexp;
    }
    const options = this.options;

    const twoStar = options.noglobstar ? star : options.dot ? twoStarDot : twoStarNoDot;
    const flags = options.nocase ? 'i' : '';

    let re = set.map(pattern => {
        return pattern.map(p => {
            return (p === GLOBSTAR) ? twoStar : (typeof p === 'string') ? regExpEscape(p) : p._src;
        }).join('\\\/');
    }).join('|');

    re = '^(?:' + re + ')$';

    if (this.negate)
        re = '^(?!' + re + ').*$';

    try {
        this.regexp = new RegExp(re, flags);
    } catch (ex) {
        this.regexp = false;
    }
    return this.regexp;
};

Minimatch.prototype.match = function (f, partial) {
    if (this.comment)
        return false;
    if (this.empty)
        return f === '';

    if (f === '/' && partial)
        return true;

    const options = this.options;

    f = f.split(slashSplit);

    const set = this.set;

    let filename;
    let i;
    for (i = f.length - 1; i >= 0; i--) {
        filename = f[i];
        if (filename)
            break;
    }

    for (i = 0; i < set.length; i++) {
        const pattern = set[i];
        const file = (options.matchBase && pattern.length === 1) ? [filename] : f;
        const hit = this.matchOne(file, pattern, partial);
        if (hit) {
            if (options.flipNegate)
                return true;
            return !this.negate;
        }
    }

    if (options.flipNegate)
        return false;
    return this.negate;
};

Minimatch.prototype.matchOne = function (file, pattern, partial) {
    const options = this.options;

    let fi, pi, fl, pl;
    for (fi = 0, pi = 0, fl = file.length, pl = pattern.length; (fi < fl) && (pi < pl); fi++, pi++) {
        const p = pattern[pi];
        const f = file[fi];

        if (p === false)
            return false;

        if (p === GLOBSTAR) {
            let fr = fi;
            const pr = pi + 1;

            if (pr === pl) {
                for (; fi < fl; fi++) {
                    if (file[fi] === '.' || file[fi] === '..' || (!options.dot && file[fi].charAt(0) === '.'))
                        return false;
                }
                return true;
            }

            while (fr < fl) {
                const swallowee = file[fr];

                if (this.matchOne(file.slice(fr), pattern.slice(pr), partial)) {
                    return true;
                } else {
                    if (swallowee === '.' || swallowee === '..' || (!options.dot && swallowee.charAt(0) === '.'))
                        break;
                    fr++;
                }
            }

            if (partial && fr === fl)
                return true;

            return false;
        }

        let hit;
        if (typeof p === 'string') {
            if (options.nocase)
                hit = f.toLowerCase() === p.toLowerCase();
            else
                hit = f === p;
        } else {
            hit = f.match(p);
        }

        if (!hit)
            return false;
    }

    if (fi === fl && pi === pl) {
        return true;
    } else if (fi === fl) {
        return partial;
    } else if (pi === pl) {
        const emptyFileEnd = (fi === fl - 1) && (file[fi] === '');
        return emptyFileEnd;
    }

    throw new Error('wtf?');
};

function globUnescape(s) {
    return s.replace(/\\(.)/g, '$1');
}

function regExpEscape(s) {
    return s.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
}
// MINIMATCH END
"""

class Tracer(object):
    def __init__(self, reactor, repository, profile, log_handler=None):
        self._reactor = reactor
        self._repository = repository
        self._profile = profile
        self._script = None
        self._log_handler = log_handler

    def start_trace(self, session, ui):
        def on_create(*args):
            ui.on_trace_handler_create(*args)
        self._repository.on_create(on_create)

        def on_load(*args):
            ui.on_trace_handler_load(*args)
        self._repository.on_load(on_load)

        def on_update(function, handler, source):
            self._script.post_message({
                'to': "/targets",
                'name': '+update',
                'payload': {
                    'items': [{
                        'name': function.name,
                        'absolute_address': hex(function.absolute_address),
                        'handler': handler
                    }]
                }
            })
        self._repository.on_update(on_update)

        def on_message(message, data):
            self._reactor.schedule(lambda: self._process_message(message, data, ui))

        ui.on_trace_progress('resolve')
        working_set = self._profile.resolve(session, log_handler=self._log_handler)
        ui.on_trace_progress('instrument')
        self._script = session.create_script(name="tracer", source=self._create_trace_script())
        self._script.set_log_handler(self._log_handler)
        self._script.on('message', on_message)
        self._script.load()
        for chunk in [working_set[i:i+1000] for i in range(0, len(working_set), 1000)]:
            targets = [{
                    'name': function.name,
                    'absolute_address': hex(function.absolute_address),
                    'handler': self._repository.ensure_handler(function)
                } for function in chunk]
            self._script.post_message({
                'to': "/targets",
                'name': '+add',
                'payload': {
                    'items': targets
                }
            })

        self._script.post_message({
            'to': "/targets",
            'name': '+start',
            'payload': {}
        })

        return working_set

    def stop(self):
        if self._script is not None:
            try:
                self._script.unload()
            except:
                pass
            self._script = None

    def _create_trace_script(self):
        return """"use strict";

const started = Date.now();
const pending = [];
let timer = null;
const handlers = {};
const state = {};
function onStanza(stanza) {
    if (stanza.to === "/targets") {
        if (stanza.name === '+add') {
            add(stanza.payload.items);
        } else if (stanza.name === '+update') {
            update(stanza.payload.items);
        } else if (stanza.name === '+start') {
            start();
        }
    }

    recv(onStanza);
}
function add(targets) {
    targets.forEach(target => {
        const handler = parseHandler(target);
        if (handler === null)
            return;
        const name = target.name;
        const targetAddress = target.absolute_address;
        target = null;

        const h = [handler];
        handlers[targetAddress] = h;

        function invokeCallback(callback, context, param) {
            if (callback === undefined)
                return;

            const timestamp = Date.now() - started;
            const threadId = context.threadId;
            const depth = context.depth;

            function log(message) {
                emit([timestamp, threadId, depth, targetAddress, message]);
            }

            callback.call(context, log, param, state);
        }

        pending.push(() => {
            try {
                Interceptor.attach(ptr(targetAddress), {
                    onEnter(args) {
                        invokeCallback(h[0].onEnter, this, args);
                    },
                    onLeave(retval) {
                        invokeCallback(h[0].onLeave, this, retval);
                    }
                });
            } catch (e) {
                send({
                    from: "/targets",
                    name: '+error',
                    payload: {
                        message: "Skipping '" + name + "': " + e.message
                    }
                });
            }
        });
    });

    scheduleNext();
}
function update(targets) {
    targets.forEach(target => {
        handlers[target.absolute_address][0] = parseHandler(target);
    });
}
function emit(event) {
    send({
        from: "/events",
        name: '+add',
        payload: {
            items: [event]
        }
    });
}
function parseHandler(target) {
    try {
        return (1, eval)("(" + target.handler + ")");
    } catch (e) {
        send({
            from: "/targets",
            name: '+error',
            payload: {
                message: "Invalid handler for '" + target.name + "': " + e.message
            }
        });
        return null;
    }
}
function start() {
    pending.push(() => {
        send({
            from: "/targets",
            name: '+started',
            payload: {}
        });
    });
    scheduleNext();
}
function scheduleNext() {
    if (timer === null) {
        timer = setTimeout(processNext, 0);
    }
}
function processNext() {
    timer = null;

    if (pending.length > 0) {
        const work = pending.shift();
        work();
        scheduleNext();
    }
}
recv(onStanza);
"""

    def _process_message(self, message, data, ui):
        handled = False
        if message['type'] == 'send':
            stanza = message['payload']
            if stanza['from'] == "/events" and stanza['name'] == '+add':
                events = [(timestamp, thread_id, depth, int(target_address.rstrip("L"), 16), message) for timestamp, thread_id, depth, target_address, message in stanza['payload']['items']]

                ui.on_trace_events(events)

                target_addresses = set([target_address for timestamp, thread_id, depth, target_address, message in events])
                for target_address in target_addresses:
                    self._repository.sync_handler(target_address)

                handled = True
            elif stanza['from'] == "/targets" and stanza['name'] == '+started':
                ui.on_trace_progress('ready')
                handled = True
            elif stanza['from'] == "/targets" and stanza['name'] == '+error':
                ui.on_trace_error(stanza['payload'])
                handled = True
        if not handled:
            print(message)

class Repository(object):
    def __init__(self):
        self._on_create_callback = None
        self._on_load_callback = None
        self._on_update_callback = None

    def ensure_handler(self, function):
        raise NotImplementedError("not implemented")

    def sync_handler(self, function_address):
        pass

    def on_create(self, callback):
        self._on_create_callback = callback

    def on_load(self, callback):
        self._on_load_callback = callback

    def on_update(self, callback):
        self._on_update_callback = callback

    def _notify_create(self, function, handler, source):
        if self._on_create_callback is not None:
            self._on_create_callback(function, handler, source)

    def _notify_load(self, function, handler, source):
        if self._on_load_callback is not None:
            self._on_load_callback(function, handler, source)

    def _notify_update(self, function, handler, source):
        if self._on_update_callback is not None:
            self._on_update_callback(function, handler, source)

    def _create_stub_handler(self, function):
        if isinstance(function, ObjCMethod):
            display_name = function.display_name()
            _nonlocal_i = {'val': 2}
            def objc_arg(m):
                r = ':" + args[%d] + " ' % _nonlocal_i['val']
                _nonlocal_i['val'] += 1
                return r

            log_str = '"' + re.sub(r':', objc_arg, display_name) + '"'
        else:
            display_name = function.name

            args = ""
            argc = 0
            varargs = False
            try:
                with open(os.devnull, 'w') as devnull:
                    man_argv = ["man"]
                    if platform.system() != "Darwin":
                        man_argv.extend(["-E", "UTF-8"])
                    man_argv.extend(["-P", "col -b", "2", function.name])
                    output = subprocess.check_output(man_argv, stderr=devnull)
                match = re.search(r"^SYNOPSIS(?:.|\n)*?((?:^.+$\n)* {5}" + function.name + r"\(.*\n(^.+$\n)*)(?:.|\n)*^DESCRIPTION", output.decode('UTF-8', errors='replace'), re.MULTILINE)
                if match:
                    decl = match.group(1)
                    for argm in re.finditer(r"([^* ]*)\s*(,|\))", decl):
                        arg = argm.group(1)
                        if arg == 'void':
                            continue
                        if arg == '...':
                            args += '+ ", ..."'
                            varargs = True
                            continue

                        args += '%(pre)s%(arg)s=" + args[%(argc)s]' % {"arg": arg, "argc": argc, "pre": '"' if argc == 0 else '+ ", '}
                        argc += 1
            except Exception as e:
                pass
            if args == "":
                args = '""'

            log_str = '"%(name)s(" + %(args)s + ")"' % { "name": function.name, "args": args }

        return """\
/*
 * Auto-generated by Frida. Please modify to match the signature of %(display_name)s.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: http://www.frida.re/docs/javascript-api/
 */

{
    /**
     * Called synchronously when about to call %(display_name)s.
     *
     * @this {object} - Object allowing you to store state for use in onLeave.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {array} args - Function arguments represented as an array of NativePointer objects.
     * For example use Memory.readUtf8String(args[0]) if the first argument is a pointer to a C string encoded as UTF-8.
     * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
     * @param {object} state - Object allowing you to keep state across function calls.
     * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
     * However, do not use this to store function arguments across onEnter/onLeave, but instead
     * use "this" which is an object for keeping state local to an invocation.
     */
    onEnter(log, args, state) {
        log(%(log_str)s);
    },

    /**
     * Called synchronously when about to return from %(display_name)s.
     *
     * See onEnter for details.
     *
     * @this {object} - Object allowing you to access state stored in onEnter.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {NativePointer} retval - Return value represented as a NativePointer object.
     * @param {object} state - Object allowing you to keep state across function calls.
     */
    onLeave(log, retval, state) {
    }
}
""" % {"display_name": display_name, "log_str": log_str}

class MemoryRepository(Repository):
    def __init__(self):
        super(MemoryRepository, self).__init__()
        self._handlers = {}

    def ensure_handler(self, function):
        handler = self._handlers.get(function)
        if handler is None:
            handler = self._create_stub_handler(function)
            self._handlers[function] = handler
            self._notify_create(function, handler, "memory")
        else:
            self._notify_load(function, handler, "memory")
        return handler

class FileRepository(Repository):
    def __init__(self):
        super(FileRepository, self).__init__()
        self._handlers = {}
        self._repo_dir = os.path.join(os.getcwd(), "__handlers__")

    def ensure_handler(self, function):
        entry = self._handlers.get(function.absolute_address)
        if entry is not None:
            (function, handler, handler_file, handler_mtime, last_sync) = entry
            return handler

        handler = None
        handler_files_to_try = []

        if isinstance(function, ModuleFunction):
            module_dir = os.path.join(self._repo_dir, to_filename(function.module.name))
            module_handler_file = os.path.join(module_dir, to_handler_filename(function.name))
            handler_files_to_try.append(module_handler_file)

        any_module_handler_file = os.path.join(self._repo_dir, to_handler_filename(function.name))
        handler_files_to_try.append(any_module_handler_file)

        for handler_file in handler_files_to_try:
            if os.path.isfile(handler_file):
                with open(handler_file, 'r') as f:
                    handler = f.read()
                self._notify_load(function, handler, handler_file)
                break

        if handler is None:
            handler = self._create_stub_handler(function)
            handler_file = handler_files_to_try[0]
            handler_dir = os.path.dirname(handler_file)
            if not os.path.isdir(handler_dir):
                os.makedirs(handler_dir)
            with open(handler_file, 'w') as f:
                f.write(handler)
            self._notify_create(function, handler, handler_file)

        handler_mtime = os.stat(handler_file).st_mtime
        self._handlers[function.absolute_address] = (function, handler, handler_file, handler_mtime, time.time())

        return handler

    def sync_handler(self, function_address):
        (function, handler, handler_file, handler_mtime, last_sync) = self._handlers[function_address]
        delta = time.time() - last_sync
        if delta >= 1.0:
            changed = False

            try:
                new_mtime = os.stat(handler_file).st_mtime
                if new_mtime != handler_mtime:
                    with open(handler_file, 'r') as f:
                        new_handler = f.read()
                    changed = new_handler != handler
                    handler = new_handler
                    handler_mtime = new_mtime
            except:
                pass

            self._handlers[function_address] = (function, handler, handler_file, handler_mtime, time.time())

            if changed:
                self._notify_update(function, handler, handler_file)

class UI(object):
    def on_trace_progress(self, operation):
        pass

    def on_trace_error(self, error):
        pass

    def on_trace_events(self, events):
        pass

    def on_trace_handler_create(self, function, handler, source):
        pass

    def on_trace_handler_load(self, function, handler, source):
        pass


def main():
    from colorama import Fore, Style
    from frida.application import ConsoleApplication, input_with_timeout

    class TracerApplication(ConsoleApplication, UI):
        def __init__(self):
            super(TracerApplication, self).__init__(self._await_ctrl_c)
            self._palette = [Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.GREEN, Fore.RED, Fore.BLUE]
            self._nextColor = 0
            self._attributes_by_thread_id = {}
            self._last_event_tid = -1

        def _add_options(self, parser):
            pb = TracerProfileBuilder()
            def process_builder_arg(option, opt_str, value, parser, method, **kwargs):
                method(value)
            parser.add_option("-I", "--include-module", help="include MODULE", metavar="MODULE",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_modules,))
            parser.add_option("-X", "--exclude-module", help="exclude MODULE", metavar="MODULE",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.exclude_modules,))
            parser.add_option("-i", "--include", help="include FUNCTION", metavar="FUNCTION",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include,))
            parser.add_option("-x", "--exclude", help="exclude FUNCTION", metavar="FUNCTION",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.exclude,))
            parser.add_option("-a", "--add", help="add MODULE!OFFSET", metavar="MODULE!OFFSET",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_relative_address,))
            parser.add_option("-T", "--include-imports", help="include program's imports",
                    action='callback', callback=process_builder_arg, callback_args=(pb.include_imports,))
            parser.add_option("-t", "--include-module-imports", help="include MODULE imports", metavar="MODULE",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_imports,))
            parser.add_option("-m", "--include-objc-method", help="include OBJC_METHOD", metavar="OBJC_METHOD",
                    type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include_objc_method,))
            self._profile_builder = pb

        def _usage(self):
            return "usage: %prog [options] target"

        def _initialize(self, parser, options, args):
            self._tracer = None
            self._targets = None
            self._profile = self._profile_builder.build()

        def _needs_target(self):
            return True

        def _start(self):
            self._tracer = Tracer(self._reactor, FileRepository(), self._profile, log_handler=self._log)
            self._targets = self._tracer.start_trace(self._session, self)

        def _stop(self):
            self._print("Stopping...")
            self._tracer.stop()
            self._tracer = None

        def _await_ctrl_c(self, reactor):
            while reactor.is_running():
                try:
                    input_with_timeout(0.5)
                except KeyboardInterrupt:
                    break

        def on_trace_progress(self, operation):
            if operation == 'resolve':
                self._update_status("Resolving functions...")
            elif operation == 'instrument':
                self._update_status("Instrumenting functions...")
            elif operation == 'ready':
                if len(self._targets) == 1:
                    plural = ""
                else:
                    plural = "s"
                self._update_status("Started tracing %d function%s. Press Ctrl+C to stop." % (len(self._targets), plural))
                self._resume()

        def on_trace_error(self, error):
            self._print(Fore.RED + Style.BRIGHT + "Error" + Style.RESET_ALL + ": " + error['message'])

        def on_trace_events(self, events):
            no_attributes = Style.RESET_ALL
            for timestamp, thread_id, depth, target_address, message in events:
                indent = depth * "   | "
                attributes = self._get_attributes(thread_id)
                if thread_id != self._last_event_tid:
                    self._print("%s           /* TID 0x%x */%s" % (attributes, thread_id, Style.RESET_ALL))
                    self._last_event_tid = thread_id
                self._print("%6d ms  %s%s%s%s" % (timestamp, attributes, indent, message, no_attributes))

        def on_trace_handler_create(self, function, handler, source):
            self._print("%s: Auto-generated handler at \"%s\"" % (function, source))

        def on_trace_handler_load(self, function, handler, source):
            self._print("%s: Loaded handler at \"%s\"" % (function, source))

        def _get_attributes(self, thread_id):
            attributes = self._attributes_by_thread_id.get(thread_id, None)
            if attributes is None:
                color = self._nextColor
                self._nextColor += 1
                attributes = self._palette[color % len(self._palette)]
                if (1 + int(color / len(self._palette))) % 2 == 0:
                    attributes += Style.BRIGHT
                self._attributes_by_thread_id[thread_id] = attributes
            return attributes

    app = TracerApplication()
    app.run()

def to_filename(name):
    result = ""
    for c in name:
        if c.isalnum() or c == ".":
            result += c
        else:
            result += "_"
    return result

def to_handler_filename(name):
    full_filename = to_filename(name)
    if len(full_filename) <= 41:
        return full_filename + ".js"
    crc = binascii.crc32(full_filename.encode())
    return full_filename[0:32] + "_%08x.js" % crc

if __name__ == '__main__':
    main()
