def _to_camel_case(name):
    result = ""
    capitalize = False
    for ch in name:
        if ch == "_":
            capitalize = True
        elif capitalize:
            result += ch.upper()
            capitalize = False
        else:
            result += ch
    return result


class RPCException(Exception):
    def __str__(self):
        return str(self.args[2]) if len(self.args) >= 3 else str(self.args[0])


class _ScriptExports:
    def __init__(self, script):
        self._script = script

    def __getattr__(self, name):
        script = self._script
        js_name = _to_camel_case(name)

        def method(*args):
            if args and isinstance(args[-1], bytes):
                params, data = list(args[:-1]), args[-1]
            else:
                params, data = list(args), None
            return script._rpc_request(["call", js_name, params], data)

        return method

    def __dir__(self):
        return self._script._list_exports()
