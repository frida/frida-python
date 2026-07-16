class _Implementation:
    def _frida_dispatch(self, name, args, completion):
        loop = self._loop

        async def run():
            try:
                result = getattr(self, name)(*[_wrap(a) for a in args])
                if asyncio.iscoroutine(result):
                    result = await result
                result = _unwrap(result)
                error = None
            except Exception as e:
                result = None
                error = e
            _frida._complete_request(completion, result, error)

        _dispatch(loop, lambda: loop.create_task(run()))
