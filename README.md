Frida lets you build your own reverse-engineering tools in a few lines of Python.

```python
import frida
p = frida.attach("skype")
for m in p.enumerate_modules():
    print m.enumerate_exports()
```
