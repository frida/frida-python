import sys
import frida
#import frida.tracer
import tracer

if __name__ == '__main__':
    tp = tracer.TracerProfileBuilder().include("read").build()
    t = tracer.Tracer(tp)
    p = frida.attach("cat")
    t.start_trace(p, tracer.STDOUT_SINK)
    sys.stdin.read()
