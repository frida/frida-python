import sys
import frida
#import frida.tracer
import tracer

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: %s <process name>" % sys.argv[0]
        sys.exit(1)
    tp = tracer.TracerProfileBuilder().include_modules("*").exclude_modules("libSystem*").build()
    t = tracer.Tracer(tp)
    p = frida.attach(sys.argv[1])
    t.start_trace(p, tracer.STDOUT_SINK)
    sys.stdin.read()
    sys.exit(0)
