## So what is Frida, exactly?

It's Greasemonkey for native apps, or, put in more technical terms, it's a
dynamic code instrumentation toolkit. It lets you inject snippets of JavaScript
into native apps on Windows, Mac, Linux and iOS. Frida also provides you with
some simple tools built on top of the Frida API. These can be used as-is,
tweaked to your needs, or serve as examples of how to use the API.

## Why do I need this?

Great question. We'll try to clarify with some use-cases:

- There's this new hot app everybody's so excited about, but it's only
  available for iOS and you'd love to interop with it. You realize it's
  relying on encrypted network protocols and tools like Wireshark just
  won't cut it. You pick up Frida and use it for API tracing.
- You're building a desktop app which has been deployed at a customer's site.
  There's a problem but the built-in logging code just isn't enough. You
  need to send your customer a custom build with lots of expensive logging
  code. Then you realize you could just use Frida and build an application-
  specific tool that will add all the diagnostics you need, and in just a
  few lines of Python. No need to send the customer a new custom build - you
  just send the tool which will work on many versions of your app.
- You'd like to build a Wireshark on steroids with support for sniffing
  encrypted protocols. It could even manipulate function calls to fake network
  conditions that would otherwise require you to set up a test lab.
- Your in-house app could use some black-box tests without polluting your
  production code with logic only required for exotic testing.

## Why a Python API, but JavaScript debugging logic?

Frida's core is written in C and injects Google's V8 engine into the target
processes, where your JS gets executed with full access to memory, hooking
functions and even calling native functions inside the process. There's a
bi-directional communication channel that is used to talk between your
app (Python?) and the JS running inside the target process.

On top of this C core there are multiple language bindings (Python, .NET
and a browser plugin), and it is very easy to build further bindings for
other languages and environments (Node.js could be a future binding if
anyone's interested in helping out with that).

## So how do I get started?

Have a look at our [Quick-start Guide](http://www.frida.re/docs/quickstart/).
