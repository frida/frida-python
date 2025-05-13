from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

from .model import Customizations, Model, parse_gir

INCLUDED_GIO_OBJECT_TYPES = [
    "Cancellable",
    "IOStream",
    "InputStream",
    "OutputStream",
    "InetSocketAddress",
    "InetAddress",
    "UnixSocketAddress",
    "SocketAddress",
    "SocketAddressEnumerator",
    "SocketConnectable",
]
INCLUDED_GIO_ENUMERATIONS = [
    "FileMonitorEvent",
    "SocketFamily",
    "UnixSocketAddressType",
]


def compute_model(
    frida_gir: Path,
    glib_gir: Path,
    gobject_gir: Path,
    gio_gir: Path,
    customizations: Customizations,
) -> Model:
    glib = parse_gir(glib_gir, [])
    gobject = parse_gir(gobject_gir, [glib])
    gio = parse_gir(gio_gir, [glib, gobject])
    frida = parse_gir(frida_gir, [glib, gobject, gio])

    object_types = OrderedDict(frida.object_types)
    object_types["Object"] = gobject.object_types["Object"]
    for t in INCLUDED_GIO_OBJECT_TYPES:
        object_types[t] = gio.object_types[t]

    enumerations = OrderedDict(frida.enumerations)
    for t in INCLUDED_GIO_ENUMERATIONS:
        enumerations[t] = gio.enumerations[t]

    model = Model(
        frida.namespace,
        object_types,
        enumerations,
        customizations,
    )

    for t in object_types.values():
        t.model = model
    for t in enumerations.values():
        t.model = model

    return model
