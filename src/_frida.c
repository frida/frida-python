/*
 * Copyright (C) 2013-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <frida-core.h>

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4115)
# pragma warning (disable: 4211)
#endif
#ifdef _POSIX_C_SOURCE
# undef _POSIX_C_SOURCE
#endif

/*
 * Don't propogate _DEBUG state to pyconfig as it incorrectly attempts to load
 * debug libraries that don't normally ship with Python (e.g. 2.x). Debuggers
 * wishing to spelunk the Python core can override this workaround by defining
 * _FRIDA_ENABLE_PYDEBUG.
 */
#if defined (_DEBUG) && !defined (_FRIDA_ENABLE_PYDEBUG)
# undef _DEBUG
# include <pyconfig.h>
# define _DEBUG
#else
# include <pyconfig.h>
#endif

#include <Python.h>
#include <structmember.h>
#ifdef _MSC_VER
# pragma warning (pop)
#endif
#ifdef HAVE_MAC
# include <crt_externs.h>
#endif

#define PyUnicode_FromUTF8String(str) PyUnicode_DecodeUTF8 (str, strlen (str), "strict")
#if PY_MAJOR_VERSION >= 3
# define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name (void)
# define MOD_DEF(ob, name, doc, methods) \
  { \
    static struct PyModuleDef moduledef = { \
        PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
    ob = PyModule_Create (&moduledef); \
  }
# define MOD_SUCCESS_VAL(val) val
# define MOD_ERROR_VAL NULL
# define PyRepr_FromFormat PyUnicode_FromFormat
# define PYFRIDA_GETARGSPEC_FUNCTION "getfullargspec"
#else
# define MOD_INIT(name) PyMODINIT_FUNC init##name (void)
# define MOD_DEF(ob, name, doc, methods) \
  ob = Py_InitModule3 (name, methods, doc);
# define MOD_SUCCESS_VAL(val)
# define MOD_ERROR_VAL
# define PyRepr_FromFormat PyString_FromFormat
# define PYFRIDA_GETARGSPEC_FUNCTION "getargspec"
#endif

#define PYFRIDA_TYPE(name) \
  G_PASTE (G_PASTE (Py, name), Type)
#define PYFRIDA_TYPE_SPEC(name) \
  G_PASTE (PYFRIDA_TYPE (name), _type_spec)
#define PYFRIDA_DEFINE_TYPE(name, init_from_handle, destroy) \
  static const PyGObjectTypeSpec PYFRIDA_TYPE_SPEC (name) = { &PYFRIDA_TYPE (name), init_from_handle, destroy }
#define PYFRIDA_REGISTER_TYPE(name, gtype) \
  G_BEGIN_DECLS \
  { \
    PyTypeObject * pytype = &PYFRIDA_TYPE (name); \
    pytype->tp_new = PyType_GenericNew; \
    if (PyType_Ready (pytype) < 0) \
      return MOD_ERROR_VAL; \
    PyGObject_register_type (gtype, &PYFRIDA_TYPE_SPEC (name)); \
    Py_INCREF (pytype); \
    PyModule_AddObject (module, G_STRINGIFY (name), (PyObject *) pytype); \
  } \
  G_END_DECLS

#define PY_GOBJECT(o) ((PyGObject *) (o))
#define PY_GOBJECT_HANDLE(o) (PY_GOBJECT (o)->handle)
#define PY_GOBJECT_SIGNAL_CLOSURE(o) ((PyGObjectSignalClosure *) (o))

#define FRIDA_FUNCPTR_TO_POINTER(f) (GSIZE_TO_POINTER (f))

static PyObject * inspect_getargspec;
static PyObject * inspect_ismethod;

static GHashTable * pygobject_type_spec_by_type;
static GHashTable * exception_by_error_code;

typedef struct _PyGObject                      PyGObject;
typedef struct _PyGObjectTypeSpec              PyGObjectTypeSpec;
typedef struct _PyGObjectSignalClosure         PyGObjectSignalClosure;
typedef struct _PyDeviceManager                PyDeviceManager;
typedef struct _PyDevice                       PyDevice;
typedef struct _PyApplication                  PyApplication;
typedef struct _PyProcess                      PyProcess;
typedef struct _PySpawn                        PySpawn;
typedef struct _PyIcon                         PyIcon;
typedef struct _PySession                      PySession;
typedef struct _PyScript                       PyScript;
typedef struct _PyFileMonitor                  PyFileMonitor;

typedef void (* PyGObjectInitFromHandleFunc) (PyObject * self, gpointer handle);

struct _PyGObject
{
  PyObject_HEAD

  gpointer handle;
  const PyGObjectTypeSpec * spec;

  GSList * signal_closures;
};

struct _PyGObjectTypeSpec
{
  PyTypeObject * type;
  gpointer init_from_handle;
  GDestroyNotify destroy;
};

struct _PyGObjectSignalClosure
{
  GClosure parent;
  guint signal_id;
  guint max_arg_count;
};

struct _PyDeviceManager
{
  PyGObject parent;
};

struct _PyDevice
{
  PyGObject parent;
  PyObject * id;
  PyObject * name;
  PyObject * icon;
  PyObject * type;
};

struct _PyApplication
{
  PyGObject parent;
  PyObject * identifier;
  PyObject * name;
  guint pid;
};

struct _PyProcess
{
  PyGObject parent;
  guint pid;
  PyObject * name;
};

struct _PySpawn
{
  PyGObject parent;
  guint pid;
  PyObject * identifier;
};

struct _PyIcon
{
  PyGObject parent;
  gint width;
  gint height;
  gint rowstride;
  PyObject * pixels;
};

struct _PySession
{
  PyGObject parent;
  guint pid;
};

struct _PyScript
{
  PyGObject parent;
};

struct _PyFileMonitor
{
  PyGObject parent;
  GFile * file;
  GFileMonitor * monitor;
  GList * on_change;
};

static PyObject * PyGObject_new_take_handle (gpointer handle, const PyGObjectTypeSpec * spec);
static PyObject * PyGObject_try_get_from_handle (gpointer handle);
static int PyGObject_init (PyGObject * self);
static void PyGObject_dealloc (PyGObject * self);
static void PyGObject_take_handle (PyGObject * self, gpointer handle, const PyGObjectTypeSpec * spec);
static gpointer PyGObject_steal_handle (PyGObject * self);
static PyObject * PyGObject_on (PyGObject * self, PyObject * args);
static PyObject * PyGObject_off (PyGObject * self, PyObject * args);
static gint PyGObject_compare_signal_closure_callback (PyGObjectSignalClosure * closure, PyObject * callback);
static gboolean PyGObject_parse_signal_method_args (PyObject * args, GType instance_type, guint * signal_id, PyObject ** callback);
static const gchar * PyGObject_class_name_from_c (const gchar * cname);
static GClosure * PyGObject_make_closure_for_signal (GType instance_type, guint signal_id, PyObject * callback, guint max_arg_count);
static void PyGObjectSignalClosure_finalize (gpointer data, GClosure * closure);
static void PyGObjectSignalClosure_marshal (GClosure * closure, GValue * return_gvalue, guint n_param_values, const GValue * param_values,
    gpointer invocation_hint, gpointer marshal_data);
static PyObject * PyGObjectSignalClosure_marshal_params (const GValue * params, guint params_length);
static PyObject * PyGObject_marshal_value (const GValue * value);
static PyObject * PyGObject_marshal_enum (gint value, GType type);
static PyObject * PyGObject_marshal_bytes (GBytes * bytes);
static PyObject * PyGObject_marshal_object (gpointer handle, GType type);

static int PyDeviceManager_init (PyDeviceManager * self, PyObject * args, PyObject * kwds);
static void PyDeviceManager_dealloc (PyDeviceManager * self);
static PyObject * PyDeviceManager_close (PyDeviceManager * self);
static PyObject * PyDeviceManager_enumerate_devices (PyDeviceManager * self);
static PyObject * PyDeviceManager_add_remote_device (PyDeviceManager * self, PyObject * args);
static PyObject * PyDeviceManager_remove_remote_device (PyDeviceManager * self, PyObject * args);

static PyObject * PyDevice_new_take_handle (FridaDevice * handle);
static int PyDevice_init (PyDevice * self, PyObject * args, PyObject * kw);
static void PyDevice_init_from_handle (PyDevice * self, FridaDevice * handle);
static void PyDevice_dealloc (PyDevice * self);
static PyObject * PyDevice_repr (PyDevice * self);
static PyObject * PyDevice_get_frontmost_application (PyDevice * self);
static PyObject * PyDevice_enumerate_applications (PyDevice * self);
static PyObject * PyDevice_enumerate_processes (PyDevice * self);
static PyObject * PyDevice_enable_spawn_gating (PyDevice * self);
static PyObject * PyDevice_disable_spawn_gating (PyDevice * self);
static PyObject * PyDevice_enumerate_pending_spawns (PyDevice * self);
static PyObject * PyDevice_spawn (PyDevice * self, PyObject * args);
static PyObject * PyDevice_input (PyDevice * self, PyObject * args);
static PyObject * PyDevice_resume (PyDevice * self, PyObject * args);
static PyObject * PyDevice_kill (PyDevice * self, PyObject * args);
static PyObject * PyDevice_attach (PyDevice * self, PyObject * args);
static PyObject * PyDevice_inject_library_file (PyDevice * self, PyObject * args);
static PyObject * PyDevice_inject_library_blob (PyDevice * self, PyObject * args);

static PyObject * PyApplication_new_take_handle (FridaApplication * handle);
static int PyApplication_init (PyApplication * self, PyObject * args, PyObject * kw);
static void PyApplication_init_from_handle (PyApplication * self, FridaApplication * handle);
static void PyApplication_dealloc (PyApplication * self);
static PyObject * PyApplication_repr (PyApplication * self);
static PyObject * PyApplication_get_small_icon (PyApplication * self);
static PyObject * PyApplication_get_large_icon (PyApplication * self);

static PyObject * PyProcess_new_take_handle (FridaProcess * handle);
static int PyProcess_init (PyProcess * self, PyObject * args, PyObject * kw);
static void PyProcess_init_from_handle (PyProcess * self, FridaProcess * handle);
static void PyProcess_dealloc (PyProcess * self);
static PyObject * PyProcess_repr (PyProcess * self);
static PyObject * PyProcess_get_small_icon (PyProcess * self);
static PyObject * PyProcess_get_large_icon (PyProcess * self);

static PyObject * PySpawn_new_take_handle (FridaSpawn * handle);
static int PySpawn_init (PySpawn * self, PyObject * args, PyObject * kw);
static void PySpawn_init_from_handle (PySpawn * self, FridaSpawn * handle);
static void PySpawn_dealloc (PySpawn * self);
static PyObject * PySpawn_repr (PySpawn * self);

static PyObject * PyIcon_new_from_handle (FridaIcon * handle);
static int PyIcon_init (PyIcon * self, PyObject * args, PyObject * kw);
static void PyIcon_init_from_handle (PyIcon * self, FridaIcon * handle);
static void PyIcon_dealloc (PyIcon * self);
static PyObject * PyIcon_repr (PyIcon * self);

static PyObject * PySession_new_take_handle (FridaSession * handle);
static int PySession_init (PySession * self, PyObject * args, PyObject * kw);
static void PySession_init_from_handle (PySession * self, FridaSession * handle);
static PyObject * PySession_repr (PySession * self);
static PyObject * PySession_detach (PySession * self);
static PyObject * PySession_create_script (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_create_script_from_bytes (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_compile_script (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_enable_debugger (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_disable_debugger (PySession * self);
static PyObject * PySession_enable_jit (PySession * self);

static PyObject * PyScript_new_take_handle (FridaScript * handle);
static PyObject * PyScript_load (PyScript * self);
static PyObject * PyScript_unload (PyScript * self);
static PyObject * PyScript_post (PyScript * self, PyObject * args, PyObject * kw);

static int PyFileMonitor_init (PyFileMonitor * self, PyObject * args, PyObject * kw);
static PyObject * PyFileMonitor_enable (PyFileMonitor * self);
static PyObject * PyFileMonitor_disable (PyFileMonitor * self);

static PyObject * PyFrida_raise (GError * error);
static guint PyFrida_get_max_argument_count (PyObject * callable);

static PyMethodDef PyGObject_methods[] =
{
  { "on", (PyCFunction) PyGObject_on, METH_VARARGS, "Add a signal handler." },
  { "off", (PyCFunction) PyGObject_off, METH_VARARGS, "Remove a signal handler." },
  { NULL }
};

static PyMethodDef PyDeviceManager_methods[] =
{
  { "close", (PyCFunction) PyDeviceManager_close, METH_NOARGS, "Close the device manager." },
  { "enumerate_devices", (PyCFunction) PyDeviceManager_enumerate_devices, METH_NOARGS, "Enumerate devices." },
  { "add_remote_device", (PyCFunction) PyDeviceManager_add_remote_device, METH_VARARGS, "Add a remote device." },
  { "remove_remote_device", (PyCFunction) PyDeviceManager_remove_remote_device, METH_VARARGS, "Remove a remote device." },
  { NULL }
};

static PyMethodDef PyDevice_methods[] =
{
  { "get_frontmost_application", (PyCFunction) PyDevice_get_frontmost_application, METH_NOARGS, "Get details about the frontmost application." },
  { "enumerate_applications", (PyCFunction) PyDevice_enumerate_applications, METH_NOARGS, "Enumerate applications." },
  { "enumerate_processes", (PyCFunction) PyDevice_enumerate_processes, METH_NOARGS, "Enumerate processes." },
  { "enable_spawn_gating", (PyCFunction) PyDevice_enable_spawn_gating, METH_NOARGS, "Enable spawn gating." },
  { "disable_spawn_gating", (PyCFunction) PyDevice_disable_spawn_gating, METH_NOARGS, "Disable spawn gating." },
  { "enumerate_pending_spawns", (PyCFunction) PyDevice_enumerate_pending_spawns, METH_NOARGS, "Enumerate pending spawns." },
  { "spawn", (PyCFunction) PyDevice_spawn, METH_VARARGS, "Spawn a process into an attachable state." },
  { "input", (PyCFunction) PyDevice_input, METH_VARARGS, "Input data on stdin of a spawned process." },
  { "resume", (PyCFunction) PyDevice_resume, METH_VARARGS, "Resume a process from the attachable state." },
  { "kill", (PyCFunction) PyDevice_kill, METH_VARARGS, "Kill a PID." },
  { "attach", (PyCFunction) PyDevice_attach, METH_VARARGS, "Attach to a PID." },
  { "inject_library_file", (PyCFunction) PyDevice_inject_library_file, METH_VARARGS, "Inject a library file to a PID." },
  { "inject_library_blob", (PyCFunction) PyDevice_inject_library_blob, METH_VARARGS, "Inject a library blob to a PID." },
  { NULL }
};

static PyMemberDef PyDevice_members[] =
{
  { "id", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, id), READONLY, "Device ID." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, name), READONLY, "Human-readable device name." },
  { "icon", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, icon), READONLY, "Icon." },
  { "type", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, type), READONLY, "Device type. One of: local, tether, remote." },
  { NULL }
};

static PyMethodDef PyApplication_methods[] =
{
  { "get_small_icon", (PyCFunction) PyApplication_get_small_icon, METH_NOARGS, "Small icon." },
  { "get_large_icon", (PyCFunction) PyApplication_get_large_icon, METH_NOARGS, "Large icon." },
  { NULL }
};

static PyMemberDef PyApplication_members[] =
{
  { "identifier", T_OBJECT_EX, G_STRUCT_OFFSET (PyApplication, identifier), READONLY, "Application identifier." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyApplication, name), READONLY, "Human-readable application name." },
  { "pid", T_UINT, G_STRUCT_OFFSET (PyApplication, pid), READONLY, "Process ID, or 0 if not running." },
  { NULL }
};

static PyMethodDef PyProcess_methods[] =
{
  { "get_small_icon", (PyCFunction) PyProcess_get_small_icon, METH_NOARGS, "Small icon." },
  { "get_large_icon", (PyCFunction) PyProcess_get_large_icon, METH_NOARGS, "Large icon." },
  { NULL }
};

static PyMemberDef PyProcess_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PyProcess, pid), READONLY, "Process ID." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyProcess, name), READONLY, "Human-readable process name." },
  { NULL }
};

static PyMemberDef PySpawn_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PySpawn, pid), READONLY, "Process ID." },
  { "identifier", T_OBJECT_EX, G_STRUCT_OFFSET (PySpawn, identifier), READONLY, "Application identifier." },
  { NULL }
};

static PyMemberDef PyIcon_members[] =
{
  { "width", T_INT, G_STRUCT_OFFSET (PyIcon, width), READONLY, "Width in pixels." },
  { "height", T_INT, G_STRUCT_OFFSET (PyIcon, height), READONLY, "Height in pixels." },
  { "rowstride", T_INT, G_STRUCT_OFFSET (PyIcon, rowstride), READONLY, "Row stride in bytes." },
  { "pixels", T_OBJECT_EX, G_STRUCT_OFFSET (PyIcon, pixels), READONLY, "Pixels as a raw string containing RGBA data." },
  { NULL }
};

static PyMethodDef PySession_methods[] =
{
  { "detach", (PyCFunction) PySession_detach, METH_NOARGS, "Detach session from the process." },
  { "create_script", (PyCFunction) PySession_create_script, METH_VARARGS | METH_KEYWORDS, "Create a new script." },
  { "create_script_from_bytes", (PyCFunction) PySession_create_script_from_bytes, METH_VARARGS | METH_KEYWORDS, "Create a new script from bytecode." },
  { "compile_script", (PyCFunction) PySession_compile_script, METH_VARARGS | METH_KEYWORDS, "Compile script source code to bytecode." },
  { "enable_debugger", (PyCFunction) PySession_enable_debugger, METH_VARARGS | METH_KEYWORDS, "Enable the Node.js compatible script debugger." },
  { "disable_debugger", (PyCFunction) PySession_disable_debugger, METH_NOARGS, "Disable the Node.js compatible script debugger." },
  { "enable_jit", (PyCFunction) PySession_enable_jit, METH_NOARGS, "Enable JIT." },
  { NULL }
};

static PyMemberDef PySession_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PySession, pid), READONLY, "Process ID." },
  { NULL }
};

static PyMethodDef PyScript_methods[] =
{
  { "load", (PyCFunction) PyScript_load, METH_NOARGS, "Load the script." },
  { "unload", (PyCFunction) PyScript_unload, METH_NOARGS, "Unload the script." },
  { "post", (PyCFunction) PyScript_post, METH_VARARGS | METH_KEYWORDS, "Post a JSON-encoded message to the script." },
  { NULL }
};

static PyMethodDef PyFileMonitor_methods[] =
{
  { "enable", (PyCFunction) PyFileMonitor_enable, METH_NOARGS, "Enables the file monitor." },
  { "disable", (PyCFunction) PyFileMonitor_disable, METH_NOARGS, "Disables the file monitor." },
  { NULL }
};

static PyTypeObject PyGObjectType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Object",                              /* tp_name           */
  sizeof (PyGObject),                           /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PyGObject_dealloc,               /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  NULL,                                         /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,     /* tp_flags          */
  "Frida Object",                               /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PyGObject_methods,                            /* tp_methods        */
  NULL,                                         /* tp_members        */
  NULL,                                         /* tp_getset         */
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyGObject_init,                    /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (GObject, NULL, g_object_unref);

static PyTypeObject PyDeviceManagerType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.DeviceManager",                       /* tp_name           */
  sizeof (PyDeviceManager),                     /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PyDeviceManager_dealloc,         /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  NULL,                                         /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida Device Manager",                       /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PyDeviceManager_methods,                      /* tp_methods        */
  NULL,                                         /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyDeviceManager_init,              /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (DeviceManager, NULL, frida_unref);

static PyTypeObject PyDeviceType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Device",                              /* tp_name           */
  sizeof (PyDevice),                            /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PyDevice_dealloc,                /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  (reprfunc) PyDevice_repr,                     /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida Device",                               /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PyDevice_methods,                             /* tp_methods        */
  PyDevice_members,                             /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyDevice_init,                     /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (Device, PyDevice_init_from_handle, frida_unref);

static PyTypeObject PyApplicationType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Application",                         /* tp_name           */
  sizeof (PyApplication),                       /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PyApplication_dealloc,           /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  (reprfunc) PyApplication_repr,                /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida Application",                          /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PyApplication_methods,                        /* tp_methods        */
  PyApplication_members,                        /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyApplication_init,                /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (Application, PyApplication_init_from_handle, g_object_unref);

static PyTypeObject PyProcessType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Process",                             /* tp_name           */
  sizeof (PyProcess),                           /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PyProcess_dealloc,               /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  (reprfunc) PyProcess_repr,                    /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida Process",                              /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PyProcess_methods,                            /* tp_methods        */
  PyProcess_members,                            /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyProcess_init,                    /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (Process, PyProcess_init_from_handle, g_object_unref);

static PyTypeObject PySpawnType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Spawn",                               /* tp_name           */
  sizeof (PySpawn),                             /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PySpawn_dealloc,                 /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  (reprfunc) PySpawn_repr,                      /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida Spawn",                                /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  NULL,                                         /* tp_methods        */
  PySpawn_members,                              /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PySpawn_init,                      /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (Spawn, PySpawn_init_from_handle, g_object_unref);

static PyTypeObject PyIconType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Icon",                                /* tp_name           */
  sizeof (PyIcon),                              /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PyIcon_dealloc,                  /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  (reprfunc) PyIcon_repr,                       /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida Icon",                                 /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  NULL,                                         /* tp_methods        */
  PyIcon_members,                               /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyIcon_init,                       /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (Icon, PyIcon_init_from_handle, g_object_unref);

static PyTypeObject PySessionType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Session",                             /* tp_name           */
  sizeof (PySession),                           /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  NULL,                                         /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  (reprfunc) PySession_repr,                    /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida Session",                              /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PySession_methods,                            /* tp_methods        */
  PySession_members,                            /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PySession_init,                    /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (Session, PySession_init_from_handle, frida_unref);

static PyTypeObject PyScriptType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Script",                              /* tp_name           */
  sizeof (PyScript),                            /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  NULL,                                         /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  NULL,                                         /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida Script",                               /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PyScript_methods,                             /* tp_methods        */
  NULL,                                         /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  NULL,                                         /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (Script, NULL, frida_unref);

static PyTypeObject PyFileMonitorType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.FileMonitor",                         /* tp_name           */
  sizeof (PyFileMonitor),                       /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  NULL,                                         /* tp_dealloc        */
  NULL,                                         /* tp_print          */
  NULL,                                         /* tp_getattr        */
  NULL,                                         /* tp_setattr        */
  NULL,                                         /* tp_compare        */
  NULL,                                         /* tp_repr           */
  NULL,                                         /* tp_as_number      */
  NULL,                                         /* tp_as_sequence    */
  NULL,                                         /* tp_as_mapping     */
  NULL,                                         /* tp_hash           */
  NULL,                                         /* tp_call           */
  NULL,                                         /* tp_str            */
  NULL,                                         /* tp_getattro       */
  NULL,                                         /* tp_setattro       */
  NULL,                                         /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,                           /* tp_flags          */
  "Frida FileMonitor",                          /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PyFileMonitor_methods,                        /* tp_methods        */
  NULL,                                         /* tp_members        */
  NULL,                                         /* tp_getset         */
  &PyGObjectType,                               /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyFileMonitor_init,                /* tp_init           */
};

PYFRIDA_DEFINE_TYPE (FileMonitor, NULL, frida_unref);


static PyObject *
PyGObject_new_take_handle (gpointer handle, const PyGObjectTypeSpec * spec)
{
  PyObject * object;

  if (handle == NULL)
    Py_RETURN_NONE;

  object = PyGObject_try_get_from_handle (handle);
  if (object == NULL)
  {
    object = PyObject_CallFunction ((PyObject *) spec->type, NULL);
    PyGObject_take_handle (PY_GOBJECT (object), handle, spec);

    if (spec->init_from_handle != NULL)
      ((PyGObjectInitFromHandleFunc) spec->init_from_handle) (object, handle);
  }
  else
  {
    spec->destroy (handle);
    Py_INCREF (object);
  }

  return object;
}

static PyObject *
PyGObject_try_get_from_handle (gpointer handle)
{
  return g_object_get_data (handle, "pyobject");
}

static int
PyGObject_init (PyGObject * self)
{
  self->handle = NULL;
  self->spec = &PYFRIDA_TYPE_SPEC (GObject);

  self->signal_closures = NULL;

  return 0;
}

static void
PyGObject_dealloc (PyGObject * self)
{
  gpointer handle;

  handle = PyGObject_steal_handle (self);
  if (handle != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    self->spec->destroy (handle);
    Py_END_ALLOW_THREADS
  }

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static void
PyGObject_take_handle (PyGObject * self, gpointer handle, const PyGObjectTypeSpec * spec)
{
  self->handle = handle;
  self->spec = spec;

  g_object_set_data (G_OBJECT (handle), "pyobject", self);
}

static gpointer
PyGObject_steal_handle (PyGObject * self)
{
  gpointer handle = self->handle;
  GSList * entry;

  if (handle == NULL)
    return NULL;

  for (entry = self->signal_closures; entry != NULL; entry = entry->next)
  {
    PyGObjectSignalClosure * closure = entry->data;
    guint num_matches;

    num_matches = g_signal_handlers_disconnect_matched (handle, G_SIGNAL_MATCH_CLOSURE, closure->signal_id, 0, &closure->parent, NULL, NULL);
    g_assert_cmpuint (num_matches, ==, 1);
  }
  g_clear_pointer (&self->signal_closures, g_slist_free);

  g_object_set_data (G_OBJECT (handle), "pyobject", NULL);

  self->handle = NULL;

  return handle;
}

static PyObject *
PyGObject_on (PyGObject * self, PyObject * args)
{
  GType instance_type;
  guint signal_id;
  PyObject * callback;
  guint max_arg_count, allowed_arg_count_including_sender;
  GSignalQuery query;
  GClosure * closure;

  instance_type = G_OBJECT_TYPE (self->handle);

  if (!PyGObject_parse_signal_method_args (args, instance_type, &signal_id, &callback))
    return NULL;

  max_arg_count = PyFrida_get_max_argument_count (callback);
  if (max_arg_count != G_MAXUINT)
  {
    g_signal_query (signal_id, &query);

    allowed_arg_count_including_sender = 1 + query.n_params;

    if (max_arg_count > allowed_arg_count_including_sender)
      goto too_many_arguments;
  }

  closure = PyGObject_make_closure_for_signal (instance_type, signal_id, callback, max_arg_count);
  g_signal_connect_closure_by_id (self->handle, signal_id, 0, closure, TRUE);

  self->signal_closures = g_slist_prepend (self->signal_closures, closure);

  Py_RETURN_NONE;

too_many_arguments:
  {
    return PyErr_Format (PyExc_TypeError,
        "callback expects too many arguments, the '%s' signal only has %u but callback expects %u",
        g_signal_name (signal_id), query.n_params, max_arg_count);
  }
}

static PyObject *
PyGObject_off (PyGObject * self, PyObject * args)
{
  guint signal_id;
  PyObject * callback;
  GSList * entry;
  GClosure * closure;
  guint num_matches;

  if (!PyGObject_parse_signal_method_args (args, G_OBJECT_TYPE (self->handle), &signal_id, &callback))
    return NULL;

  entry = g_slist_find_custom (self->signal_closures, callback, (GCompareFunc) PyGObject_compare_signal_closure_callback);
  if (entry == NULL)
    goto unknown_callback;

  closure = entry->data;
  self->signal_closures = g_slist_delete_link (self->signal_closures, entry);

  num_matches = g_signal_handlers_disconnect_matched (self->handle, G_SIGNAL_MATCH_CLOSURE, signal_id, 0, closure, NULL, NULL);
  g_assert_cmpuint (num_matches, ==, 1);

  Py_RETURN_NONE;

unknown_callback:
  {
    PyErr_SetString (PyExc_ValueError, "unknown callback");
    return NULL;
  }
}

static gint
PyGObject_compare_signal_closure_callback (PyGObjectSignalClosure * closure,
                                           PyObject * callback)
{
  int result;

  result = PyObject_RichCompareBool (closure->parent.data, callback, Py_EQ);

  return (result == 1) ? 0 : -1;
}

static gboolean
PyGObject_parse_signal_method_args (PyObject * args, GType instance_type, guint * signal_id, PyObject ** callback)
{
  const gchar * signal_name;

  if (!PyArg_ParseTuple (args, "sO", &signal_name, callback))
    return FALSE;

  if (!PyCallable_Check (*callback))
  {
    PyErr_SetString (PyExc_TypeError, "second argument must be callable");
    return FALSE;
  }

  *signal_id = g_signal_lookup (signal_name, instance_type);
  if (*signal_id == 0)
    goto invalid_signal_name;

  return TRUE;

invalid_signal_name:
  {
    GString * message;
    guint * ids, n_ids, i;

    message = g_string_sized_new (128);

    g_string_append (message, PyGObject_class_name_from_c (g_type_name (instance_type)));

    ids = g_signal_list_ids (instance_type, &n_ids);

    if (n_ids > 0)
    {
      g_string_append_printf (message, " does not have a signal named '%s', it only has: ", signal_name);

      for (i = 0; i != n_ids; i++)
      {
        if (i != 0)
          g_string_append (message, ", ");
        g_string_append_c (message, '\'');
        g_string_append (message, g_signal_name (ids[i]));
        g_string_append_c (message, '\'');
      }
    }
    else
    {
      g_string_append (message, " does not have any signals");
    }

    g_free (ids);

    PyErr_SetString (PyExc_ValueError, message->str);

    g_string_free (message, TRUE);

    return FALSE;
  }
}

static const gchar *
PyGObject_class_name_from_c (const gchar * cname)
{
  if (g_str_has_prefix (cname, "Frida"))
    return cname + 5;

  return cname;
}

static void
PyGObject_class_init (void)
{
  pygobject_type_spec_by_type = g_hash_table_new_full (NULL, NULL, NULL, NULL);
}

static void
PyGObject_register_type (GType instance_type, const PyGObjectTypeSpec * spec)
{
  g_hash_table_insert (pygobject_type_spec_by_type, GSIZE_TO_POINTER (instance_type), (gpointer) spec);
}

static GClosure *
PyGObject_make_closure_for_signal (GType instance_type, guint signal_id, PyObject * callback, guint max_arg_count)
{
  GClosure * closure;
  PyGObjectSignalClosure * pyclosure;

  closure = g_closure_new_simple (sizeof (PyGObjectSignalClosure), callback);
  Py_IncRef (callback);

  g_closure_add_finalize_notifier (closure, callback, PyGObjectSignalClosure_finalize);
  g_closure_set_marshal (closure, PyGObjectSignalClosure_marshal);

  pyclosure = PY_GOBJECT_SIGNAL_CLOSURE (closure);
  pyclosure->signal_id = signal_id;
  pyclosure->max_arg_count = max_arg_count;

  return closure;
}

static void
PyGObjectSignalClosure_finalize (gpointer data, GClosure * closure)
{
  PyObject * callback = data;
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  Py_DecRef (callback);

  PyGILState_Release (gstate);
}

static void
PyGObjectSignalClosure_marshal (GClosure * closure, GValue * return_gvalue, guint n_param_values, const GValue * param_values,
    gpointer invocation_hint, gpointer marshal_data)
{
  PyGObjectSignalClosure * self = PY_GOBJECT_SIGNAL_CLOSURE (closure);
  PyObject * callback = closure->data;
  PyGILState_STATE gstate;
  PyObject * args, * result;

  gstate = PyGILState_Ensure ();

  if (PyGObject_try_get_from_handle (g_value_get_object (&param_values[0])) == NULL)
    goto beach;

  if (self->max_arg_count == n_param_values)
    args = PyGObjectSignalClosure_marshal_params (param_values, n_param_values);
  else
    args = PyGObjectSignalClosure_marshal_params (param_values + 1, MIN (n_param_values - 1, self->max_arg_count));
  if (args == NULL)
  {
    PyErr_Print ();
    goto beach;
  }

  result = PyObject_CallObject (callback, args);
  if (result == NULL)
    PyErr_Print ();
  else
    Py_DECREF (result);

  Py_DECREF (args);

beach:
  PyGILState_Release (gstate);
}

static PyObject *
PyGObjectSignalClosure_marshal_params (const GValue * params, guint params_length)
{
  PyObject * args;
  guint i;

  args = PyTuple_New (params_length);

  for (i = 0; i != params_length; i++)
  {
    PyObject * arg;

    arg = PyGObject_marshal_value (&params[i]);
    if (arg == NULL)
      goto marshal_error;

    PyTuple_SetItem (args, i, arg);
  }

  return args;

marshal_error:
  {
    Py_DECREF (args);
    return NULL;
  }
}

static PyObject *
PyGObject_marshal_value (const GValue * value)
{
  GType type;

  type = G_VALUE_TYPE (value);

  switch (type)
  {
    case G_TYPE_BOOLEAN:
      return PyBool_FromLong (g_value_get_boolean (value));
    case G_TYPE_INT:
      return PyLong_FromLong (g_value_get_int (value));
    case G_TYPE_UINT:
      return PyLong_FromUnsignedLong (g_value_get_uint (value));
    case G_TYPE_FLOAT:
      return PyFloat_FromDouble (g_value_get_float (value));
    case G_TYPE_DOUBLE:
      return PyFloat_FromDouble (g_value_get_double (value));
    case G_TYPE_STRING:
      return PyUnicode_FromUTF8String (g_value_get_string (value));
    default: {
      if (G_TYPE_IS_ENUM (type))
        return PyGObject_marshal_enum (g_value_get_enum (value), type);
      else if (type == G_TYPE_BYTES)
        return PyGObject_marshal_bytes (g_value_get_boxed (value));
      else if (G_TYPE_IS_OBJECT (type))
        return PyGObject_marshal_object (g_value_get_object (value), type);
      else
        goto unsupported_type;
    }
  }

  g_assert_not_reached ();

unsupported_type:
  {
    return PyErr_Format (PyExc_NotImplementedError,
        "unsupported type: '%s'",
        g_type_name (type));
  }
}

static PyObject *
PyGObject_marshal_enum (gint value, GType type)
{
  GEnumClass * enum_class;
  GEnumValue * enum_value;
  PyObject * result;

  enum_class = g_type_class_ref (type);

  enum_value = g_enum_get_value (enum_class, value);
  g_assert (enum_value != NULL);

  result = PyUnicode_FromUTF8String (enum_value->value_nick);

  g_type_class_unref (enum_class);

  return result;
}

static PyObject *
PyGObject_marshal_bytes (GBytes * bytes)
{
  gconstpointer data;
  gsize size;

  if (bytes == NULL)
    Py_RETURN_NONE;

  data = g_bytes_get_data (bytes, &size);

  return PyBytes_FromStringAndSize (data, size);
}

static PyObject *
PyGObject_marshal_object (gpointer handle, GType type)
{
  const PyGObjectTypeSpec * spec;

  if (handle == NULL)
    Py_RETURN_NONE;

  spec = g_hash_table_lookup (pygobject_type_spec_by_type, GSIZE_TO_POINTER (type));
  if (spec == NULL)
    spec = &PYFRIDA_TYPE_SPEC (GObject);

  return PyGObject_new_take_handle (g_object_ref (handle), spec);
}


static int
PyDeviceManager_init (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  if (PyGObjectType.tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  PyGObject_take_handle (&self->parent, frida_device_manager_new (), &PYFRIDA_TYPE_SPEC (DeviceManager));

  return 0;
}

static void
PyDeviceManager_dealloc (PyDeviceManager * self)
{
  FridaDeviceManager * handle;

  handle = PyGObject_steal_handle (&self->parent);
  if (handle != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    frida_device_manager_close_sync (handle);
    frida_unref (handle);
    Py_END_ALLOW_THREADS
  }

  PyGObjectType.tp_dealloc ((PyObject *) self);
}

static PyObject *
PyDeviceManager_close (PyDeviceManager * self)
{
  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_close_sync (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  Py_RETURN_NONE;
}

static PyObject *
PyDeviceManager_enumerate_devices (PyDeviceManager * self)
{
  GError * error = NULL;
  FridaDeviceList * result;
  gint result_length, i;
  PyObject * devices;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_manager_enumerate_devices_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_device_list_size (result);
  devices = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (devices, i, PyDevice_new_take_handle (frida_device_list_get (result, i)));
  }
  frida_unref (result);

  return devices;
}

static PyObject *
PyDeviceManager_add_remote_device (PyDeviceManager * self, PyObject * args)
{
  const char * host;
  GError * error = NULL;
  FridaDevice * result;

  if (!PyArg_ParseTuple (args, "s", &host))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_manager_add_remote_device_sync (PY_GOBJECT_HANDLE (self), host, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyDevice_new_take_handle (result);
}

static PyObject *
PyDeviceManager_remove_remote_device (PyDeviceManager * self, PyObject * args)
{
  const char * host;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "s", &host))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_remove_remote_device_sync (PY_GOBJECT_HANDLE (self), host, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}


static PyObject *
PyDevice_new_take_handle (FridaDevice * handle)
{
  return PyGObject_new_take_handle (handle, &PYFRIDA_TYPE_SPEC (Device));
}

static int
PyDevice_init (PyDevice * self, PyObject * args, PyObject * kw)
{
  if (PyGObjectType.tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->id = NULL;
  self->name = NULL;
  self->icon = NULL;
  self->type = NULL;

  return 0;
}

static void
PyDevice_init_from_handle (PyDevice * self, FridaDevice * handle)
{
  self->id = PyUnicode_FromUTF8String (frida_device_get_id (handle));
  self->name = PyUnicode_FromUTF8String (frida_device_get_name (handle));
  self->icon = PyIcon_new_from_handle (frida_device_get_icon (handle));
  self->type = PyGObject_marshal_enum (frida_device_get_dtype (handle), FRIDA_TYPE_DEVICE_TYPE);
}

static void
PyDevice_dealloc (PyDevice * self)
{
  Py_XDECREF (self->type);
  Py_XDECREF (self->icon);
  Py_XDECREF (self->name);
  Py_XDECREF (self->id);

  PyGObjectType.tp_dealloc ((PyObject *) self);
}

static PyObject *
PyDevice_repr (PyDevice * self)
{
  PyObject * id_bytes, * name_bytes, * type_bytes, * result;

  id_bytes = PyUnicode_AsUTF8String (self->id);
  name_bytes = PyUnicode_AsUTF8String (self->name);
  type_bytes = PyUnicode_AsUTF8String (self->type);

  result = PyRepr_FromFormat ("Device(id=\"%s\", name=\"%s\", type='%s')",
      PyBytes_AsString (id_bytes),
      PyBytes_AsString (name_bytes),
      PyBytes_AsString (type_bytes));

  Py_XDECREF (type_bytes);
  Py_XDECREF (name_bytes);
  Py_XDECREF (id_bytes);

  return result;
}

static PyObject *
PyDevice_get_frontmost_application (PyDevice * self)
{
  GError * error = NULL;
  FridaApplication * result;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_get_frontmost_application_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  if (result != NULL)
    return PyApplication_new_take_handle (result);
  else
    Py_RETURN_NONE;
}

static PyObject *
PyDevice_enumerate_applications (PyDevice * self)
{
  GError * error = NULL;
  FridaApplicationList * result;
  gint result_length, i;
  PyObject * applications;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_applications_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_application_list_size (result);
  applications = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (applications, i, PyApplication_new_take_handle (frida_application_list_get (result, i)));
  }
  g_object_unref (result);

  return applications;
}

static PyObject *
PyDevice_enumerate_processes (PyDevice * self)
{
  GError * error = NULL;
  FridaProcessList * result;
  gint result_length, i;
  PyObject * processes;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_processes_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_process_list_size (result);
  processes = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (processes, i, PyProcess_new_take_handle (frida_process_list_get (result, i)));
  }
  g_object_unref (result);

  return processes;
}

static PyObject *
PyDevice_enable_spawn_gating (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_enable_spawn_gating_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_disable_spawn_gating (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_enable_spawn_gating_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_enumerate_pending_spawns (PyDevice * self)
{
  GError * error = NULL;
  FridaSpawnList * result;
  gint result_length, i;
  PyObject * spawns;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_pending_spawns_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_spawn_list_size (result);
  spawns = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (spawns, i, PySpawn_new_take_handle (frida_spawn_list_get (result, i)));
  }
  g_object_unref (result);

  return spawns;
}

static PyObject *
PyDevice_spawn (PyDevice * self, PyObject * args)
{
  PyObject * elements;
  gint argc, i;
  gchar ** argv;
  gchar ** envp;
  gint envp_length;
  GError * error = NULL;
  guint pid;

  if (PyTuple_Size (args) != 1 || (!PyList_Check (PyTuple_GetItem (args, 0)) &&
      !PyTuple_Check (PyTuple_GetItem (args, 0))))
  {
    PyErr_SetString (PyExc_TypeError, "expecting argv as a list or a tuple");
    return NULL;
  }

  elements = PyTuple_GetItem (args, 0);
  argc = PySequence_Size (elements);
  argv = g_new0 (gchar *, argc + 1);
  for (i = 0; i != argc; i++)
  {
    PyObject * element;

    element = PySequence_GetItem (elements, i);
    if (PyUnicode_Check (element))
    {
      Py_DECREF (element);
      element = PyUnicode_AsUTF8String (element);
    }
    if (PyBytes_Check (element))
      argv[i] = g_strdup (PyBytes_AsString (element));
    Py_DECREF (element);

    if (argv[i] == NULL)
    {
      g_strfreev (argv);
      PyErr_SetString (PyExc_TypeError, "argv must be a sequence of strings");
      return NULL;
    }
  }

  envp = g_get_environ ();
  envp_length = g_strv_length (envp);

  Py_BEGIN_ALLOW_THREADS
  pid = frida_device_spawn_sync (PY_GOBJECT_HANDLE (self), argv[0], argv, argc, envp, envp_length, &error);
  Py_END_ALLOW_THREADS

  g_strfreev (envp);
  g_strfreev (argv);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (pid);
}

static PyObject *
PyDevice_input (PyDevice * self, PyObject * args)
{
  long pid;
  gconstpointer data_buffer;
  int data_size;
  GBytes * data;
  GError * error = NULL;

#if PY_MAJOR_VERSION >= 3
  if (!PyArg_ParseTuple (args, "ly#", &pid, &data_buffer, &data_size))
#else
  if (!PyArg_ParseTuple (args, "ls#", &pid, &data_buffer, &data_size))
#endif
    return NULL;

  data = g_bytes_new (data_buffer, data_size);

  Py_BEGIN_ALLOW_THREADS
  frida_device_input_sync (PY_GOBJECT_HANDLE (self), (guint) pid, data, &error);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);

  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_resume (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_resume_sync (PY_GOBJECT_HANDLE (self), (guint) pid, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_kill (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_kill_sync (PY_GOBJECT_HANDLE (self), (guint) pid, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_attach (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;
  FridaSession * handle;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_device_attach_sync (PY_GOBJECT_HANDLE (self), (guint) pid, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PySession_new_take_handle (handle);
}

static PyObject *
PyDevice_inject_library_file (PyDevice * self, PyObject * args)
{
  long pid;
  const char * path, * entrypoint, * data;
  GError * error = NULL;
  guint id;

  if (!PyArg_ParseTuple (args, "lsss", &pid, &path, &entrypoint, &data))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  id = frida_device_inject_library_file_sync (PY_GOBJECT_HANDLE (self), (guint) pid, path, entrypoint, data, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (id);
}

static PyObject *
PyDevice_inject_library_blob (PyDevice * self, PyObject * args)
{
  long pid;
  GBytes * blob;
  gconstpointer blob_buffer;
  int blob_size;
  const char * entrypoint, * data;
  GError * error = NULL;
  guint id;

#if PY_MAJOR_VERSION >= 3
  if (!PyArg_ParseTuple (args, "ly#ss", &pid, &blob_buffer, &blob_size, &entrypoint, &data))
#else
  if (!PyArg_ParseTuple (args, "ls#ss", &pid, &blob_buffer, &blob_size, &entrypoint, &data))
#endif
    return NULL;

  blob = g_bytes_new (blob_buffer, blob_size);

  Py_BEGIN_ALLOW_THREADS
  id = frida_device_inject_library_blob_sync (PY_GOBJECT_HANDLE (self), (guint) pid, blob, entrypoint, data, &error);
  Py_END_ALLOW_THREADS

  g_bytes_unref (blob);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (id);
}


static PyObject *
PyApplication_new_take_handle (FridaApplication * handle)
{
  return PyGObject_new_take_handle (handle, &PYFRIDA_TYPE_SPEC (Application));
}

static int
PyApplication_init (PyApplication * self, PyObject * args, PyObject * kw)
{
  if (PyGObjectType.tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->identifier = NULL;
  self->name = NULL;
  self->pid = 0;

  return 0;
}

static void
PyApplication_init_from_handle (PyApplication * self, FridaApplication * handle)
{
  self->identifier = PyUnicode_FromUTF8String (frida_application_get_identifier (handle));
  self->name = PyUnicode_FromUTF8String (frida_application_get_name (handle));
  self->pid = frida_application_get_pid (handle);
}

static void
PyApplication_dealloc (PyApplication * self)
{
  Py_XDECREF (self->name);
  Py_XDECREF (self->identifier);

  PyGObjectType.tp_dealloc ((PyObject *) self);
}

static PyObject *
PyApplication_repr (PyApplication * self)
{
  PyObject * identifier_bytes, * name_bytes, * result;

  identifier_bytes = PyUnicode_AsUTF8String (self->identifier);
  name_bytes = PyUnicode_AsUTF8String (self->name);

  if (self->pid != 0)
  {
    result = PyRepr_FromFormat ("Application(identifier=\"%s\", name=\"%s\", pid=%u)",
        PyBytes_AsString (identifier_bytes),
        PyBytes_AsString (name_bytes),
        self->pid);
  }
  else
  {
    result = PyRepr_FromFormat ("Application(identifier=\"%s\", name=\"%s\")",
        PyBytes_AsString (identifier_bytes),
        PyBytes_AsString (name_bytes));
  }

  Py_XDECREF (name_bytes);
  Py_XDECREF (identifier_bytes);

  return result;
}

static PyObject *
PyApplication_get_small_icon (PyApplication * self)
{
  return PyIcon_new_from_handle (frida_application_get_small_icon (PY_GOBJECT_HANDLE (self)));
}

static PyObject *
PyApplication_get_large_icon (PyApplication * self)
{
  return PyIcon_new_from_handle (frida_application_get_large_icon (PY_GOBJECT_HANDLE (self)));
}


static PyObject *
PyProcess_new_take_handle (FridaProcess * handle)
{
  return PyGObject_new_take_handle (handle, &PYFRIDA_TYPE_SPEC (Process));
}

static int
PyProcess_init (PyProcess * self, PyObject * args, PyObject * kw)
{
  if (PyGObjectType.tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->name = NULL;

  return 0;
}

static void
PyProcess_init_from_handle (PyProcess * self, FridaProcess * handle)
{
  self->pid = frida_process_get_pid (handle);
  self->name = PyUnicode_FromUTF8String (frida_process_get_name (handle));
}

static void
PyProcess_dealloc (PyProcess * self)
{
  Py_XDECREF (self->name);

  PyGObjectType.tp_dealloc ((PyObject *) self);
}

static PyObject *
PyProcess_repr (PyProcess * self)
{
  PyObject * name_bytes, * result;

  name_bytes = PyUnicode_AsUTF8String (self->name);

  result = PyRepr_FromFormat ("Process(pid=%u, name=\"%s\")",
      self->pid,
      PyBytes_AsString (name_bytes));

  Py_XDECREF (name_bytes);

  return result;
}

static PyObject *
PyProcess_get_small_icon (PyProcess * self)
{
  return PyIcon_new_from_handle (frida_process_get_small_icon (PY_GOBJECT_HANDLE (self)));
}

static PyObject *
PyProcess_get_large_icon (PyProcess * self)
{
  return PyIcon_new_from_handle (frida_process_get_large_icon (PY_GOBJECT_HANDLE (self)));
}


static PyObject *
PySpawn_new_take_handle (FridaSpawn * handle)
{
  return PyGObject_new_take_handle (handle, &PYFRIDA_TYPE_SPEC (Spawn));
}

static int
PySpawn_init (PySpawn * self, PyObject * args, PyObject * kw)
{
  if (PyGObjectType.tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->identifier = NULL;

  return 0;
}

static void
PySpawn_init_from_handle (PySpawn * self, FridaSpawn * handle)
{
  self->pid = frida_spawn_get_pid (handle);
  self->identifier = PyUnicode_FromUTF8String (frida_spawn_get_identifier (handle));
}

static void
PySpawn_dealloc (PySpawn * self)
{
  Py_XDECREF (self->identifier);

  PyGObjectType.tp_dealloc ((PyObject *) self);
}

static PyObject *
PySpawn_repr (PySpawn * self)
{
  PyObject * identifier_bytes, * result;

  identifier_bytes = PyUnicode_AsUTF8String (self->identifier);

  if (self->identifier != NULL)
  {
    result = PyRepr_FromFormat ("Spawn(pid=%u, identifier=\"%s\")",
        self->pid,
        PyBytes_AsString (identifier_bytes));
  }
  else
  {
    result = PyRepr_FromFormat ("Spawn(pid=%u)",
        self->pid);
  }

  Py_XDECREF (identifier_bytes);

  return result;
}


static PyObject *
PyIcon_new_from_handle (FridaIcon * handle)
{
  if (handle != NULL)
    g_object_ref (handle);

  return PyGObject_new_take_handle (handle, &PYFRIDA_TYPE_SPEC (Icon));
}

static int
PyIcon_init (PyIcon * self, PyObject * args, PyObject * kw)
{
  if (PyGObjectType.tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->width = 0;
  self->height = 0;
  self->rowstride = 0;
  self->pixels = NULL;

  return 0;
}

static void
PyIcon_init_from_handle (PyIcon * self, FridaIcon * handle)
{
  gconstpointer pixels;
  gsize pixels_size;

  self->width = frida_icon_get_width (handle);
  self->height = frida_icon_get_height (handle);
  self->rowstride = frida_icon_get_rowstride (handle);
  pixels = g_bytes_get_data (frida_icon_get_pixels (handle), &pixels_size);
  self->pixels = PyBytes_FromStringAndSize ((char *) pixels, (Py_ssize_t) pixels_size);
}

static void
PyIcon_dealloc (PyIcon * self)
{
  Py_XDECREF (self->pixels);

  PyGObjectType.tp_dealloc ((PyObject *) self);
}

static PyObject *
PyIcon_repr (PyIcon * self)
{
  return PyRepr_FromFormat ("Icon(width=%d, height=%d, rowstride=%d, pixels=<%zd bytes>)", self->width, self->height, self->rowstride, PyBytes_Size (self->pixels));
}


static PyObject *
PySession_new_take_handle (FridaSession * handle)
{
  return PyGObject_new_take_handle (handle, &PYFRIDA_TYPE_SPEC (Session));
}

static int
PySession_init (PySession * self, PyObject * args, PyObject * kw)
{
  if (PyGObjectType.tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;

  return 0;
}

static void
PySession_init_from_handle (PySession * self, FridaSession * handle)
{
  self->pid = frida_session_get_pid (handle);
}

static PyObject *
PySession_repr (PySession * self)
{
  return PyRepr_FromFormat ("Session(pid=%u)", self->pid);
}

static PyObject *
PySession_detach (PySession * self)
{
  Py_BEGIN_ALLOW_THREADS
  frida_session_detach_sync (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  Py_RETURN_NONE;
}

static PyObject *
PySession_create_script (PySession * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "source", "name", NULL };
  char * source, * name = NULL;
  GError * error = NULL;
  FridaScript * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|es", keywords, "utf-8", &source, "utf-8", &name))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_session_create_script_sync (PY_GOBJECT_HANDLE (self), name, source, &error);
  Py_END_ALLOW_THREADS

  PyMem_Free (source);
  PyMem_Free (name);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyScript_new_take_handle (handle);
}

static PyObject *
PySession_create_script_from_bytes (PySession * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "data", "name", NULL };
  guint8 * data;
  int size;
  char * name = NULL;
  GBytes * bytes;
  GError * error = NULL;
  FridaScript * handle;

#if PY_MAJOR_VERSION >= 3
  if (!PyArg_ParseTupleAndKeywords (args, kw, "y#|es", keywords, &data, &size, "utf-8", &name))
#else
  if (!PyArg_ParseTupleAndKeywords (args, kw, "s#|es", keywords, &data, &size, "utf-8", &name))
#endif
    return NULL;

  bytes = g_bytes_new (data, size);

  Py_BEGIN_ALLOW_THREADS
  handle = frida_session_create_script_from_bytes_sync (PY_GOBJECT_HANDLE (self), name, bytes, &error);
  Py_END_ALLOW_THREADS

  g_bytes_unref (bytes);
  PyMem_Free (name);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyScript_new_take_handle (handle);
}

static PyObject *
PySession_compile_script (PySession * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "source", NULL };
  char * source;
  GError * error = NULL;
  GBytes * bytes;
  gconstpointer data;
  gsize size;
  PyObject * result;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es", keywords, "utf-8", &source))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  bytes = frida_session_compile_script_sync (PY_GOBJECT_HANDLE (self), source, &error);
  Py_END_ALLOW_THREADS

  PyMem_Free (source);

  if (error != NULL)
    return PyFrida_raise (error);

  data = g_bytes_get_data (bytes, &size);
  result = PyBytes_FromStringAndSize (data, size);
  g_bytes_unref (bytes);

  return result;
}

static PyObject *
PySession_enable_debugger (PySession * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "port", NULL };
  unsigned short int port = 0;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|H", keywords, &port))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_enable_debugger_sync (PY_GOBJECT_HANDLE (self), port, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PySession_disable_debugger (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_disable_debugger_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PySession_enable_jit (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_enable_jit_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}


static PyObject *
PyScript_new_take_handle (FridaScript * handle)
{
  return PyGObject_new_take_handle (handle, &PYFRIDA_TYPE_SPEC (Script));
}

static PyObject *
PyScript_load (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_load_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyScript_unload (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_unload_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyScript_post (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "message", "data", NULL };
  char * message;
  gconstpointer data_buffer = NULL;
  int data_size = 0;
  GBytes * data;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|z#", keywords, "utf-8", &message, &data_buffer, &data_size))
    return NULL;
  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_post_sync (PY_GOBJECT_HANDLE (self), message, data, &error);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}


static int
PyFileMonitor_init (PyFileMonitor * self, PyObject * args, PyObject * kw)
{
  const char * path;

  if (PyGObjectType.tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTuple (args, "s", &path))
    return -1;

  PyGObject_take_handle (&self->parent, frida_file_monitor_new (path), &PYFRIDA_TYPE_SPEC (FileMonitor));

  return 0;
}

static PyObject *
PyFileMonitor_enable (PyFileMonitor * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_file_monitor_enable_sync (PY_GOBJECT_HANDLE (self), NULL, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyFileMonitor_disable (PyFileMonitor * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_file_monitor_disable_sync (PY_GOBJECT_HANDLE (self), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}


static void
PyFrida_object_decref (gpointer obj)
{
  PyObject * o = obj;
  Py_DECREF (o);
}

static PyObject *
PyFrida_raise (GError * error)
{
  PyObject * exception;
  GString * message;

  g_assert (error->domain == FRIDA_ERROR);
  exception = g_hash_table_lookup (exception_by_error_code, GINT_TO_POINTER (error->code));
  g_assert (exception != NULL);
  message = g_string_new ("");
  g_string_append_unichar (message, g_unichar_tolower (g_utf8_get_char (error->message)));
  g_string_append (message, g_utf8_offset_to_pointer (error->message, 1));

  PyErr_SetString (exception, message->str);

  g_string_free (message, TRUE);
  g_error_free (error);

  return NULL;
}

static guint
PyFrida_get_max_argument_count (PyObject * callable)
{
  guint result = G_MAXUINT;
  PyObject * spec;
  PyObject * varargs = NULL;
  PyObject * args = NULL;
  PyObject * is_method;

  spec = PyObject_CallFunction (inspect_getargspec, "O", callable);
  if (spec == NULL)
  {
    PyErr_Clear ();
    goto beach;
  }

  varargs = PyTuple_GetItem (spec, 1);
  if (varargs != Py_None)
    goto beach;

  args = PyTuple_GetItem (spec, 0);

  result = PyObject_Size (args);

  is_method = PyObject_CallFunction (inspect_ismethod, "O", callable);
  g_assert (is_method != NULL);
  if (is_method == Py_True)
    result--;
  Py_DECREF (is_method);

beach:
  Py_XDECREF (args);
  Py_XDECREF (varargs);
  Py_XDECREF (spec);

  return result;
}


MOD_INIT (_frida)
{
  PyObject * inspect, * module;

  PyEval_InitThreads ();

  inspect = PyImport_ImportModule ("inspect");
  inspect_getargspec = PyObject_GetAttrString (inspect, PYFRIDA_GETARGSPEC_FUNCTION);
  inspect_ismethod = PyObject_GetAttrString (inspect, "ismethod");
  Py_DECREF (inspect);

  frida_init ();

  PyGObject_class_init ();

  MOD_DEF (module, "_frida", "Frida", NULL);

  PyModule_AddStringConstant (module, "__version__", frida_version_string ());

  PYFRIDA_REGISTER_TYPE (GObject, G_TYPE_OBJECT);
  PYFRIDA_REGISTER_TYPE (DeviceManager, FRIDA_TYPE_DEVICE_MANAGER);
  PYFRIDA_REGISTER_TYPE (Device, FRIDA_TYPE_DEVICE);
  PYFRIDA_REGISTER_TYPE (Application, FRIDA_TYPE_APPLICATION);
  PYFRIDA_REGISTER_TYPE (Process, FRIDA_TYPE_PROCESS);
  PYFRIDA_REGISTER_TYPE (Spawn, FRIDA_TYPE_SPAWN);
  PYFRIDA_REGISTER_TYPE (Icon, FRIDA_TYPE_ICON);
  PYFRIDA_REGISTER_TYPE (Session, FRIDA_TYPE_SESSION);
  PYFRIDA_REGISTER_TYPE (Script, FRIDA_TYPE_SCRIPT);
  PYFRIDA_REGISTER_TYPE (FileMonitor, FRIDA_TYPE_FILE_MONITOR);

  exception_by_error_code = g_hash_table_new_full (NULL, NULL, NULL, PyFrida_object_decref);
#define PYFRIDA_DECLARE_EXCEPTION(code, name) \
    do \
    { \
      PyObject * exception = PyErr_NewException ("frida." name "Error", NULL, NULL); \
      g_hash_table_insert (exception_by_error_code, GINT_TO_POINTER (G_PASTE (FRIDA_ERROR_, code)), exception); \
      Py_INCREF (exception); \
      PyModule_AddObject (module, name "Error", exception); \
    } while (FALSE)
  PYFRIDA_DECLARE_EXCEPTION (SERVER_NOT_RUNNING, "ServerNotRunning");
  PYFRIDA_DECLARE_EXCEPTION (EXECUTABLE_NOT_FOUND, "ExecutableNotFound");
  PYFRIDA_DECLARE_EXCEPTION (EXECUTABLE_NOT_SUPPORTED, "ExecutableNotSupported");
  PYFRIDA_DECLARE_EXCEPTION (PROCESS_NOT_FOUND, "ProcessNotFound");
  PYFRIDA_DECLARE_EXCEPTION (PROCESS_NOT_RESPONDING, "ProcessNotResponding");
  PYFRIDA_DECLARE_EXCEPTION (INVALID_ARGUMENT, "InvalidArgument");
  PYFRIDA_DECLARE_EXCEPTION (INVALID_OPERATION, "InvalidOperation");
  PYFRIDA_DECLARE_EXCEPTION (PERMISSION_DENIED, "PermissionDenied");
  PYFRIDA_DECLARE_EXCEPTION (ADDRESS_IN_USE, "AddressInUse");
  PYFRIDA_DECLARE_EXCEPTION (TIMED_OUT, "TimedOut");
  PYFRIDA_DECLARE_EXCEPTION (NOT_SUPPORTED, "NotSupported");
  PYFRIDA_DECLARE_EXCEPTION (PROTOCOL, "Protocol");
  PYFRIDA_DECLARE_EXCEPTION (TRANSPORT, "Transport");

  return MOD_SUCCESS_VAL (module);
}
