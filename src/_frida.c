/*
 * Copyright (C) 2013-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <frida-core.h>

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4211)
#endif
#ifdef _POSIX_C_SOURCE
# undef _POSIX_C_SOURCE
#endif
#include <Python.h>
#include <structmember.h>
#ifdef _MSC_VER
# pragma warning (pop)
#endif
#ifdef HAVE_MAC
# include <crt_externs.h>
#endif

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
#else
# define MOD_INIT(name) PyMODINIT_FUNC init##name (void)
# define MOD_DEF(ob, name, doc, methods) \
  ob = Py_InitModule3 (name, methods, doc);
# define MOD_SUCCESS_VAL(val)
# define MOD_ERROR_VAL
# define PyRepr_FromFormat PyString_FromFormat
#endif

#define FRIDA_FUNCPTR_TO_POINTER(f) (GSIZE_TO_POINTER (f))

static PyObject * json_loads;
static PyObject * json_dumps;

static GHashTable * exception_by_error_code;

typedef struct _PyDeviceManager  PyDeviceManager;
typedef struct _PyDevice         PyDevice;
typedef struct _PyApplication    PyApplication;
typedef struct _PyProcess        PyProcess;
typedef struct _PySpawn          PySpawn;
typedef struct _PyIcon           PyIcon;
typedef struct _PySession        PySession;
typedef struct _PyScript         PyScript;

struct _PyDeviceManager
{
  PyObject_HEAD

  FridaDeviceManager * handle;
  GList * on_changed;
};

struct _PyDevice
{
  PyObject_HEAD

  FridaDevice * handle;

  guint id;
  const gchar * name;
  PyObject * icon;
  const gchar * type;

  GList * on_spawned;
  GList * on_lost;
};

struct _PyApplication
{
  PyObject_HEAD

  FridaApplication * handle;

  const gchar * identifier;
  const gchar * name;
  guint pid;
};

struct _PyProcess
{
  PyObject_HEAD

  FridaProcess * handle;

  guint pid;
  const gchar * name;
};

struct _PySpawn
{
  PyObject_HEAD

  FridaSpawn * handle;

  guint pid;
  const gchar * identifier;
};

struct _PyIcon
{
  PyObject_HEAD

  gint width;
  gint height;
  gint rowstride;
  PyObject * pixels;
};

struct _PySession
{
  PyObject_HEAD

  FridaSession * handle;
  GList * on_detached;
};

struct _PyScript
{
  PyObject_HEAD

  FridaScript * handle;
  GList * on_message;
};

static int PyDeviceManager_init (PyDeviceManager * self);
static void PyDeviceManager_dealloc (PyDeviceManager * self);
static PyObject * PyDeviceManager_close (PyDeviceManager * self);
static PyObject * PyDeviceManager_enumerate_devices (PyDeviceManager * self);
static PyObject * PyDeviceManager_on (PyDeviceManager * self, PyObject * args);
static PyObject * PyDeviceManager_off (PyDeviceManager * self, PyObject * args);
static void PyDeviceManager_on_changed (PyDeviceManager * self, FridaDeviceManager * handle);

static PyObject * PyDevice_from_handle (FridaDevice * handle);
static int PyDevice_init (PyDevice * self);
static void PyDevice_dealloc (PyDevice * self);
static PyObject * PyDevice_repr (PyDevice * self);
static PyObject * PyDevice_get_frontmost_application (PyDevice * self);
static PyObject * PyDevice_enumerate_applications (PyDevice * self);
static PyObject * PyDevice_enumerate_processes (PyDevice * self);
static PyObject * PyDevice_enable_spawn_gating (PyDevice * self);
static PyObject * PyDevice_disable_spawn_gating (PyDevice * self);
static PyObject * PyDevice_enumerate_pending_spawns (PyDevice * self);
static PyObject * PyDevice_spawn (PyDevice * self, PyObject * args);
static PyObject * PyDevice_resume (PyDevice * self, PyObject * args);
static PyObject * PyDevice_kill (PyDevice * self, PyObject * args);
static PyObject * PyDevice_attach (PyDevice * self, PyObject * args);
static PyObject * PyDevice_on (PyDevice * self, PyObject * args);
static PyObject * PyDevice_off (PyDevice * self, PyObject * args);
static void PyDevice_on_spawned (PyDevice * self, FridaSpawn * spawn, FridaDevice * handle);
static void PyDevice_on_lost (PyDevice * self, FridaDevice * handle);

static PyObject * PyApplication_from_handle (FridaApplication * handle);
static int PyApplication_init (PyApplication * self);
static void PyApplication_dealloc (PyApplication * self);
static PyObject * PyApplication_repr (PyApplication * self);
static PyObject * PyApplication_get_small_icon (PyApplication * self);
static PyObject * PyApplication_get_large_icon (PyApplication * self);

static PyObject * PyProcess_from_handle (FridaProcess * handle);
static int PyProcess_init (PyProcess * self);
static void PyProcess_dealloc (PyProcess * self);
static PyObject * PyProcess_repr (PyProcess * self);
static PyObject * PyProcess_get_small_icon (PyProcess * self);
static PyObject * PyProcess_get_large_icon (PyProcess * self);

static PyObject * PySpawn_from_handle (FridaSpawn * handle);
static int PySpawn_init (PySpawn * self);
static void PySpawn_dealloc (PySpawn * self);
static PyObject * PySpawn_repr (PySpawn * self);

static PyObject * PyIcon_from_handle (FridaIcon * handle);
static int PyIcon_init (PyIcon * self);
static void PyIcon_dealloc (PyIcon * self);
static PyObject * PyIcon_repr (PyIcon * self);

static PyObject * PySession_from_handle (FridaSession * handle);
static int PySession_init (PySession * self);
static void PySession_dealloc (PySession * self);
static PyObject * PySession_detach (PySession * self);
static PyObject * PySession_create_script (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_enable_debugger (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_disable_debugger (PySession * self, PyObject * args);
static PyObject * PySession_on (PySession * self, PyObject * args);
static PyObject * PySession_off (PySession * self, PyObject * args);
static void PySession_on_detached (PySession * self, FridaSession * handle);

static PyObject * PyScript_from_handle (FridaScript * handle);
static int PyScript_init (PyScript * self);
static void PyScript_dealloc (PyScript * self);
static PyObject * PyScript_load (PyScript * self);
static PyObject * PyScript_unload (PyScript * self);
static PyObject * PyScript_post_message (PyScript * self, PyObject * args);
static PyObject * PyScript_on (PyScript * self, PyObject * args);
static PyObject * PyScript_off (PyScript * self, PyObject * args);
static void PyScript_on_message (PyScript * self, const gchar * message, const gchar * data, gint data_size, FridaScript * handle);

static PyObject * PyFrida_raise (GError * error);
static const gchar * PyFrida_device_type_to_string (FridaDeviceType type);
static gboolean PyFrida_parse_signal_method_args (PyObject * args, const char ** signal, PyObject ** callback);

static PyMethodDef PyDeviceManager_methods[] =
{
  { "close", (PyCFunction) PyDeviceManager_close, METH_NOARGS, "Close the device manager." },
  { "enumerate_devices", (PyCFunction) PyDeviceManager_enumerate_devices, METH_NOARGS, "Enumerate devices." },
  { "on", (PyCFunction) PyDeviceManager_on, METH_VARARGS, "Add an event handler." },
  { "off", (PyCFunction) PyDeviceManager_off, METH_VARARGS, "Remove an event handler." },
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
  { "resume", (PyCFunction) PyDevice_resume, METH_VARARGS, "Resume a process from the attachable state." },
  { "kill", (PyCFunction) PyDevice_kill, METH_VARARGS, "Kill a PID." },
  { "attach", (PyCFunction) PyDevice_attach, METH_VARARGS, "Attach to a PID." },
  { "on", (PyCFunction) PyDevice_on, METH_VARARGS, "Add an event handler." },
  { "off", (PyCFunction) PyDevice_off, METH_VARARGS, "Remove an event handler." },
  { NULL }
};

static PyMemberDef PyDevice_members[] =
{
  { "id", T_UINT, G_STRUCT_OFFSET (PyDevice, id), READONLY, "Device ID."},
  { "name", T_STRING, G_STRUCT_OFFSET (PyDevice, name), READONLY, "Human-readable device name."},
  { "icon", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, icon), READONLY, "Icon."},
  { "type", T_STRING, G_STRUCT_OFFSET (PyDevice, type), READONLY, "Device type. One of: local, tether, remote."},
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
  { "identifier", T_STRING, G_STRUCT_OFFSET (PyApplication, identifier), READONLY, "Application identifier."},
  { "name", T_STRING, G_STRUCT_OFFSET (PyApplication, name), READONLY, "Human-readable process name."},
  { "pid", T_UINT, G_STRUCT_OFFSET (PyApplication, pid), READONLY, "Process ID, or 0 if not running."},
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
  { "pid", T_UINT, G_STRUCT_OFFSET (PyProcess, pid), READONLY, "Process ID."},
  { "name", T_STRING, G_STRUCT_OFFSET (PyProcess, name), READONLY, "Human-readable process name."},
  { NULL }
};

static PyMemberDef PySpawn_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PySpawn, pid), READONLY, "Process ID."},
  { "identifier", T_STRING, G_STRUCT_OFFSET (PySpawn, identifier), READONLY, "Application identifier."},
  { NULL }
};

static PyMemberDef PyIcon_members[] =
{
  { "width", T_INT, G_STRUCT_OFFSET (PyIcon, width), READONLY, "Width in pixels."},
  { "height", T_INT, G_STRUCT_OFFSET (PyIcon, height), READONLY, "Height in pixels."},
  { "rowstride", T_INT, G_STRUCT_OFFSET (PyIcon, rowstride), READONLY, "Row stride in bytes."},
  { "pixels", T_OBJECT_EX, G_STRUCT_OFFSET (PyIcon, pixels), READONLY, "Pixels as a raw string containing RGBA data."},
  { NULL }
};

static PyMethodDef PySession_methods[] =
{
  { "detach", (PyCFunction) PySession_detach, METH_NOARGS, "Detach session from the process." },
  { "create_script", (PyCFunction) PySession_create_script, METH_VARARGS | METH_KEYWORDS, "Create a new script." },
  { "enable_debugger", (PyCFunction) PySession_enable_debugger, METH_VARARGS | METH_KEYWORDS, "Enable the Node.js compatible script debugger." },
  { "disable_debugger", (PyCFunction) PySession_disable_debugger, METH_VARARGS, "Disable the Node.js compatible script debugger." },
  { "on", (PyCFunction) PySession_on, METH_VARARGS, "Add an event handler." },
  { "off", (PyCFunction) PySession_off, METH_VARARGS, "Remove an event handler." },
  { NULL }
};

static PyMethodDef PyScript_methods[] =
{
  { "load", (PyCFunction) PyScript_load, METH_NOARGS, "Load the script." },
  { "unload", (PyCFunction) PyScript_unload, METH_NOARGS, "Unload the script." },
  { "post_message", (PyCFunction) PyScript_post_message, METH_VARARGS, "Post a JSON-formatted message to the script." },
  { "on", (PyCFunction) PyScript_on, METH_VARARGS, "Add an event handler." },
  { "off", (PyCFunction) PyScript_off, METH_VARARGS, "Remove an event handler." },
  { NULL }
};

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
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyDeviceManager_init,              /* tp_init           */
};

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
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyDevice_init,                     /* tp_init           */
};

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
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyApplication_init,                /* tp_init           */
};

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
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyProcess_init,                    /* tp_init           */
};

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
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PySpawn_init,                      /* tp_init           */
};

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
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyIcon_init,                       /* tp_init           */
};

static PyTypeObject PySessionType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Session",                             /* tp_name           */
  sizeof (PySession),                           /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PySession_dealloc,               /* tp_dealloc        */
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
  "Frida Session",                              /* tp_doc            */
  NULL,                                         /* tp_traverse       */
  NULL,                                         /* tp_clear          */
  NULL,                                         /* tp_richcompare    */
  0,                                            /* tp_weaklistoffset */
  NULL,                                         /* tp_iter           */
  NULL,                                         /* tp_iternext       */
  PySession_methods,                            /* tp_methods        */
  NULL,                                         /* tp_members        */
  NULL,                                         /* tp_getset         */
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PySession_init,                    /* tp_init           */
};

static PyTypeObject PyScriptType =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "_frida.Script",                              /* tp_name           */
  sizeof (PyScript),                            /* tp_basicsize      */
  0,                                            /* tp_itemsize       */
  (destructor) PyScript_dealloc,                /* tp_dealloc        */
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
  NULL,                                         /* tp_base           */
  NULL,                                         /* tp_dict           */
  NULL,                                         /* tp_descr_get      */
  NULL,                                         /* tp_descr_set      */
  0,                                            /* tp_dictoffset     */
  (initproc) PyScript_init,                     /* tp_init           */
};


static int
PyDeviceManager_init (PyDeviceManager * self)
{
  self->handle = frida_device_manager_new ();
  self->on_changed = NULL;

  g_object_set_data (G_OBJECT (self->handle), "pyobject", self);

  return 0;
}

static void
PyDeviceManager_dealloc (PyDeviceManager * self)
{
  if (self->on_changed != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDeviceManager_on_changed), self);
    g_list_free_full (self->on_changed, (GDestroyNotify) Py_DecRef);
  }

  if (self->handle != NULL)
  {
    g_object_set_data (G_OBJECT (self->handle), "pyobject", NULL);
    Py_BEGIN_ALLOW_THREADS
    frida_device_manager_close_sync (self->handle);
    frida_unref (self->handle);
    Py_END_ALLOW_THREADS
  }

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static PyObject *
PyDeviceManager_close (PyDeviceManager * self)
{
  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_close_sync (self->handle);
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
  result = frida_device_manager_enumerate_devices_sync (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_device_list_size (result);
  devices = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (devices, i, PyDevice_from_handle (frida_device_list_get (result, i)));
  }
  frida_unref (result);

  return devices;
}

static PyObject *
PyDeviceManager_on (PyDeviceManager * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "changed") == 0)
  {
    if (self->on_changed == NULL)
    {
      g_signal_connect_swapped (self->handle, "changed", G_CALLBACK (PyDeviceManager_on_changed), self);
    }

    Py_INCREF (callback);
    self->on_changed = g_list_append (self->on_changed, callback);
  }
  else
  {
    PyErr_SetString (PyExc_NotImplementedError, "unsupported signal");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject *
PyDeviceManager_off (PyDeviceManager * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "changed") == 0)
  {
    GList * entry;

    entry = g_list_find (self->on_changed, callback);
    if (entry != NULL)
    {
      self->on_changed = g_list_delete_link (self->on_changed, entry);
      Py_DECREF (callback);
    }
    else
    {
      PyErr_SetString (PyExc_ValueError, "unknown callback");
      return NULL;
    }

    if (self->on_changed == NULL)
    {
      g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDeviceManager_on_changed), self);
    }
  }
  else
  {
    PyErr_SetString (PyExc_NotImplementedError, "unsupported signal");
    return NULL;
  }

  Py_RETURN_NONE;
}

static void
PyDeviceManager_on_changed (PyDeviceManager * self, FridaDeviceManager * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    GList * callbacks, * cur;

    g_list_foreach (self->on_changed, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_changed);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallFunction ((PyObject *) cur->data, NULL);
      if (result == NULL)
        PyErr_Print ();
      else
        Py_DECREF (result);
    }

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);
  }

  PyGILState_Release (gstate);
}


static PyObject *
PyDevice_from_handle (FridaDevice * handle)
{
  PyObject * device;

  device = g_object_get_data (G_OBJECT (handle), "pyobject");
  if (device == NULL)
  {
    PyDevice * dev;

    device = PyObject_CallFunction ((PyObject *) &PyDeviceType, NULL);

    dev = (PyDevice *) device;
    dev->handle = handle;
    dev->id = frida_device_get_id (handle);
    dev->name = frida_device_get_name (handle);
    dev->icon = PyIcon_from_handle (frida_device_get_icon (handle));
    dev->type = PyFrida_device_type_to_string (frida_device_get_dtype (handle));

    g_object_set_data (G_OBJECT (handle), "pyobject", device);
  }
  else
  {
    frida_unref (handle);
    Py_INCREF (device);
  }

  return device;
}

static int
PyDevice_init (PyDevice * self)
{
  self->handle = NULL;

  self->id = 0;
  self->name = NULL;
  self->icon = NULL;
  self->type = NULL;

  self->on_spawned = NULL;
  self->on_lost = NULL;

  return 0;
}

static void
PyDevice_dealloc (PyDevice * self)
{
  if (self->on_spawned != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDevice_on_spawned), self);
    g_list_free_full (self->on_spawned, (GDestroyNotify) Py_DecRef);
  }

  if (self->on_lost != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDevice_on_lost), self);
    g_list_free_full (self->on_lost, (GDestroyNotify) Py_DecRef);
  }

  Py_XDECREF (self->icon);

  if (self->handle != NULL)
  {
    g_object_set_data (G_OBJECT (self->handle), "pyobject", NULL);
    Py_BEGIN_ALLOW_THREADS
    frida_unref (self->handle);
    Py_END_ALLOW_THREADS
  }

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static PyObject *
PyDevice_repr (PyDevice * self)
{
  return PyRepr_FromFormat ("Device(id=%u, name=\"%s\", type='%s')", self->id, self->name, self->type);
}

static PyObject *
PyDevice_get_frontmost_application (PyDevice * self)
{
  GError * error = NULL;
  FridaApplication * result;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_get_frontmost_application_sync (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  if (result != NULL)
    return PyApplication_from_handle (result);
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
  result = frida_device_enumerate_applications_sync (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_application_list_size (result);
  applications = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (applications, i, PyApplication_from_handle (frida_application_list_get (result, i)));
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
  result = frida_device_enumerate_processes_sync (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_process_list_size (result);
  processes = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (processes, i, PyProcess_from_handle (frida_process_list_get (result, i)));
  }
  g_object_unref (result);

  return processes;
}

static PyObject *
PyDevice_enable_spawn_gating (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_enable_spawn_gating_sync (self->handle, &error);
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
  frida_device_enable_spawn_gating_sync (self->handle, &error);
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
  result = frida_device_enumerate_pending_spawns_sync (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_spawn_list_size (result);
  spawns = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (spawns, i, PySpawn_from_handle (frida_spawn_list_get (result, i)));
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
  pid = frida_device_spawn_sync (self->handle, argv[0], argv, argc, envp, envp_length, &error);
  Py_END_ALLOW_THREADS

  g_strfreev (envp);
  g_strfreev (argv);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromLong (pid);
}

static PyObject *
PyDevice_resume (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_resume_sync (self->handle, (guint) pid, &error);
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
  frida_device_kill_sync (self->handle, (guint) pid, &error);
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
  handle = frida_device_attach_sync (self->handle, (guint) pid, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PySession_from_handle (handle);
}

static PyObject *
PyDevice_on (PyDevice * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "spawned") == 0)
  {
    if (self->on_spawned == NULL)
    {
      g_signal_connect_swapped (self->handle, "spawned", G_CALLBACK (PyDevice_on_spawned), self);
    }

    Py_INCREF (callback);
    self->on_spawned = g_list_append (self->on_spawned, callback);
  }
  else if (strcmp (signal, "lost") == 0)
  {
    if (self->on_lost == NULL)
    {
      g_signal_connect_swapped (self->handle, "lost", G_CALLBACK (PyDevice_on_lost), self);
    }

    Py_INCREF (callback);
    self->on_lost = g_list_append (self->on_lost, callback);
  }
  else
  {
    PyErr_SetString (PyExc_NotImplementedError, "unsupported signal");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_off (PyDevice * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "spawned") == 0)
  {
    GList * entry;

    entry = g_list_find (self->on_spawned, callback);
    if (entry != NULL)
    {
      self->on_spawned = g_list_delete_link (self->on_spawned, entry);
      Py_DECREF (callback);
    }
    else
    {
      PyErr_SetString (PyExc_ValueError, "unknown callback");
      return NULL;
    }

    if (self->on_spawned == NULL)
    {
      g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDevice_on_spawned), self);
    }
  }
  else if (strcmp (signal, "lost") == 0)
  {
    GList * entry;

    entry = g_list_find (self->on_lost, callback);
    if (entry != NULL)
    {
      self->on_lost = g_list_delete_link (self->on_lost, entry);
      Py_DECREF (callback);
    }
    else
    {
      PyErr_SetString (PyExc_ValueError, "unknown callback");
      return NULL;
    }

    if (self->on_lost == NULL)
    {
      g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDevice_on_lost), self);
    }
  }
  else
  {
    PyErr_SetString (PyExc_NotImplementedError, "unsupported signal");
    return NULL;
  }

  Py_RETURN_NONE;
}

static void
PyDevice_on_spawned (PyDevice * self, FridaSpawn * spawn, FridaDevice * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    PyObject * args;
    GList * callbacks, * cur;

    g_object_ref (spawn);
    args = PyTuple_Pack (1, PySpawn_from_handle (spawn));

    g_list_foreach (self->on_spawned, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_spawned);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallObject ((PyObject *) cur->data, args);
      if (result == NULL)
        PyErr_Print ();
      else
        Py_DECREF (result);
    }

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);

    Py_DECREF (args);
  }

  PyGILState_Release (gstate);
}

static void
PyDevice_on_lost (PyDevice * self, FridaDevice * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    GList * callbacks, * cur;

    g_list_foreach (self->on_lost, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_lost);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallFunction ((PyObject *) cur->data, NULL);
      if (result == NULL)
        PyErr_Print ();
      else
        Py_DECREF (result);
    }

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);
  }

  PyGILState_Release (gstate);
}


static PyObject *
PyApplication_from_handle (FridaApplication * handle)
{
  PyObject * result;
  PyApplication * application;

  result = PyObject_CallFunction ((PyObject *) &PyApplicationType, NULL);

  application = (PyApplication *) result;
  application->handle = handle;
  application->identifier = frida_application_get_identifier (handle);
  application->name = frida_application_get_name (handle);
  application->pid = frida_application_get_pid (handle);

  return result;
}

static int
PyApplication_init (PyApplication * self)
{
  self->handle = NULL;

  self->identifier = NULL;
  self->name = NULL;

  return 0;
}

static void
PyApplication_dealloc (PyApplication * self)
{
  if (self->handle != NULL)
    g_object_unref (self->handle);

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static PyObject *
PyApplication_repr (PyApplication * self)
{
  if (self->pid != 0)
    return PyRepr_FromFormat ("Application(identifier=\"%s\", name=\"%s\", pid=%u)", self->identifier, self->name, self->pid);
  else
    return PyRepr_FromFormat ("Application(identifier=\"%s\", name=\"%s\")", self->identifier, self->name);
}

static PyObject *
PyApplication_get_small_icon (PyApplication * self)
{
  return PyIcon_from_handle (frida_application_get_small_icon (self->handle));
}

static PyObject *
PyApplication_get_large_icon (PyApplication * self)
{
  return PyIcon_from_handle (frida_application_get_large_icon (self->handle));
}


static PyObject *
PyProcess_from_handle (FridaProcess * handle)
{
  PyObject * result;
  PyProcess * process;

  result = PyObject_CallFunction ((PyObject *) &PyProcessType, NULL);

  process = (PyProcess *) result;
  process->handle = handle;
  process->pid = frida_process_get_pid (handle);
  process->name = frida_process_get_name (handle);

  return result;
}

static int
PyProcess_init (PyProcess * self)
{
  self->handle = NULL;

  self->pid = 0;
  self->name = NULL;

  return 0;
}

static void
PyProcess_dealloc (PyProcess * self)
{
  if (self->handle != NULL)
    g_object_unref (self->handle);

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static PyObject *
PyProcess_repr (PyProcess * self)
{
  return PyRepr_FromFormat ("Process(pid=%u, name=\"%s\")", self->pid, self->name);
}

static PyObject *
PyProcess_get_small_icon (PyProcess * self)
{
  return PyIcon_from_handle (frida_process_get_small_icon (self->handle));
}

static PyObject *
PyProcess_get_large_icon (PyProcess * self)
{
  return PyIcon_from_handle (frida_process_get_large_icon (self->handle));
}


static PyObject *
PySpawn_from_handle (FridaSpawn * handle)
{
  PyObject * result;
  PySpawn * spawn;

  result = PyObject_CallFunction ((PyObject *) &PySpawnType, NULL);

  spawn = (PySpawn *) result;
  spawn->handle = handle;
  spawn->pid = frida_spawn_get_pid (handle);
  spawn->identifier = frida_spawn_get_identifier (handle);

  return result;
}

static int
PySpawn_init (PySpawn * self)
{
  self->handle = NULL;

  self->pid = 0;
  self->identifier = NULL;

  return 0;
}

static void
PySpawn_dealloc (PySpawn * self)
{
  if (self->handle != NULL)
    g_object_unref (self->handle);

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static PyObject *
PySpawn_repr (PySpawn * self)
{
  if (self->identifier != NULL)
    return PyRepr_FromFormat ("Spawn(pid=%u, identifier=\"%s\")", self->pid, self->identifier);
  else
    return PyRepr_FromFormat ("Spawn(pid=%u)", self->pid);
}


static PyObject *
PyIcon_from_handle (FridaIcon * handle)
{
  if (handle != NULL)
  {
    PyObject * result;
    PyIcon * icon;
    guint8 * pixels;
    gint pixels_length;

    result = PyObject_CallFunction ((PyObject *) &PyIconType, NULL);

    icon = (PyIcon *) result;
    icon->width = frida_icon_get_width (handle);
    icon->height = frida_icon_get_height (handle);
    icon->rowstride = frida_icon_get_rowstride (handle);
    pixels = frida_icon_get_pixels (handle, &pixels_length);
    icon->pixels = PyBytes_FromStringAndSize ((char *) pixels, (Py_ssize_t) pixels_length);

    return result;
  }

  Py_RETURN_NONE;
}

static int
PyIcon_init (PyIcon * self)
{
  self->width = 0;
  self->height = 0;
  self->rowstride = 0;
  self->pixels = NULL;

  return 0;
}

static void
PyIcon_dealloc (PyIcon * self)
{
  Py_XDECREF (self->pixels);

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static PyObject *
PyIcon_repr (PyIcon * self)
{
  return PyRepr_FromFormat ("Icon(width=%d, height=%d, rowstride=%d, pixels=<%zd bytes>)", self->width, self->height, self->rowstride, PyBytes_Size (self->pixels));
}


static PyObject *
PySession_from_handle (FridaSession * handle)
{
  PyObject * session;

  session = g_object_get_data (G_OBJECT (handle), "pyobject");
  if (session == NULL)
  {
    session = PyObject_CallFunction ((PyObject *) &PySessionType, NULL);
    ((PySession *) session)->handle = handle;
    g_object_set_data (G_OBJECT (handle), "pyobject", session);
  }
  else
  {
    frida_unref (handle);
    Py_INCREF (session);
  }

  return session;
}

static int
PySession_init (PySession * self)
{
  self->handle = NULL;
  self->on_detached = NULL;

  return 0;
}

static void
PySession_dealloc (PySession * self)
{
  if (self->on_detached != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PySession_on_detached), self);
    g_list_free_full (self->on_detached, (GDestroyNotify) Py_DecRef);
  }

  if (self->handle != NULL)
  {
    g_object_set_data (G_OBJECT (self->handle), "pyobject", NULL);
    Py_BEGIN_ALLOW_THREADS
    frida_unref (self->handle);
    Py_END_ALLOW_THREADS
  }

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static PyObject *
PySession_detach (PySession * self)
{
  Py_BEGIN_ALLOW_THREADS
  frida_session_detach_sync (self->handle);
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
  handle = frida_session_create_script_sync (self->handle, name, source, &error);
  Py_END_ALLOW_THREADS

  PyMem_Free (source);
  PyMem_Free (name);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyScript_from_handle (handle);
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
  frida_session_enable_debugger_sync (self->handle, port, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PySession_disable_debugger (PySession * self, PyObject * args)
{
  GError * error = NULL;

  (void) args;

  Py_BEGIN_ALLOW_THREADS
  frida_session_disable_debugger_sync (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PySession_on (PySession * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "detached") == 0)
  {
    if (self->on_detached == NULL)
    {
      g_signal_connect_swapped (self->handle, "detached", G_CALLBACK (PySession_on_detached), self);
    }

    Py_INCREF (callback);
    self->on_detached = g_list_append (self->on_detached, callback);
  }
  else
  {
    PyErr_SetString (PyExc_NotImplementedError, "unsupported signal");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject *
PySession_off (PySession * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "detached") == 0)
  {
    GList * entry;

    entry = g_list_find (self->on_detached, callback);
    if (entry != NULL)
    {
      self->on_detached = g_list_delete_link (self->on_detached, entry);
      Py_DECREF (callback);
    }
    else
    {
      PyErr_SetString (PyExc_ValueError, "unknown callback");
      return NULL;
    }

    if (self->on_detached == NULL)
    {
      g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PySession_on_detached), self);
    }
  }
  else
  {
    PyErr_SetString (PyExc_NotImplementedError, "unsupported signal");
    return NULL;
  }

  Py_RETURN_NONE;
}

static void
PySession_on_detached (PySession * self, FridaSession * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    GList * callbacks, * cur;

    g_list_foreach (self->on_detached, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_detached);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallFunction ((PyObject *) cur->data, NULL);
      if (result == NULL)
        PyErr_Print ();
      else
        Py_DECREF (result);
    }

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);
  }

  PyGILState_Release (gstate);
}


static PyObject *
PyScript_from_handle (FridaScript * handle)
{
  PyObject * script;

  script = g_object_get_data (G_OBJECT (handle), "pyobject");
  if (script == NULL)
  {
    script = PyObject_CallFunction ((PyObject *) &PyScriptType, NULL);
    ((PyScript *) script)->handle = handle;
    g_object_set_data (G_OBJECT (handle), "pyobject", script);
    g_signal_connect_swapped (handle, "message", G_CALLBACK (PyScript_on_message), script);
  }
  else
  {
    frida_unref (handle);
    Py_INCREF (script);
  }

  return script;
}

static int
PyScript_init (PyScript * self)
{
  self->handle = NULL;
  self->on_message = NULL;

  return 0;
}

static void
PyScript_dealloc (PyScript * self)
{
  if (self->handle != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyScript_on_message), self);
    g_list_free_full (self->on_message, (GDestroyNotify) Py_DecRef);
    g_object_set_data (G_OBJECT (self->handle), "pyobject", NULL);
    Py_BEGIN_ALLOW_THREADS
    frida_unref (self->handle);
    Py_END_ALLOW_THREADS
  }

  Py_TYPE (self)->tp_free ((PyObject *) self);
}

static PyObject *
PyScript_load (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_load_sync (self->handle, &error);
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
  frida_script_unload_sync (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyScript_post_message (PyScript * self, PyObject * args)
{
  PyObject * message_object, * message_json;
  char * message_utf8;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "O", &message_object))
    return NULL;

  message_json = PyObject_CallFunction (json_dumps, "O", message_object);
  if (message_json == NULL)
    return NULL;

#if PY_MAJOR_VERSION >= 3
  {
    PyObject * message_bytes;

    message_bytes = PyUnicode_AsUTF8String (message_json);
    Py_DECREF (message_json);
    message_json = message_bytes;

    message_utf8 = PyBytes_AsString (message_bytes);
  }
#else
  message_utf8 = PyString_AsString (message_json);
#endif

  Py_BEGIN_ALLOW_THREADS
  frida_script_post_message_sync (self->handle, message_utf8, &error);
  Py_END_ALLOW_THREADS

  Py_DECREF (message_json);

  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyScript_on (PyScript * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "message") == 0)
  {
    Py_INCREF (callback);
    self->on_message = g_list_append (self->on_message, callback);
  }
  else
  {
    PyErr_SetString (PyExc_NotImplementedError, "unsupported signal");
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject *
PyScript_off (PyScript * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "message") == 0)
  {
    GList * entry;

    entry = g_list_find (self->on_message, callback);
    if (entry != NULL)
    {
      self->on_message = g_list_delete_link (self->on_message, entry);
      Py_DECREF (callback);
    }
    else
    {
      PyErr_SetString (PyExc_ValueError, "unknown callback");
      return NULL;
    }
  }
  else
  {
    PyErr_SetString (PyExc_NotImplementedError, "unsupported signal");
    return NULL;
  }

  Py_RETURN_NONE;
}

static void
PyScript_on_message (PyScript * self, const gchar * message, const gchar * data, gint data_size, FridaScript * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    PyObject * message_object, * args;
    GList * callbacks, * cur;

    message_object = PyObject_CallFunction (json_loads, "s", message);
    g_assert (message_object != NULL);

#if PY_MAJOR_VERSION >= 3
    args = Py_BuildValue ("Oy#", message_object, data, data_size);
#else
    args = Py_BuildValue ("Os#", message_object, data, data_size);
#endif

    g_list_foreach (self->on_message, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_message);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallObject ((PyObject *) cur->data, args);
      if (result == NULL)
        PyErr_Print ();
      else
        Py_DECREF (result);
    }

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);

    Py_DECREF (args);

    Py_DECREF (message_object);
  }

  PyGILState_Release (gstate);
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

static const gchar *
PyFrida_device_type_to_string (FridaDeviceType type)
{
  switch (type)
  {
    case FRIDA_DEVICE_TYPE_LOCAL:
      return "local";
    case FRIDA_DEVICE_TYPE_TETHER:
      return "tether";
    case FRIDA_DEVICE_TYPE_REMOTE:
      return "remote";
    default:
      g_assert_not_reached ();
  }
}

static gboolean
PyFrida_parse_signal_method_args (PyObject * args, const char ** signal, PyObject ** callback)
{
  if (!PyArg_ParseTuple (args, "sO", signal, callback))
    return FALSE;

  if (!PyCallable_Check (*callback))
  {
    PyErr_SetString (PyExc_TypeError, "second argument must be callable");
    return FALSE;
  }

  return TRUE;
}


MOD_INIT (_frida)
{
  PyObject * json;
  PyObject * module;

  PyEval_InitThreads ();

  json = PyImport_ImportModule ("json");
  json_loads = PyObject_GetAttrString (json, "loads");
  json_dumps = PyObject_GetAttrString (json, "dumps");
  Py_DECREF (json);

  frida_init ();

  PyDeviceManagerType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyDeviceManagerType) < 0)
    return MOD_ERROR_VAL;

  PyDeviceType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyDeviceType) < 0)
    return MOD_ERROR_VAL;

  PyApplicationType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyApplicationType) < 0)
    return MOD_ERROR_VAL;

  PyProcessType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyProcessType) < 0)
    return MOD_ERROR_VAL;

  PySpawnType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PySpawnType) < 0)
    return MOD_ERROR_VAL;

  PyIconType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyIconType) < 0)
    return MOD_ERROR_VAL;

  PySessionType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PySessionType) < 0)
    return MOD_ERROR_VAL;

  PyScriptType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyScriptType) < 0)
    return MOD_ERROR_VAL;

  MOD_DEF (module, "_frida", "Frida", NULL);

  PyModule_AddStringConstant (module, "__version__", frida_version_string ());

  Py_INCREF (&PyDeviceManagerType);
  PyModule_AddObject (module, "DeviceManager", (PyObject *) &PyDeviceManagerType);

  Py_INCREF (&PyDeviceType);
  PyModule_AddObject (module, "Device", (PyObject *) &PyDeviceType);

  Py_INCREF (&PyApplicationType);
  PyModule_AddObject (module, "Application", (PyObject *) &PyApplicationType);

  Py_INCREF (&PyProcessType);
  PyModule_AddObject (module, "Process", (PyObject *) &PyProcessType);

  Py_INCREF (&PySpawnType);
  PyModule_AddObject (module, "Spawn", (PyObject *) &PySpawnType);

  Py_INCREF (&PyIconType);
  PyModule_AddObject (module, "Icon", (PyObject *) &PyIconType);

  Py_INCREF (&PySessionType);
  PyModule_AddObject (module, "Session", (PyObject *) &PySessionType);

  Py_INCREF (&PyScriptType);
  PyModule_AddObject (module, "Script", (PyObject *) &PyScriptType);

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
