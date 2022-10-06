/*
 * Copyright (C) 2013-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <frida-core.h>
#include <string.h>
#if defined (G_OS_UNIX) && !defined (G_TYPE_UNIX_SOCKET_ADDRESS)
# include <gio/gunixsocketaddress.h>
#endif

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4115)
# pragma warning (disable: 4211)
#endif
#ifdef _POSIX_C_SOURCE
# undef _POSIX_C_SOURCE
#endif

#define Py_LIMITED_API 0x03070000
#define PY_SSIZE_T_CLEAN

/*
 * Don't propagate _DEBUG state to pyconfig as it incorrectly attempts to load
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
#include <string.h>
#ifdef _MSC_VER
# pragma warning (pop)
#endif
#ifdef HAVE_MACOS
# include <crt_externs.h>
#endif

#define PyUnicode_FromUTF8String(str) PyUnicode_DecodeUTF8 (str, strlen (str), "strict")
#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name (void)
#define MOD_DEF(ob, name, doc, methods) \
  { \
    static struct PyModuleDef moduledef = { \
        PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
    ob = PyModule_Create (&moduledef); \
  }
#define MOD_SUCCESS_VAL(val) val
#define MOD_ERROR_VAL NULL
#define PyRepr_FromString PyUnicode_FromString
#define PyRepr_FromFormat PyUnicode_FromFormat
#define PYFRIDA_GETARGSPEC_FUNCTION "getfullargspec"

#if PY_VERSION_HEX >= 0x03080000
# define PYFRIDA_NO_PRINT_FUNC_OR_VECTORCALL_OFFSET 0
#else
# define PYFRIDA_NO_PRINT_FUNC_OR_VECTORCALL_OFFSET NULL
#endif

#define PYFRIDA_TYPE(name) \
  (&_PYFRIDA_TYPE_VAR (name, type))
#define PYFRIDA_TYPE_OBJECT(name) \
  PYFRIDA_TYPE (name)->object
#define _PYFRIDA_TYPE_VAR(name, var) \
  G_PASTE (G_PASTE (G_PASTE (Py, name), _), var)
#define PYFRIDA_DEFINE_BASETYPE(pyname, cname, init_func, destroy_func, ...) \
  _PYFRIDA_DEFINE_TYPE_SLOTS (cname, __VA_ARGS__); \
  _PYFRIDA_DEFINE_TYPE_SPEC (cname, pyname, Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE); \
  static PyGObjectType _PYFRIDA_TYPE_VAR (cname, type) = \
  { \
    .parent = NULL, \
    .object = NULL, \
    .init_from_handle = (PyGObjectInitFromHandleFunc) init_func, \
    .destroy = destroy_func, \
  }
#define PYFRIDA_DEFINE_TYPE(pyname, cname, parent_cname, init_func, destroy_func, ...) \
  _PYFRIDA_DEFINE_TYPE_SLOTS (cname, __VA_ARGS__); \
  _PYFRIDA_DEFINE_TYPE_SPEC (cname, pyname, Py_TPFLAGS_DEFAULT); \
  static PyGObjectType _PYFRIDA_TYPE_VAR (cname, type) = \
  { \
    .parent = PYFRIDA_TYPE (parent_cname), \
    .object = NULL, \
    .init_from_handle = (PyGObjectInitFromHandleFunc) init_func, \
    .destroy = destroy_func, \
  }
#define PYFRIDA_REGISTER_TYPE(cname, gtype) \
  G_BEGIN_DECLS \
  { \
    PyGObjectType * t = PYFRIDA_TYPE (cname); \
    t->object = PyType_FromSpecWithBases (&_PYFRIDA_TYPE_VAR (cname, spec), \
        (t->parent != NULL) ? PyTuple_Pack (1, t->parent->object) : NULL); \
    PyGObject_register_type (gtype, t); \
    Py_INCREF (t->object); \
    PyModule_AddObject (module, G_STRINGIFY (cname), t->object); \
  } \
  G_END_DECLS
#define _PYFRIDA_DEFINE_TYPE_SPEC(cname, pyname, type_flags) \
  static PyType_Spec _PYFRIDA_TYPE_VAR (cname, spec) = \
  { \
    .name = pyname, \
    .basicsize = sizeof (G_PASTE (Py, cname)), \
    .itemsize = 0, \
    .flags = type_flags, \
    .slots = _PYFRIDA_TYPE_VAR (cname, slots), \
  }
#define _PYFRIDA_DEFINE_TYPE_SLOTS(cname, ...) \
  static PyType_Slot _PYFRIDA_TYPE_VAR (cname, slots)[] = \
  { \
    __VA_ARGS__ \
    { 0 }, \
  }

#define PY_GOBJECT(o) ((PyGObject *) (o))
#define PY_GOBJECT_HANDLE(o) (PY_GOBJECT (o)->handle)
#define PY_GOBJECT_SIGNAL_CLOSURE(o) ((PyGObjectSignalClosure *) (o))

#define FRIDA_FUNCPTR_TO_POINTER(f) (GSIZE_TO_POINTER (f))

static volatile gint toplevel_objects_alive = 0;

static PyObject * inspect_getargspec;
static PyObject * inspect_ismethod;

static PyObject * datetime_constructor;

static initproc PyGObject_tp_init;
static destructor PyGObject_tp_dealloc;
static GHashTable * pygobject_type_spec_by_type;
static GHashTable * frida_exception_by_error_code;
static PyObject * cancelled_exception;

typedef struct _PyGObject                      PyGObject;
typedef struct _PyGObjectType                  PyGObjectType;
typedef struct _PyGObjectSignalClosure         PyGObjectSignalClosure;
typedef struct _PyDeviceManager                PyDeviceManager;
typedef struct _PyDevice                       PyDevice;
typedef struct _PyApplication                  PyApplication;
typedef struct _PyProcess                      PyProcess;
typedef struct _PySpawn                        PySpawn;
typedef struct _PyChild                        PyChild;
typedef struct _PyCrash                        PyCrash;
typedef struct _PyBus                          PyBus;
typedef struct _PySession                      PySession;
typedef struct _PyScript                       PyScript;
typedef struct _PyRelay                        PyRelay;
typedef struct _PyPortalMembership             PyPortalMembership;
typedef struct _PyPortalService                PyPortalService;
typedef struct _PyEndpointParameters           PyEndpointParameters;
typedef struct _PyCompiler                     PyCompiler;
typedef struct _PyFileMonitor                  PyFileMonitor;
typedef struct _PyIOStream                     PyIOStream;
typedef struct _PyCancellable                  PyCancellable;

#define FRIDA_TYPE_PYTHON_AUTHENTICATION_SERVICE (frida_python_authentication_service_get_type ())
G_DECLARE_FINAL_TYPE (FridaPythonAuthenticationService, frida_python_authentication_service, FRIDA, PYTHON_AUTHENTICATION_SERVICE, GObject)

typedef void (* PyGObjectInitFromHandleFunc) (PyObject * self, gpointer handle);

struct _PyGObject
{
  PyObject_HEAD

  gpointer handle;
  const PyGObjectType * type;

  GSList * signal_closures;
};

struct _PyGObjectType
{
  PyGObjectType * parent;
  PyObject * object;
  PyGObjectInitFromHandleFunc init_from_handle;
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
  PyObject * bus;
};

struct _PyApplication
{
  PyGObject parent;
  PyObject * identifier;
  PyObject * name;
  guint pid;
  PyObject * parameters;
};

struct _PyProcess
{
  PyGObject parent;
  guint pid;
  PyObject * name;
  PyObject * parameters;
};

struct _PySpawn
{
  PyGObject parent;
  guint pid;
  PyObject * identifier;
};

struct _PyChild
{
  PyGObject parent;
  guint pid;
  guint parent_pid;
  PyObject * origin;
  PyObject * identifier;
  PyObject * path;
  PyObject * argv;
  PyObject * envp;
};

struct _PyCrash
{
  PyGObject parent;
  guint pid;
  PyObject * process_name;
  PyObject * summary;
  PyObject * report;
  PyObject * parameters;
};

struct _PyBus
{
  PyGObject parent;
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

struct _PyRelay
{
  PyGObject parent;
  PyObject * address;
  PyObject * username;
  PyObject * password;
  PyObject * kind;
};

struct _PyPortalMembership
{
  PyGObject parent;
};

struct _PyPortalService
{
  PyGObject parent;
  PyObject * device;
};

struct _PyEndpointParameters
{
  PyGObject parent;
};

struct _FridaPythonAuthenticationService
{
  GObject parent;
  PyObject * callback;
  GThreadPool * pool;
};

struct _PyCompiler
{
  PyGObject parent;
};

struct _PyFileMonitor
{
  PyGObject parent;
};

struct _PyIOStream
{
  PyGObject parent;
  GInputStream * input;
  GOutputStream * output;
};

struct _PyCancellable
{
  PyGObject parent;
};

static PyObject * PyGObject_new_take_handle (gpointer handle, const PyGObjectType * type);
static PyObject * PyGObject_try_get_from_handle (gpointer handle);
static int PyGObject_init (PyGObject * self);
static void PyGObject_dealloc (PyGObject * self);
static void PyGObject_take_handle (PyGObject * self, gpointer handle, const PyGObjectType * type);
static gpointer PyGObject_steal_handle (PyGObject * self);
static PyObject * PyGObject_on (PyGObject * self, PyObject * args);
static PyObject * PyGObject_off (PyGObject * self, PyObject * args);
static gint PyGObject_compare_signal_closure_callback (PyGObjectSignalClosure * closure, PyObject * callback);
static gboolean PyGObject_parse_signal_method_args (PyObject * args, GType instance_type, guint * signal_id, PyObject ** callback);
static const gchar * PyGObject_class_name_from_c (const gchar * cname);
static GClosure * PyGObject_make_closure_for_signal (guint signal_id, PyObject * callback, guint max_arg_count);
static void PyGObjectSignalClosure_finalize (PyObject * callback);
static void PyGObjectSignalClosure_marshal (GClosure * closure, GValue * return_gvalue, guint n_param_values, const GValue * param_values,
    gpointer invocation_hint, gpointer marshal_data);
static PyObject * PyGObjectSignalClosure_marshal_params (const GValue * params, guint params_length);
static PyObject * PyGObject_marshal_value (const GValue * value);
static PyObject * PyGObject_marshal_string (const gchar * str);
static gboolean PyGObject_unmarshal_string (PyObject * value, gchar ** str);
static PyObject * PyGObject_marshal_datetime (const gchar * iso8601_text);
static PyObject * PyGObject_marshal_strv (gchar * const * strv, gint length);
static gboolean PyGObject_unmarshal_strv (PyObject * value, gchar *** strv, gint * length);
static PyObject * PyGObject_marshal_envp (gchar * const * envp, gint length);
static gboolean PyGObject_unmarshal_envp (PyObject * value, gchar *** envp, gint * length);
static PyObject * PyGObject_marshal_enum (gint value, GType type);
static gboolean PyGObject_unmarshal_enum (const gchar * str, GType type, gpointer value);
static PyObject * PyGObject_marshal_bytes (GBytes * bytes);
static PyObject * PyGObject_marshal_bytes_non_nullable (GBytes * bytes);
static PyObject * PyGObject_marshal_variant (GVariant * variant);
static gboolean PyGObject_unmarshal_variant (PyObject * value, GVariant ** variant);
static PyObject * PyGObject_marshal_parameters_dict (GHashTable * dict);
static PyObject * PyGObject_marshal_socket_address (GSocketAddress * address);
static gboolean PyGObject_unmarshal_certificate (const gchar * str, GTlsCertificate ** certificate);
static PyObject * PyGObject_marshal_object (gpointer handle, GType type);

static int PyDeviceManager_init (PyDeviceManager * self, PyObject * args, PyObject * kwds);
static void PyDeviceManager_dealloc (PyDeviceManager * self);
static PyObject * PyDeviceManager_close (PyDeviceManager * self);
static PyObject * PyDeviceManager_get_device_matching (PyDeviceManager * self, PyObject * args);
static gboolean PyDeviceManager_is_matching_device (FridaDevice * device, PyObject * predicate);
static PyObject * PyDeviceManager_enumerate_devices (PyDeviceManager * self);
static PyObject * PyDeviceManager_add_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw);
static PyObject * PyDeviceManager_remove_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw);
static FridaRemoteDeviceOptions * PyDeviceManager_parse_remote_device_options (const gchar * certificate_value, const gchar * origin,
    const gchar * token, gint keepalive_interval);

static PyObject * PyDevice_new_take_handle (FridaDevice * handle);
static int PyDevice_init (PyDevice * self, PyObject * args, PyObject * kw);
static void PyDevice_init_from_handle (PyDevice * self, FridaDevice * handle);
static void PyDevice_dealloc (PyDevice * self);
static PyObject * PyDevice_repr (PyDevice * self);
static PyObject * PyDevice_is_lost (PyDevice * self);
static PyObject * PyDevice_query_system_parameters (PyDevice * self);
static PyObject * PyDevice_get_frontmost_application (PyDevice * self, PyObject * args, PyObject * kw);
static PyObject * PyDevice_enumerate_applications (PyDevice * self, PyObject * args, PyObject * kw);
static FridaApplicationQueryOptions * PyDevice_parse_application_query_options (PyObject * identifiers_value, const gchar * scope_value);
static PyObject * PyDevice_enumerate_processes (PyDevice * self, PyObject * args, PyObject * kw);
static FridaProcessQueryOptions * PyDevice_parse_process_query_options (PyObject * pids_value, const gchar * scope_value);
static PyObject * PyDevice_enable_spawn_gating (PyDevice * self);
static PyObject * PyDevice_disable_spawn_gating (PyDevice * self);
static PyObject * PyDevice_enumerate_pending_spawn (PyDevice * self);
static PyObject * PyDevice_enumerate_pending_children (PyDevice * self);
static PyObject * PyDevice_spawn (PyDevice * self, PyObject * args, PyObject * kw);
static PyObject * PyDevice_input (PyDevice * self, PyObject * args);
static PyObject * PyDevice_resume (PyDevice * self, PyObject * args);
static PyObject * PyDevice_kill (PyDevice * self, PyObject * args);
static PyObject * PyDevice_attach (PyDevice * self, PyObject * args, PyObject * kw);
static FridaSessionOptions * PyDevice_parse_session_options (const gchar * realm_value, guint persist_timeout);
static PyObject * PyDevice_inject_library_file (PyDevice * self, PyObject * args);
static PyObject * PyDevice_inject_library_blob (PyDevice * self, PyObject * args);
static PyObject * PyDevice_open_channel (PyDevice * self, PyObject * args);

static PyObject * PyApplication_new_take_handle (FridaApplication * handle);
static int PyApplication_init (PyApplication * self, PyObject * args, PyObject * kw);
static void PyApplication_init_from_handle (PyApplication * self, FridaApplication * handle);
static void PyApplication_dealloc (PyApplication * self);
static PyObject * PyApplication_repr (PyApplication * self);
static PyObject * PyApplication_marshal_parameters_dict (GHashTable * dict);

static PyObject * PyProcess_new_take_handle (FridaProcess * handle);
static int PyProcess_init (PyProcess * self, PyObject * args, PyObject * kw);
static void PyProcess_init_from_handle (PyProcess * self, FridaProcess * handle);
static void PyProcess_dealloc (PyProcess * self);
static PyObject * PyProcess_repr (PyProcess * self);
static PyObject * PyProcess_marshal_parameters_dict (GHashTable * dict);

static PyObject * PySpawn_new_take_handle (FridaSpawn * handle);
static int PySpawn_init (PySpawn * self, PyObject * args, PyObject * kw);
static void PySpawn_init_from_handle (PySpawn * self, FridaSpawn * handle);
static void PySpawn_dealloc (PySpawn * self);
static PyObject * PySpawn_repr (PySpawn * self);

static PyObject * PyChild_new_take_handle (FridaChild * handle);
static int PyChild_init (PyChild * self, PyObject * args, PyObject * kw);
static void PyChild_init_from_handle (PyChild * self, FridaChild * handle);
static void PyChild_dealloc (PyChild * self);
static PyObject * PyChild_repr (PyChild * self);

static int PyCrash_init (PyCrash * self, PyObject * args, PyObject * kw);
static void PyCrash_init_from_handle (PyCrash * self, FridaCrash * handle);
static void PyCrash_dealloc (PyCrash * self);
static PyObject * PyCrash_repr (PyCrash * self);

static PyObject * PyBus_new_take_handle (FridaBus * handle);
static PyObject * PyBus_attach (PySession * self);
static PyObject * PyBus_post (PyScript * self, PyObject * args, PyObject * kw);

static PyObject * PySession_new_take_handle (FridaSession * handle);
static int PySession_init (PySession * self, PyObject * args, PyObject * kw);
static void PySession_init_from_handle (PySession * self, FridaSession * handle);
static PyObject * PySession_repr (PySession * self);
static PyObject * PySession_is_detached (PySession * self);
static PyObject * PySession_detach (PySession * self);
static PyObject * PySession_resume (PySession * self);
static PyObject * PySession_enable_child_gating (PySession * self);
static PyObject * PySession_disable_child_gating (PySession * self);
static PyObject * PySession_create_script (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_create_script_from_bytes (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_compile_script (PySession * self, PyObject * args, PyObject * kw);
static PyObject * PySession_snapshot_script (PySession * self, PyObject * args, PyObject * kw);
static FridaScriptOptions * PySession_parse_script_options (const gchar * name, gconstpointer snapshot_data, gsize snapshot_size,
    const gchar * runtime_value);
static PyObject * PySession_snapshot_script (PySession * self, PyObject * args, PyObject * kw);
static FridaSnapshotOptions * PySession_parse_snapshot_options (const gchar * warmup_script, const gchar * runtime_value);
static PyObject * PySession_setup_peer_connection (PySession * self, PyObject * args, PyObject * kw);
static FridaPeerOptions * PySession_parse_peer_options (const gchar * stun_server, PyObject * relays);
static PyObject * PySession_join_portal (PySession * self, PyObject * args, PyObject * kw);
static FridaPortalOptions * PySession_parse_portal_options (const gchar * certificate_value, const gchar * token, PyObject * acl_value);

static PyObject * PyScript_new_take_handle (FridaScript * handle);
static PyObject * PyScript_is_destroyed (PyScript * self);
static PyObject * PyScript_load (PyScript * self);
static PyObject * PyScript_unload (PyScript * self);
static PyObject * PyScript_eternalize (PyScript * self);
static PyObject * PyScript_post (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyScript_enable_debugger (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyScript_disable_debugger (PyScript * self);

static int PyRelay_init (PyRelay * self, PyObject * args, PyObject * kw);
static void PyRelay_init_from_handle (PyRelay * self, FridaRelay * handle);
static void PyRelay_dealloc (PyRelay * self);
static PyObject * PyRelay_repr (PyRelay * self);

static PyObject * PyPortalMembership_new_take_handle (FridaPortalMembership * handle);
static PyObject * PyPortalMembership_terminate (PyPortalMembership * self);

static int PyPortalService_init (PyPortalService * self, PyObject * args, PyObject * kw);
static void PyPortalService_init_from_handle (PyPortalService * self, FridaPortalService * handle);
static void PyPortalService_dealloc (PyPortalService * self);
static PyObject * PyPortalService_start (PyPortalService * self);
static PyObject * PyPortalService_stop (PyPortalService * self);
static PyObject * PyPortalService_kick (PyScript * self, PyObject * args);
static PyObject * PyPortalService_post (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyPortalService_narrowcast (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyPortalService_broadcast (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyPortalService_enumerate_tags (PyScript * self, PyObject * args);
static PyObject * PyPortalService_tag (PyScript * self, PyObject * args, PyObject * kw);
static PyObject * PyPortalService_untag (PyScript * self, PyObject * args, PyObject * kw);

static int PyEndpointParameters_init (PyEndpointParameters * self, PyObject * args, PyObject * kw);

static FridaPythonAuthenticationService * frida_python_authentication_service_new (PyObject * callback);
static void frida_python_authentication_service_iface_init (gpointer g_iface, gpointer iface_data);
static void frida_python_authentication_service_dispose (GObject * object);
static void frida_python_authentication_service_authenticate (FridaAuthenticationService * service, const gchar * token,
    GCancellable * cancellable, GAsyncReadyCallback callback, gpointer user_data);
static gchar * frida_python_authentication_service_authenticate_finish (FridaAuthenticationService * service, GAsyncResult * result,
    GError ** error);
static void frida_python_authentication_service_do_authenticate (GTask * task, FridaPythonAuthenticationService * self);

static int PyCompiler_init (PyCompiler * self, PyObject * args, PyObject * kw);
static PyObject * PyCompiler_build (PyCompiler * self, PyObject * args, PyObject * kw);
static PyObject * PyCompiler_watch (PyCompiler * self, PyObject * args, PyObject * kw);
static gboolean PyCompiler_set_options (FridaCompilerOptions * options, const gchar * project_root_value, const gchar * source_maps_value,
    const gchar * compression_value);

static int PyFileMonitor_init (PyFileMonitor * self, PyObject * args, PyObject * kw);
static PyObject * PyFileMonitor_enable (PyFileMonitor * self);
static PyObject * PyFileMonitor_disable (PyFileMonitor * self);

static PyObject * PyIOStream_new_take_handle (GIOStream * handle);
static int PyIOStream_init (PyIOStream * self, PyObject * args, PyObject * kw);
static void PyIOStream_init_from_handle (PyIOStream * self, GIOStream * handle);
static PyObject * PyIOStream_repr (PyIOStream * self);
static PyObject * PyIOStream_is_closed (PyIOStream * self);
static PyObject * PyIOStream_close (PyIOStream * self);
static PyObject * PyIOStream_read (PyIOStream * self, PyObject * args);
static PyObject * PyIOStream_read_all (PyIOStream * self, PyObject * args);
static PyObject * PyIOStream_write (PyIOStream * self, PyObject * args);
static PyObject * PyIOStream_write_all (PyIOStream * self, PyObject * args);

static int PyCancellable_init (PyCancellable * self, PyObject * args, PyObject * kw);
static PyObject * PyCancellable_repr (PyCancellable * self);
static PyObject * PyCancellable_is_cancelled (PyCancellable * self);
static PyObject * PyCancellable_raise_if_cancelled (PyCancellable * self);
static PyObject * PyCancellable_get_fd (PyCancellable * self);
static PyObject * PyCancellable_release_fd (PyCancellable * self);
static PyObject * PyCancellable_get_current (PyCancellable * self);
static PyObject * PyCancellable_push_current (PyCancellable * self);
static PyObject * PyCancellable_pop_current (PyCancellable * self);
static PyObject * PyCancellable_connect (PyCancellable * self, PyObject * args);
static PyObject * PyCancellable_disconnect (PyCancellable * self, PyObject * args);
static void PyCancellable_on_cancelled (GCancellable * cancellable, PyObject * callback);
static void PyCancellable_destroy_callback (PyObject * callback);
static PyObject * PyCancellable_cancel (PyCancellable * self);

static PyObject * PyFrida_raise (GError * error);
static gboolean PyFrida_is_string (PyObject * obj);
static gchar * PyFrida_repr (PyObject * obj);
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
  { "get_device_matching", (PyCFunction) PyDeviceManager_get_device_matching, METH_VARARGS, "Get device matching predicate." },
  { "enumerate_devices", (PyCFunction) PyDeviceManager_enumerate_devices, METH_NOARGS, "Enumerate devices." },
  { "add_remote_device", (PyCFunction) PyDeviceManager_add_remote_device, METH_VARARGS | METH_KEYWORDS, "Add a remote device." },
  { "remove_remote_device", (PyCFunction) PyDeviceManager_remove_remote_device, METH_VARARGS | METH_KEYWORDS, "Remove a remote device." },
  { NULL }
};

static PyMethodDef PyDevice_methods[] =
{
  { "is_lost", (PyCFunction) PyDevice_is_lost, METH_NOARGS, "Query whether the device has been lost." },
  { "query_system_parameters", (PyCFunction) PyDevice_query_system_parameters, METH_NOARGS, "Returns a dictionary of information about the host system." },
  { "get_frontmost_application", (PyCFunction) PyDevice_get_frontmost_application, METH_VARARGS | METH_KEYWORDS, "Get details about the frontmost application." },
  { "enumerate_applications", (PyCFunction) PyDevice_enumerate_applications, METH_VARARGS | METH_KEYWORDS, "Enumerate applications." },
  { "enumerate_processes", (PyCFunction) PyDevice_enumerate_processes, METH_VARARGS | METH_KEYWORDS, "Enumerate processes." },
  { "enable_spawn_gating", (PyCFunction) PyDevice_enable_spawn_gating, METH_NOARGS, "Enable spawn gating." },
  { "disable_spawn_gating", (PyCFunction) PyDevice_disable_spawn_gating, METH_NOARGS, "Disable spawn gating." },
  { "enumerate_pending_spawn", (PyCFunction) PyDevice_enumerate_pending_spawn, METH_NOARGS, "Enumerate pending spawn." },
  { "enumerate_pending_children", (PyCFunction) PyDevice_enumerate_pending_children, METH_NOARGS, "Enumerate pending children." },
  { "spawn", (PyCFunction) PyDevice_spawn, METH_VARARGS | METH_KEYWORDS, "Spawn a process into an attachable state." },
  { "input", (PyCFunction) PyDevice_input, METH_VARARGS, "Input data on stdin of a spawned process." },
  { "resume", (PyCFunction) PyDevice_resume, METH_VARARGS, "Resume a process from the attachable state." },
  { "kill", (PyCFunction) PyDevice_kill, METH_VARARGS, "Kill a PID." },
  { "attach", (PyCFunction) PyDevice_attach, METH_VARARGS | METH_KEYWORDS, "Attach to a PID." },
  { "inject_library_file", (PyCFunction) PyDevice_inject_library_file, METH_VARARGS, "Inject a library file to a PID." },
  { "inject_library_blob", (PyCFunction) PyDevice_inject_library_blob, METH_VARARGS, "Inject a library blob to a PID." },
  { "open_channel", (PyCFunction) PyDevice_open_channel, METH_VARARGS, "Open a device-specific communication channel." },
  { NULL }
};

static PyMemberDef PyDevice_members[] =
{
  { "id", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, id), READONLY, "Device ID." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, name), READONLY, "Human-readable device name." },
  { "icon", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, icon), READONLY, "Icon." },
  { "type", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, type), READONLY, "Device type. One of: local, remote, usb." },
  { "bus", T_OBJECT_EX, G_STRUCT_OFFSET (PyDevice, bus), READONLY, "Message bus." },
  { NULL }
};

static PyMemberDef PyApplication_members[] =
{
  { "identifier", T_OBJECT_EX, G_STRUCT_OFFSET (PyApplication, identifier), READONLY, "Application identifier." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyApplication, name), READONLY, "Human-readable application name." },
  { "pid", T_UINT, G_STRUCT_OFFSET (PyApplication, pid), READONLY, "Process ID, or 0 if not running." },
  { "parameters", T_OBJECT_EX, G_STRUCT_OFFSET (PyApplication, parameters), READONLY, "Parameters." },
  { NULL }
};

static PyMemberDef PyProcess_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PyProcess, pid), READONLY, "Process ID." },
  { "name", T_OBJECT_EX, G_STRUCT_OFFSET (PyProcess, name), READONLY, "Human-readable process name." },
  { "parameters", T_OBJECT_EX, G_STRUCT_OFFSET (PyProcess, parameters), READONLY, "Parameters." },
  { NULL }
};

static PyMemberDef PySpawn_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PySpawn, pid), READONLY, "Process ID." },
  { "identifier", T_OBJECT_EX, G_STRUCT_OFFSET (PySpawn, identifier), READONLY, "Application identifier." },
  { NULL }
};

static PyMemberDef PyChild_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PyChild, pid), READONLY, "Process ID." },
  { "parent_pid", T_UINT, G_STRUCT_OFFSET (PyChild, parent_pid), READONLY, "Parent Process ID." },
  { "origin", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, origin), READONLY, "Origin." },
  { "identifier", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, identifier), READONLY, "Application identifier." },
  { "path", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, path), READONLY, "Path of executable." },
  { "argv", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, argv), READONLY, "Argument vector." },
  { "envp", T_OBJECT_EX, G_STRUCT_OFFSET (PyChild, envp), READONLY, "Environment vector." },
  { NULL }
};

static PyMemberDef PyCrash_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PyCrash, pid), READONLY, "Process ID." },
  { "process_name", T_OBJECT_EX, G_STRUCT_OFFSET (PyCrash, process_name), READONLY, "Process name." },
  { "summary", T_OBJECT_EX, G_STRUCT_OFFSET (PyCrash, summary), READONLY, "Human-readable crash summary." },
  { "report", T_OBJECT_EX, G_STRUCT_OFFSET (PyCrash, report), READONLY, "Human-readable crash report." },
  { "parameters", T_OBJECT_EX, G_STRUCT_OFFSET (PyCrash, parameters), READONLY, "Parameters." },
  { NULL }
};

static PyMethodDef PyBus_methods[] =
{
  { "attach", (PyCFunction) PyBus_attach, METH_NOARGS, "Attach to the bus." },
  { "post", (PyCFunction) PyBus_post, METH_VARARGS | METH_KEYWORDS, "Post a JSON-encoded message to the bus." },
  { NULL }
};

static PyMethodDef PySession_methods[] =
{
  { "is_detached", (PyCFunction) PySession_is_detached, METH_NOARGS, "Query whether the session is detached." },
  { "detach", (PyCFunction) PySession_detach, METH_NOARGS, "Detach session from the process." },
  { "resume", (PyCFunction) PySession_resume, METH_NOARGS, "Resume session after network error." },
  { "enable_child_gating", (PyCFunction) PySession_enable_child_gating, METH_NOARGS, "Enable child gating." },
  { "disable_child_gating", (PyCFunction) PySession_disable_child_gating, METH_NOARGS, "Disable child gating." },
  { "create_script", (PyCFunction) PySession_create_script, METH_VARARGS | METH_KEYWORDS, "Create a new script." },
  { "create_script_from_bytes", (PyCFunction) PySession_create_script_from_bytes, METH_VARARGS | METH_KEYWORDS, "Create a new script from bytecode." },
  { "compile_script", (PyCFunction) PySession_compile_script, METH_VARARGS | METH_KEYWORDS, "Compile script source code to bytecode." },
  { "snapshot_script", (PyCFunction) PySession_snapshot_script, METH_VARARGS | METH_KEYWORDS, "Evaluate script and snapshot the resulting VM state." },
  { "setup_peer_connection", (PyCFunction) PySession_setup_peer_connection, METH_VARARGS | METH_KEYWORDS, "Set up a peer connection with the target process." },
  { "join_portal", (PyCFunction) PySession_join_portal, METH_VARARGS | METH_KEYWORDS, "Join a portal." },
  { NULL }
};

static PyMemberDef PySession_members[] =
{
  { "pid", T_UINT, G_STRUCT_OFFSET (PySession, pid), READONLY, "Process ID." },
  { NULL }
};

static PyMethodDef PyScript_methods[] =
{
  { "is_destroyed", (PyCFunction) PyScript_is_destroyed, METH_NOARGS, "Query whether the script has been destroyed." },
  { "load", (PyCFunction) PyScript_load, METH_NOARGS, "Load the script." },
  { "unload", (PyCFunction) PyScript_unload, METH_NOARGS, "Unload the script." },
  { "eternalize", (PyCFunction) PyScript_eternalize, METH_NOARGS, "Eternalize the script." },
  { "post", (PyCFunction) PyScript_post, METH_VARARGS | METH_KEYWORDS, "Post a JSON-encoded message to the script." },
  { "enable_debugger", (PyCFunction) PyScript_enable_debugger, METH_VARARGS | METH_KEYWORDS, "Enable the Node.js compatible script debugger." },
  { "disable_debugger", (PyCFunction) PyScript_disable_debugger, METH_NOARGS, "Disable the Node.js compatible script debugger." },
  { NULL }
};

static PyMemberDef PyRelay_members[] =
{
  { "address", T_OBJECT_EX, G_STRUCT_OFFSET (PyRelay, address), READONLY, "Network address or address:port of the TURN server." },
  { "username", T_OBJECT_EX, G_STRUCT_OFFSET (PyRelay, username), READONLY, "The TURN username to use for the allocate request." },
  { "password", T_OBJECT_EX, G_STRUCT_OFFSET (PyRelay, password), READONLY, "The TURN password to use for the allocate request." },
  { "kind", T_OBJECT_EX, G_STRUCT_OFFSET (PyRelay, kind), READONLY, "Relay kind. One of: turn-udp, turn-tcp, turn-tls." },
  { NULL }
};

static PyMethodDef PyPortalMembership_methods[] =
{
  { "terminate", (PyCFunction) PyPortalMembership_terminate, METH_NOARGS, "Terminate the membership." },
  { NULL }
};

static PyMethodDef PyPortalService_methods[] =
{
  { "start", (PyCFunction) PyPortalService_start, METH_NOARGS, "Start listening for incoming connections." },
  { "stop", (PyCFunction) PyPortalService_stop, METH_NOARGS, "Stop listening for incoming connections, and kick any connected clients." },
  { "kick", (PyCFunction) PyPortalService_kick, METH_VARARGS, "Kick out a specific connection." },
  { "post", (PyCFunction) PyPortalService_post, METH_VARARGS | METH_KEYWORDS, "Post a message to a specific control channel." },
  { "narrowcast", (PyCFunction) PyPortalService_narrowcast, METH_VARARGS | METH_KEYWORDS, "Post a message to control channels with a specific tag." },
  { "broadcast", (PyCFunction) PyPortalService_broadcast, METH_VARARGS | METH_KEYWORDS, "Broadcast a message to all control channels." },
  { "enumerate_tags", (PyCFunction) PyPortalService_enumerate_tags, METH_VARARGS, "Enumerate tags of a specific connection." },
  { "tag", (PyCFunction) PyPortalService_tag, METH_VARARGS | METH_KEYWORDS, "Tag a specific control channel." },
  { "untag", (PyCFunction) PyPortalService_untag, METH_VARARGS | METH_KEYWORDS, "Untag a specific control channel." },
  { NULL }
};

static PyMemberDef PyPortalService_members[] =
{
  { "device", T_OBJECT_EX, G_STRUCT_OFFSET (PyPortalService, device), READONLY, "Device for in-process control." },
  { NULL }
};

static PyMethodDef PyCompiler_methods[] =
{
  { "build", (PyCFunction) PyCompiler_build, METH_VARARGS | METH_KEYWORDS, "Build an agent." },
  { "watch", (PyCFunction) PyCompiler_watch, METH_VARARGS | METH_KEYWORDS, "Continuously build an agent." },
  { NULL }
};

static PyMethodDef PyFileMonitor_methods[] =
{
  { "enable", (PyCFunction) PyFileMonitor_enable, METH_NOARGS, "Enable the file monitor." },
  { "disable", (PyCFunction) PyFileMonitor_disable, METH_NOARGS, "Disable the file monitor." },
  { NULL }
};

static PyMethodDef PyIOStream_methods[] =
{
  { "is_closed", (PyCFunction) PyIOStream_is_closed, METH_NOARGS, "Query whether the stream is closed." },
  { "close", (PyCFunction) PyIOStream_close, METH_NOARGS, "Close the stream." },
  { "read", (PyCFunction) PyIOStream_read, METH_VARARGS, "Read up to the specified number of bytes from the stream." },
  { "read_all", (PyCFunction) PyIOStream_read_all, METH_VARARGS, "Read exactly the specified number of bytes from the stream." },
  { "write", (PyCFunction) PyIOStream_write, METH_VARARGS, "Write as much as possible of the provided data to the stream." },
  { "write_all", (PyCFunction) PyIOStream_write_all, METH_VARARGS, "Write all of the provided data to the stream." },
  { NULL }
};

static PyMethodDef PyCancellable_methods[] =
{
  { "is_cancelled", (PyCFunction) PyCancellable_is_cancelled, METH_NOARGS, "Query whether cancellable has been cancelled." },
  { "raise_if_cancelled", (PyCFunction) PyCancellable_raise_if_cancelled, METH_NOARGS, "Raise an exception if cancelled." },
  { "get_fd", (PyCFunction) PyCancellable_get_fd, METH_NOARGS, "Get file descriptor for integrating with an event loop." },
  { "release_fd", (PyCFunction) PyCancellable_release_fd, METH_NOARGS, "Release a resource previously allocated by get_fd()." },
  { "get_current", (PyCFunction) PyCancellable_get_current, METH_CLASS | METH_NOARGS, "Get the top cancellable from the stack." },
  { "push_current", (PyCFunction) PyCancellable_push_current, METH_NOARGS, "Push cancellable onto the cancellable stack." },
  { "pop_current", (PyCFunction) PyCancellable_pop_current, METH_NOARGS, "Pop cancellable off the cancellable stack." },
  { "connect", (PyCFunction) PyCancellable_connect, METH_VARARGS, "Register notification callback." },
  { "disconnect", (PyCFunction) PyCancellable_disconnect, METH_VARARGS, "Unregister notification callback." },
  { "cancel", (PyCFunction) PyCancellable_cancel, METH_NOARGS, "Set cancellable to cancelled." },
  { NULL }
};

PYFRIDA_DEFINE_BASETYPE ("_frida.Object", GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida Object" },
  { Py_tp_init, PyGObject_init },
  { Py_tp_dealloc, PyGObject_dealloc },
  { Py_tp_methods, PyGObject_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.DeviceManager", DeviceManager, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida Device Manager" },
  { Py_tp_init, PyDeviceManager_init },
  { Py_tp_dealloc, PyDeviceManager_dealloc },
  { Py_tp_methods, PyDeviceManager_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Device", Device, GObject, PyDevice_init_from_handle, frida_unref,
  { Py_tp_doc, "Frida Device" },
  { Py_tp_init, PyDevice_init },
  { Py_tp_dealloc, PyDevice_dealloc },
  { Py_tp_repr, PyDevice_repr },
  { Py_tp_methods, PyDevice_methods },
  { Py_tp_members, PyDevice_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Application", Application, GObject, PyApplication_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Application" },
  { Py_tp_init, PyApplication_init },
  { Py_tp_dealloc, PyApplication_dealloc },
  { Py_tp_repr, PyApplication_repr },
  { Py_tp_members, PyApplication_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Process", Process, GObject, PyProcess_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Process" },
  { Py_tp_init, PyProcess_init },
  { Py_tp_dealloc, PyProcess_dealloc },
  { Py_tp_repr, PyProcess_repr },
  { Py_tp_members, PyProcess_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Spawn", Spawn, GObject, PySpawn_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Spawn" },
  { Py_tp_init, PySpawn_init },
  { Py_tp_dealloc, PySpawn_dealloc },
  { Py_tp_repr, PySpawn_repr },
  { Py_tp_members, PySpawn_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Child", Child, GObject, PyChild_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Child" },
  { Py_tp_init, PyChild_init },
  { Py_tp_dealloc, PyChild_dealloc },
  { Py_tp_repr, PyChild_repr },
  { Py_tp_members, PyChild_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Crash", Crash, GObject, PyCrash_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Crash Details" },
  { Py_tp_init, PyCrash_init },
  { Py_tp_dealloc, PyCrash_dealloc },
  { Py_tp_repr, PyCrash_repr },
  { Py_tp_members, PyCrash_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Bus", Bus, GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida Message Bus" },
  { Py_tp_methods, PyBus_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Session", Session, GObject, PySession_init_from_handle, frida_unref,
  { Py_tp_doc, "Frida Session" },
  { Py_tp_init, PySession_init },
  { Py_tp_repr, PySession_repr },
  { Py_tp_methods, PySession_methods },
  { Py_tp_members, PySession_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.Script", Script, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida Script" },
  { Py_tp_methods, PyScript_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Relay", Relay, GObject, PyRelay_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida Relay" },
  { Py_tp_init, PyRelay_init },
  { Py_tp_dealloc, PyRelay_dealloc },
  { Py_tp_repr, PyRelay_repr },
  { Py_tp_members, PyRelay_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.PortalMembership", PortalMembership, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida Portal Membership" },
  { Py_tp_methods, PyPortalMembership_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.PortalService", PortalService, GObject, PyPortalService_init_from_handle, frida_unref,
  { Py_tp_doc, "Frida Portal Service" },
  { Py_tp_init, PyPortalService_init },
  { Py_tp_dealloc, PyPortalService_dealloc },
  { Py_tp_methods, PyPortalService_methods },
  { Py_tp_members, PyPortalService_members },
);

PYFRIDA_DEFINE_TYPE ("_frida.EndpointParameters", EndpointParameters, GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida EndpointParameters" },
  { Py_tp_init, PyEndpointParameters_init },
);

PYFRIDA_DEFINE_TYPE ("_frida.Compiler", Compiler, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida File Monitor" },
  { Py_tp_init, PyCompiler_init },
  { Py_tp_methods, PyCompiler_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.FileMonitor", FileMonitor, GObject, NULL, frida_unref,
  { Py_tp_doc, "Frida File Monitor" },
  { Py_tp_init, PyFileMonitor_init },
  { Py_tp_methods, PyFileMonitor_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.IOStream", IOStream, GObject, PyIOStream_init_from_handle, g_object_unref,
  { Py_tp_doc, "Frida IOStream" },
  { Py_tp_init, PyIOStream_init },
  { Py_tp_repr, PyIOStream_repr },
  { Py_tp_methods, PyIOStream_methods },
);

PYFRIDA_DEFINE_TYPE ("_frida.Cancellable", Cancellable, GObject, NULL, g_object_unref,
  { Py_tp_doc, "Frida Cancellable" },
  { Py_tp_init, PyCancellable_init },
  { Py_tp_repr, PyCancellable_repr },
  { Py_tp_methods, PyCancellable_methods },
);


static PyObject *
PyGObject_new_take_handle (gpointer handle, const PyGObjectType * pytype)
{
  PyObject * object;

  if (handle == NULL)
    Py_RETURN_NONE;

  object = PyGObject_try_get_from_handle (handle);
  if (object == NULL)
  {
    object = PyObject_CallFunction (pytype->object, NULL);
    PyGObject_take_handle (PY_GOBJECT (object), handle, pytype);

    if (pytype->init_from_handle != NULL)
      pytype->init_from_handle (object, handle);
  }
  else
  {
    pytype->destroy (handle);
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
  self->type = PYFRIDA_TYPE (GObject);

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
    self->type->destroy (handle);
    Py_END_ALLOW_THREADS
  }

  ((freefunc) PyType_GetSlot (Py_TYPE (self), Py_tp_free)) (self);
}

static void
PyGObject_take_handle (PyGObject * self, gpointer handle, const PyGObjectType * type)
{
  self->handle = handle;
  self->type = type;

  if (handle != NULL)
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
    g_assert (num_matches == 1);
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

  closure = PyGObject_make_closure_for_signal (signal_id, callback, max_arg_count);
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
  g_assert (num_matches == 1);

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
PyGObject_register_type (GType instance_type, PyGObjectType * python_type)
{
  g_hash_table_insert (pygobject_type_spec_by_type, GSIZE_TO_POINTER (instance_type), python_type);
}

static GClosure *
PyGObject_make_closure_for_signal (guint signal_id, PyObject * callback, guint max_arg_count)
{
  GClosure * closure;
  PyGObjectSignalClosure * pyclosure;

  closure = g_closure_new_simple (sizeof (PyGObjectSignalClosure), callback);
  Py_IncRef (callback);

  g_closure_add_finalize_notifier (closure, callback, (GClosureNotify) PyGObjectSignalClosure_finalize);
  g_closure_set_marshal (closure, PyGObjectSignalClosure_marshal);

  pyclosure = PY_GOBJECT_SIGNAL_CLOSURE (closure);
  pyclosure->signal_id = signal_id;
  pyclosure->max_arg_count = max_arg_count;

  return closure;
}

static void
PyGObjectSignalClosure_finalize (PyObject * callback)
{
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

  (void) return_gvalue;
  (void) invocation_hint;
  (void) marshal_data;

  if (g_atomic_int_get (&toplevel_objects_alive) == 0)
    return;

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
  if (result != NULL)
    Py_DECREF (result);
  else
    PyErr_Print ();

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
      return PyGObject_marshal_string (g_value_get_string (value));

    case G_TYPE_VARIANT:
      return PyGObject_marshal_variant (g_value_get_variant (value));

    default:
      if (G_TYPE_IS_ENUM (type))
        return PyGObject_marshal_enum (g_value_get_enum (value), type);

      if (type == G_TYPE_BYTES)
        return PyGObject_marshal_bytes (g_value_get_boxed (value));

      if (G_TYPE_IS_OBJECT (type))
        return PyGObject_marshal_object (g_value_get_object (value), type);

      goto unsupported_type;
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
PyGObject_marshal_string (const gchar * str)
{
  if (str == NULL)
    Py_RETURN_NONE;

  return PyUnicode_FromUTF8String (str);
}

static gboolean
PyGObject_unmarshal_string (PyObject * value, gchar ** str)
{
  PyObject * bytes;

  *str = NULL;

  bytes = PyUnicode_AsUTF8String (value);
  if (bytes == NULL)
    return FALSE;

  *str = g_strdup (PyBytes_AsString (bytes));

  Py_DecRef (bytes);

  return *str != NULL;
}

static PyObject *
PyGObject_marshal_datetime (const gchar * iso8601_text)
{
  PyObject * result;
  GDateTime * raw_dt, * dt;

  raw_dt = g_date_time_new_from_iso8601 (iso8601_text, NULL);
  if (raw_dt == NULL)
    Py_RETURN_NONE;

  dt = g_date_time_to_local (raw_dt);

  result = PyObject_CallFunction (datetime_constructor, "iiiiiii",
      g_date_time_get_year (dt),
      g_date_time_get_month (dt),
      g_date_time_get_day_of_month (dt),
      g_date_time_get_hour (dt),
      g_date_time_get_minute (dt),
      g_date_time_get_second (dt),
      g_date_time_get_microsecond (dt));

  g_date_time_unref (dt);
  g_date_time_unref (raw_dt);

  return result;
}

static PyObject *
PyGObject_marshal_strv (gchar * const * strv, gint length)
{
  PyObject * result;
  gint i;

  if (strv == NULL)
    Py_RETURN_NONE;

  result = PyList_New (length);

  for (i = 0; i != length; i++)
  {
    PyList_SetItem (result, i, PyGObject_marshal_string (strv[i]));
  }

  return result;
}

static gboolean
PyGObject_unmarshal_strv (PyObject * value, gchar *** strv, gint * length)
{
  gint n, i;
  gchar ** elements;

  if (!PyList_Check (value) && !PyTuple_Check (value))
    goto invalid_type;

  n = PySequence_Size (value);
  elements = g_new0 (gchar *, n + 1);

  for (i = 0; i != n; i++)
  {
    PyObject * element;

    element = PySequence_GetItem (value, i);
    if (PyUnicode_Check (element))
    {
      Py_DECREF (element);
      element = PyUnicode_AsUTF8String (element);
    }
    if (PyBytes_Check (element))
      elements[i] = g_strdup (PyBytes_AsString (element));
    Py_DECREF (element);

    if (elements[i] == NULL)
      goto invalid_element;
  }

  *strv = elements;
  *length = n;

  return TRUE;

invalid_type:
  {
    PyErr_SetString (PyExc_TypeError, "expected list or tuple of strings");
    return FALSE;
  }
invalid_element:
  {
    g_strfreev (elements);

    PyErr_SetString (PyExc_TypeError, "expected list or tuple with string elements only");
    return FALSE;
  }
}

static PyObject *
PyGObject_marshal_envp (gchar * const * envp, gint length)
{
  PyObject * result;
  gint i;

  if (envp == NULL)
    Py_RETURN_NONE;

  result = PyDict_New ();

  for (i = 0; i != length; i++)
  {
    gchar ** tokens;

    tokens = g_strsplit (envp[i], "=", 2);

    if (g_strv_length (tokens) == 2)
    {
      const gchar * name;
      PyObject * value;

      name = tokens[0];
      value = PyGObject_marshal_string (tokens[1]);

      PyDict_SetItemString (result, name, value);

      Py_DECREF (value);
    }

    g_strfreev (tokens);
  }

  return result;
}

static gboolean
PyGObject_unmarshal_envp (PyObject * dict, gchar *** envp, gint * length)
{
  gint n;
  gchar ** elements;
  gint i;
  Py_ssize_t pos;
  PyObject * name, * value;
  gchar * raw_name = NULL;
  gchar * raw_value = NULL;

  if (!PyDict_Check (dict))
    goto invalid_type;

  n = PyDict_Size (dict);
  elements = g_new0 (gchar *, n + 1);

  i = 0;
  pos = 0;
  while (PyDict_Next (dict, &pos, &name, &value))
  {
    if (!PyGObject_unmarshal_string (name, &raw_name))
      goto invalid_dict_key;

    if (!PyGObject_unmarshal_string (value, &raw_value))
      goto invalid_dict_value;

    elements[i] = g_strconcat (raw_name, "=", raw_value, NULL);

    g_free (g_steal_pointer (&raw_value));
    g_free (g_steal_pointer (&raw_name));

    i++;
  }

  *envp = elements;
  *length = n;

  return TRUE;

invalid_type:
  {
    PyErr_SetString (PyExc_TypeError, "expected dict");
    return FALSE;
  }
invalid_dict_key:
invalid_dict_value:
  {
    g_free (raw_value);
    g_free (raw_name);
    g_strfreev (elements);

    PyErr_SetString (PyExc_TypeError, "expected dict with strings only");
    return FALSE;
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

static gboolean
PyGObject_unmarshal_enum (const gchar * str, GType type, gpointer value)
{
  GEnumClass * enum_class;
  GEnumValue * enum_value;

  enum_class = g_type_class_ref (type);

  enum_value = g_enum_get_value_by_nick (enum_class, str);
  if (enum_value == NULL)
    goto invalid_value;

  *((gint *) value) = enum_value->value;

  g_type_class_unref (enum_class);

  return TRUE;

invalid_value:
  {
    GString * message;
    guint i;

    message = g_string_sized_new (128);

    g_string_append_printf (message,
        "Enum type %s does not have a value named '%s', it only has: ",
        PyGObject_class_name_from_c (g_type_name (type)), str);

    for (i = 0; i != enum_class->n_values; i++)
    {
      if (i != 0)
        g_string_append (message, ", ");
      g_string_append_c (message, '\'');
      g_string_append (message, enum_class->values[i].value_nick);
      g_string_append_c (message, '\'');
    }

    PyErr_SetString (PyExc_ValueError, message->str);

    g_string_free (message, TRUE);

    g_type_class_unref (enum_class);

    return FALSE;
  }
}

static PyObject *
PyGObject_marshal_bytes (GBytes * bytes)
{
  if (bytes == NULL)
    Py_RETURN_NONE;

  return PyGObject_marshal_bytes_non_nullable (bytes);
}

static PyObject *
PyGObject_marshal_bytes_non_nullable (GBytes * bytes)
{
  gconstpointer data;
  gsize size;

  data = g_bytes_get_data (bytes, &size);

  return PyBytes_FromStringAndSize (data, size);
}

static PyObject *
PyGObject_marshal_variant (GVariant * variant)
{
  if (g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING))
    return PyGObject_marshal_string (g_variant_get_string (variant, NULL));

  if (g_variant_is_of_type (variant, G_VARIANT_TYPE_INT64))
    return PyLong_FromLongLong (g_variant_get_int64 (variant));

  if (g_variant_is_of_type (variant, G_VARIANT_TYPE_BOOLEAN))
    return PyBool_FromLong (g_variant_get_boolean (variant));

  if (g_variant_is_of_type (variant, G_VARIANT_TYPE ("ay")))
  {
    gconstpointer elements;
    gsize n_elements;

    elements = g_variant_get_fixed_array (variant, &n_elements, sizeof (guint8));

    return PyBytes_FromStringAndSize (elements, n_elements);
  }

  if (g_variant_is_of_type (variant, G_VARIANT_TYPE_VARDICT))
  {
    PyObject * dict;
    GVariantIter iter;
    gchar * key;
    GVariant * raw_value;

    dict = PyDict_New ();

    g_variant_iter_init (&iter, variant);

    while (g_variant_iter_next (&iter, "{sv}", &key, &raw_value))
    {
      PyObject * value = PyGObject_marshal_variant (raw_value);

      PyDict_SetItemString (dict, key, value);

      Py_DECREF (value);
      g_variant_unref (raw_value);
      g_free (key);
    }

    return dict;
  }

  if (g_variant_is_of_type (variant, G_VARIANT_TYPE_ARRAY))
  {
    GVariantIter iter;
    PyObject * list;
    guint i;
    GVariant * child;

    g_variant_iter_init (&iter, variant);

    list = PyList_New (g_variant_iter_n_children (&iter));

    for (i = 0; (child = g_variant_iter_next_value (&iter)) != NULL; i++)
    {
      PyList_SetItem (list, i, PyGObject_marshal_variant (child));
      g_variant_unref (child);
    }

    return list;
  }

  Py_RETURN_NONE;
}

static gboolean
PyGObject_unmarshal_variant (PyObject * value, GVariant ** variant)
{
  if (PyFrida_is_string (value))
  {
    gchar * str;

    PyGObject_unmarshal_string (value, &str);

    *variant = g_variant_new_take_string (str);
  }
  else if (PyBool_Check (value))
  {
    *variant = g_variant_new_boolean (value == Py_True);
  }
#if PY_MAJOR_VERSION < 3
  else if (PyUnicode_Check (value))
  {
    PyObject * value_utf8;

    value_utf8 = PyUnicode_AsUTF8String (value);
    if (value_utf8 == NULL)
      goto propagate_error;

    *variant = g_variant_new_string (PyBytes_AsString (value_utf8));

    Py_DECREF (value_utf8);
  }
  else if (PyInt_Check (value))
  {
    *variant = g_variant_new_int64 (PyInt_AS_LONG (value));
  }
#endif
  else if (PyLong_Check (value))
  {
    PY_LONG_LONG l;

    l = PyLong_AsLongLong (value);
    if (l == -1 && PyErr_Occurred ())
      goto propagate_error;

    *variant = g_variant_new_int64 (l);
  }
  else
  {
    goto unsupported_type;
  }

  return TRUE;

unsupported_type:
  {
    PyErr_SetString (PyExc_TypeError, "unsupported type");
    goto propagate_error;
  }
propagate_error:
  {
    return FALSE;
  }
}

static PyObject *
PyGObject_marshal_parameters_dict (GHashTable * dict)
{
  PyObject * result;
  GHashTableIter iter;
  const gchar * key;
  GVariant * raw_value;

  result = PyDict_New ();

  g_hash_table_iter_init (&iter, dict);

  while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &raw_value))
  {
    PyObject * value = PyGObject_marshal_variant (raw_value);

    PyDict_SetItemString (result, key, value);

    Py_DECREF (value);
  }

  return result;
}

static PyObject *
PyGObject_marshal_object (gpointer handle, GType type)
{
  const PyGObjectType * pytype;

  if (handle == NULL)
    Py_RETURN_NONE;

  pytype = g_hash_table_lookup (pygobject_type_spec_by_type, GSIZE_TO_POINTER (type));
  if (pytype == NULL)
    pytype = PYFRIDA_TYPE (GObject);

  if (G_IS_SOCKET_ADDRESS (handle))
    return PyGObject_marshal_socket_address (handle);

  return PyGObject_new_take_handle (g_object_ref (handle), pytype);
}

static PyObject *
PyGObject_marshal_socket_address (GSocketAddress * address)
{
  PyObject * result = NULL;

  if (G_IS_INET_SOCKET_ADDRESS (address))
  {
    GInetSocketAddress * sa;
    GInetAddress * ia;
    gchar * host;
    guint16 port;

    sa = G_INET_SOCKET_ADDRESS (address);
    ia = g_inet_socket_address_get_address (sa);

    host = g_inet_address_to_string (ia);
    port = g_inet_socket_address_get_port (sa);

    if (g_socket_address_get_family (address) == G_SOCKET_FAMILY_IPV4)
      result = Py_BuildValue ("(sH)", host, port);
    else
      result = Py_BuildValue ("(sHII)", host, port, g_inet_socket_address_get_flowinfo (sa), g_inet_socket_address_get_scope_id (sa));

    g_free (host);
  }
#ifdef G_OS_UNIX
  else if (G_IS_UNIX_SOCKET_ADDRESS (address))
  {
    GUnixSocketAddress * sa = G_UNIX_SOCKET_ADDRESS (address);

    switch (g_unix_socket_address_get_address_type (sa))
    {
      case G_UNIX_SOCKET_ADDRESS_ANONYMOUS:
      {
        result = PyUnicode_FromUTF8String ("");
        break;
      }
      case G_UNIX_SOCKET_ADDRESS_PATH:
      {
        gchar * path = g_filename_to_utf8 (g_unix_socket_address_get_path (sa), -1, NULL, NULL, NULL);
        result = PyUnicode_FromUTF8String (path);
        g_free (path);
        break;
      }
      case G_UNIX_SOCKET_ADDRESS_ABSTRACT:
      case G_UNIX_SOCKET_ADDRESS_ABSTRACT_PADDED:
      {
        result = PyBytes_FromStringAndSize (g_unix_socket_address_get_path (sa), g_unix_socket_address_get_path_len (sa));
        break;
      }
      default:
      {
        result = Py_None;
        Py_INCREF (result);
        break;
      }
    }
  }
#endif

  if (result == NULL)
    result = PyGObject_new_take_handle (g_object_ref (address), PYFRIDA_TYPE (GObject));

  return result;
}

static gboolean
PyGObject_unmarshal_certificate (const gchar * str, GTlsCertificate ** certificate)
{
  GError * error = NULL;

  if (strchr (str, '\n') != NULL)
    *certificate = g_tls_certificate_new_from_pem (str, -1, &error);
  else
    *certificate = g_tls_certificate_new_from_file (str, &error);
  if (error != NULL)
    goto propagate_error;

  return TRUE;

propagate_error:
  {
    PyFrida_raise (g_error_new_literal (FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT, error->message));
    g_error_free (error);

    return FALSE;
  }
}


static int
PyDeviceManager_init (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  g_atomic_int_inc (&toplevel_objects_alive);

  PyGObject_take_handle (&self->parent, frida_device_manager_new (), PYFRIDA_TYPE (DeviceManager));

  return 0;
}

static void
PyDeviceManager_dealloc (PyDeviceManager * self)
{
  FridaDeviceManager * handle;

  g_atomic_int_dec_and_test (&toplevel_objects_alive);

  handle = PyGObject_steal_handle (&self->parent);
  if (handle != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    frida_device_manager_close_sync (handle, NULL, NULL);
    frida_unref (handle);
    Py_END_ALLOW_THREADS
  }

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyDeviceManager_close (PyDeviceManager * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_close_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyDeviceManager_get_device_matching (PyDeviceManager * self, PyObject * args)
{
  PyObject * predicate;
  gint timeout;
  GError * error = NULL;
  FridaDevice * result;

  if (!PyArg_ParseTuple (args, "Oi", &predicate, &timeout))
    return NULL;

  if (!PyCallable_Check (predicate))
    goto not_callable;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_manager_get_device_sync (PY_GOBJECT_HANDLE (self), (FridaDeviceManagerPredicate) PyDeviceManager_is_matching_device,
      predicate, timeout, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyDevice_new_take_handle (result);

not_callable:
  {
    PyErr_SetString (PyExc_TypeError, "object must be callable");
    return NULL;
  }
}

static gboolean
PyDeviceManager_is_matching_device (FridaDevice * device, PyObject * predicate)
{
  gboolean is_matching = FALSE;
  PyGILState_STATE gstate;
  PyObject * device_object, * result;

  gstate = PyGILState_Ensure ();

  device_object = PyDevice_new_take_handle (g_object_ref (device));

  result = PyObject_CallFunction (predicate, "O", device_object);
  if (result != NULL)
  {
    is_matching = result == Py_True;

    Py_DECREF (result);
  }
  else
  {
    PyErr_Print ();
  }

  Py_DECREF (device_object);

  PyGILState_Release (gstate);

  return is_matching;
}

static PyObject *
PyDeviceManager_enumerate_devices (PyDeviceManager * self)
{
  GError * error = NULL;
  FridaDeviceList * result;
  gint result_length, i;
  PyObject * devices;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_manager_enumerate_devices_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_device_list_size (result);
  devices = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (devices, i, PyDevice_new_take_handle (frida_device_list_get (result, i)));
  }
  frida_unref (result);

  return devices;
}

static PyObject *
PyDeviceManager_add_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "address", "certificate", "origin", "token", "keepalive_interval", NULL };
  char * address;
  char * certificate = NULL;
  char * origin = NULL;
  char * token = NULL;
  int keepalive_interval = -1;
  FridaRemoteDeviceOptions * options;
  GError * error = NULL;
  FridaDevice * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esesesi", keywords,
        "utf-8", &address,
        "utf-8", &certificate,
        "utf-8", &origin,
        "utf-8", &token,
        &keepalive_interval))
    return NULL;

  options = PyDeviceManager_parse_remote_device_options (certificate, origin, token, keepalive_interval);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_device_manager_add_remote_device_sync (PY_GOBJECT_HANDLE (self), address, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyDevice_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (token);
  PyMem_Free (origin);
  PyMem_Free (certificate);
  PyMem_Free (address);

  return result;
}

static PyObject *
PyDeviceManager_remove_remote_device (PyDeviceManager * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "address", NULL };
  char * address;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es", keywords, "utf-8", &address))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_manager_remove_remote_device_sync (PY_GOBJECT_HANDLE (self), address, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  PyMem_Free (address);

  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static FridaRemoteDeviceOptions *
PyDeviceManager_parse_remote_device_options (const gchar * certificate_value, const gchar * origin, const gchar * token,
    gint keepalive_interval)
{
  FridaRemoteDeviceOptions * options;

  options = frida_remote_device_options_new ();

  if (certificate_value != NULL)
  {
    GTlsCertificate * certificate;

    if (!PyGObject_unmarshal_certificate (certificate_value, &certificate))
      goto propagate_error;

    frida_remote_device_options_set_certificate (options, certificate);

    g_object_unref (certificate);
  }

  if (origin != NULL)
    frida_remote_device_options_set_origin (options, origin);

  if (token != NULL)
    frida_remote_device_options_set_token (options, token);

  if (keepalive_interval != -1)
    frida_remote_device_options_set_keepalive_interval (options, keepalive_interval);

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}


static PyObject *
PyDevice_new_take_handle (FridaDevice * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Device));
}

static int
PyDevice_init (PyDevice * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->id = NULL;
  self->name = NULL;
  self->icon = NULL;
  self->type = NULL;
  self->bus = NULL;

  return 0;
}

static void
PyDevice_init_from_handle (PyDevice * self, FridaDevice * handle)
{
  GVariant * icon;

  self->id = PyUnicode_FromUTF8String (frida_device_get_id (handle));
  self->name = PyUnicode_FromUTF8String (frida_device_get_name (handle));
  icon = frida_device_get_icon (handle);
  if (icon != NULL)
  {
    self->icon = PyGObject_marshal_variant (icon);
  }
  else
  {
    self->icon = Py_None;
    Py_IncRef (Py_None);
  }
  self->type = PyGObject_marshal_enum (frida_device_get_dtype (handle), FRIDA_TYPE_DEVICE_TYPE);
  self->bus = PyBus_new_take_handle (g_object_ref (frida_device_get_bus (handle)));
}

static void
PyDevice_dealloc (PyDevice * self)
{
  Py_XDECREF (self->bus);
  Py_XDECREF (self->type);
  Py_XDECREF (self->icon);
  Py_XDECREF (self->name);
  Py_XDECREF (self->id);

  PyGObject_tp_dealloc ((PyObject *) self);
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

  Py_DECREF (type_bytes);
  Py_DECREF (name_bytes);
  Py_DECREF (id_bytes);

  return result;
}

static PyObject *
PyDevice_is_lost (PyDevice * self)
{
  gboolean is_lost;

  Py_BEGIN_ALLOW_THREADS
  is_lost = frida_device_is_lost (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  return PyBool_FromLong (is_lost);
}

static PyObject *
PyDevice_query_system_parameters (PyDevice * self)
{
  GError * error = NULL;
  GHashTable * result;
  PyObject * parameters;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_query_system_parameters_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  parameters = PyGObject_marshal_parameters_dict (result);
  g_hash_table_unref (result);

  return parameters;
}

static PyObject *
PyDevice_get_frontmost_application (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "scope", NULL };
  const char * scope_value = NULL;
  FridaFrontmostQueryOptions * options;
  GError * error = NULL;
  FridaApplication * result;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|s", keywords, &scope_value))
    return NULL;

  options = frida_frontmost_query_options_new ();

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto invalid_argument;

    frida_frontmost_query_options_set_scope (options, scope);
  }

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_get_frontmost_application_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  if (result != NULL)
    return PyApplication_new_take_handle (result);
  else
    Py_RETURN_NONE;

invalid_argument:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enumerate_applications (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "identifiers", "scope", NULL };
  PyObject * identifiers = NULL;
  const char * scope = NULL;
  FridaApplicationQueryOptions * options;
  GError * error = NULL;
  FridaApplicationList * result;
  gint result_length, i;
  PyObject * applications;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|Os", keywords, &identifiers, &scope))
    return NULL;

  options = PyDevice_parse_application_query_options (identifiers, scope);
  if (options == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_applications_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_application_list_size (result);
  applications = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (applications, i, PyApplication_new_take_handle (frida_application_list_get (result, i)));
  }
  g_object_unref (result);

  return applications;
}

static FridaApplicationQueryOptions *
PyDevice_parse_application_query_options (PyObject * identifiers_value, const gchar * scope_value)
{
  FridaApplicationQueryOptions * options;

  options = frida_application_query_options_new ();

  if (identifiers_value != NULL)
  {
    gint n, i;

    n = PySequence_Size (identifiers_value);
    if (n == -1)
      goto propagate_error;

    for (i = 0; i != n; i++)
    {
      PyObject * element;
      gchar * identifier = NULL;

      element = PySequence_GetItem (identifiers_value, i);
      if (element == NULL)
        goto propagate_error;
      PyGObject_unmarshal_string (element, &identifier);
      Py_DECREF (element);
      if (identifier == NULL)
        goto propagate_error;

      frida_application_query_options_select_identifier (options, identifier);

      g_free (identifier);
    }
  }

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto propagate_error;

    frida_application_query_options_set_scope (options, scope);
  }

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enumerate_processes (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "pids", "scope", NULL };
  PyObject * pids = NULL;
  const char * scope = NULL;
  FridaProcessQueryOptions * options;
  GError * error = NULL;
  FridaProcessList * result;
  gint result_length, i;
  PyObject * processes;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|Os", keywords, &pids, &scope))
    return NULL;

  options = PyDevice_parse_process_query_options (pids, scope);
  if (options == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_processes_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_process_list_size (result);
  processes = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (processes, i, PyProcess_new_take_handle (frida_process_list_get (result, i)));
  }
  g_object_unref (result);

  return processes;
}

static FridaProcessQueryOptions *
PyDevice_parse_process_query_options (PyObject * pids_value, const gchar * scope_value)
{
  FridaProcessQueryOptions * options;

  options = frida_process_query_options_new ();

  if (pids_value != NULL)
  {
    gint n, i;

    n = PySequence_Size (pids_value);
    if (n == -1)
      goto propagate_error;

    for (i = 0; i != n; i++)
    {
      PyObject * element;
      long long pid;

      element = PySequence_GetItem (pids_value, i);
      if (element == NULL)
        goto propagate_error;
      pid = PyLong_AsLongLong (element);
      Py_DECREF (element);
      if (pid == -1)
        goto propagate_error;

      frida_process_query_options_select_pid (options, pid);
    }
  }

  if (scope_value != NULL)
  {
    FridaScope scope;

    if (!PyGObject_unmarshal_enum (scope_value, FRIDA_TYPE_SCOPE, &scope))
      goto propagate_error;

    frida_process_query_options_set_scope (options, scope);
  }

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PyDevice_enable_spawn_gating (PyDevice * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_device_enable_spawn_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
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
  frida_device_disable_spawn_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_enumerate_pending_spawn (PyDevice * self)
{
  GError * error = NULL;
  FridaSpawnList * result;
  gint result_length, i;
  PyObject * spawn;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_pending_spawn_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_spawn_list_size (result);
  spawn = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (spawn, i, PySpawn_new_take_handle (frida_spawn_list_get (result, i)));
  }
  g_object_unref (result);

  return spawn;
}

static PyObject *
PyDevice_enumerate_pending_children (PyDevice * self)
{
  GError * error = NULL;
  FridaChildList * result;
  gint result_length, i;
  PyObject * children;

  Py_BEGIN_ALLOW_THREADS
  result = frida_device_enumerate_pending_children_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  result_length = frida_child_list_size (result);
  children = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SetItem (children, i, PyChild_new_take_handle (frida_child_list_get (result, i)));
  }
  g_object_unref (result);

  return children;
}

static PyObject *
PyDevice_spawn (PyDevice * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "program", "argv", "envp", "env", "cwd", "stdio", "aux", NULL };
  const char * program;
  PyObject * argv_value = Py_None;
  PyObject * envp_value = Py_None;
  PyObject * env_value = Py_None;
  const char * cwd = NULL;
  const char * stdio_value = NULL;
  PyObject * aux_value = Py_None;
  FridaSpawnOptions * options;
  GError * error = NULL;
  guint pid;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "s|OOOzzO", keywords,
      &program,
      &argv_value,
      &envp_value,
      &env_value,
      &cwd,
      &stdio_value,
      &aux_value))
    return NULL;

  options = frida_spawn_options_new ();

  if (argv_value != Py_None)
  {
    gchar ** argv;
    gint argv_length;

    if (!PyGObject_unmarshal_strv (argv_value, &argv, &argv_length))
      goto invalid_argument;

    frida_spawn_options_set_argv (options, argv, argv_length);

    g_strfreev (argv);
  }

  if (envp_value != Py_None)
  {
    gchar ** envp;
    gint envp_length;

    if (!PyGObject_unmarshal_envp (envp_value, &envp, &envp_length))
      goto invalid_argument;

    frida_spawn_options_set_envp (options, envp, envp_length);

    g_strfreev (envp);
  }

  if (env_value != Py_None)
  {
    gchar ** env;
    gint env_length;

    if (!PyGObject_unmarshal_envp (env_value, &env, &env_length))
      goto invalid_argument;

    frida_spawn_options_set_env (options, env, env_length);

    g_strfreev (env);
  }

  if (cwd != NULL)
    frida_spawn_options_set_cwd (options, cwd);

  if (stdio_value != NULL)
  {
    FridaStdio stdio;

    if (!PyGObject_unmarshal_enum (stdio_value, FRIDA_TYPE_STDIO, &stdio))
      goto invalid_argument;

    frida_spawn_options_set_stdio (options, stdio);
  }

  if (aux_value != Py_None)
  {
    GHashTable * aux;
    Py_ssize_t pos;
    PyObject * key, * value;

    aux = frida_spawn_options_get_aux (options);

    if (!PyDict_Check (aux_value))
      goto invalid_aux_dict;

    pos = 0;
    while (PyDict_Next (aux_value, &pos, &key, &value))
    {
      gchar * raw_key;
      GVariant * raw_value;

      if (!PyGObject_unmarshal_string (key, &raw_key))
        goto invalid_dict_key;

      if (!PyGObject_unmarshal_variant (value, &raw_value))
      {
        g_free (raw_key);
        goto invalid_dict_value;
      }

      g_hash_table_insert (aux, raw_key, g_variant_ref_sink (raw_value));
    }
  }

  Py_BEGIN_ALLOW_THREADS
  pid = frida_device_spawn_sync (PY_GOBJECT_HANDLE (self), program, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (pid);

invalid_argument:
invalid_dict_key:
invalid_dict_value:
  {
    g_object_unref (options);

    return NULL;
  }
invalid_aux_dict:
  {
    g_object_unref (options);

    PyErr_SetString (PyExc_TypeError, "unsupported parameter");

    return NULL;
  }
}

static PyObject *
PyDevice_input (PyDevice * self, PyObject * args)
{
  long pid;
  gconstpointer data_buffer;
  Py_ssize_t data_size;
  GBytes * data;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "ly#", &pid, &data_buffer, &data_size))
    return NULL;

  data = g_bytes_new (data_buffer, data_size);

  Py_BEGIN_ALLOW_THREADS
  frida_device_input_sync (PY_GOBJECT_HANDLE (self), (guint) pid, data, g_cancellable_get_current (), &error);
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
  frida_device_resume_sync (PY_GOBJECT_HANDLE (self), (guint) pid, g_cancellable_get_current (), &error);
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
  frida_device_kill_sync (PY_GOBJECT_HANDLE (self), (guint) pid, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_attach (PyDevice * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "pid", "realm", "persist_timeout", NULL };
  long pid;
  char * realm_value = NULL;
  unsigned int persist_timeout = 0;
  FridaSessionOptions * options = NULL;
  GError * error = NULL;
  FridaSession * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "l|esI", keywords,
        &pid,
        "utf-8", &realm_value,
        &persist_timeout))
    return NULL;

  options = PyDevice_parse_session_options (realm_value, persist_timeout);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_device_attach_sync (PY_GOBJECT_HANDLE (self), (guint) pid, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PySession_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (realm_value);

  return result;
}

static FridaSessionOptions *
PyDevice_parse_session_options (const gchar * realm_value,
                                guint persist_timeout)
{
  FridaSessionOptions * options;

  options = frida_session_options_new ();

  if (realm_value != NULL)
  {
    FridaRealm realm;

    if (!PyGObject_unmarshal_enum (realm_value, FRIDA_TYPE_REALM, &realm))
      goto propagate_error;

    frida_session_options_set_realm (options, realm);
  }

  frida_session_options_set_persist_timeout (options, persist_timeout);

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
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
  id = frida_device_inject_library_file_sync (PY_GOBJECT_HANDLE (self), (guint) pid, path, entrypoint, data, g_cancellable_get_current (), &error);
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
  Py_ssize_t blob_size;
  const char * entrypoint, * data;
  GError * error = NULL;
  guint id;

  if (!PyArg_ParseTuple (args, "ly#ss", &pid, &blob_buffer, &blob_size, &entrypoint, &data))
    return NULL;

  blob = g_bytes_new (blob_buffer, blob_size);

  Py_BEGIN_ALLOW_THREADS
  id = frida_device_inject_library_blob_sync (PY_GOBJECT_HANDLE (self), (guint) pid, blob, entrypoint, data, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_bytes_unref (blob);

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromUnsignedLong (id);
}

static PyObject *
PyDevice_open_channel (PyDevice * self, PyObject * args)
{
  const char * address;
  GError * error = NULL;
  GIOStream * stream;

  if (!PyArg_ParseTuple (args, "s", &address))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  stream = frida_device_open_channel_sync (PY_GOBJECT_HANDLE (self), address, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  return PyIOStream_new_take_handle (stream);
}


static PyObject *
PyApplication_new_take_handle (FridaApplication * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Application));
}

static int
PyApplication_init (PyApplication * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->identifier = NULL;
  self->name = NULL;
  self->pid = 0;
  self->parameters = NULL;

  return 0;
}

static void
PyApplication_init_from_handle (PyApplication * self, FridaApplication * handle)
{
  self->identifier = PyUnicode_FromUTF8String (frida_application_get_identifier (handle));
  self->name = PyUnicode_FromUTF8String (frida_application_get_name (handle));
  self->pid = frida_application_get_pid (handle);
  self->parameters = PyApplication_marshal_parameters_dict (frida_application_get_parameters (handle));
}

static void
PyApplication_dealloc (PyApplication * self)
{
  Py_XDECREF (self->parameters);
  Py_XDECREF (self->name);
  Py_XDECREF (self->identifier);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyApplication_repr (PyApplication * self)
{
  PyObject * result;
  FridaApplication * handle;
  GString * repr;
  gchar * str;

  handle = PY_GOBJECT_HANDLE (self);

  repr = g_string_new ("Application(");

  g_string_append_printf (repr, "identifier=\"%s\", name=\"%s\"",
      frida_application_get_identifier (handle),
      frida_application_get_name (handle));

  if (self->pid != 0)
    g_string_append_printf (repr, ", pid=%u", self->pid);

  str = PyFrida_repr (self->parameters);
  g_string_append_printf (repr, ", parameters=%s", str);
  g_free (str);

  g_string_append (repr, ")");

  result = PyRepr_FromString (repr->str);

  g_string_free (repr, TRUE);

  return result;
}

static PyObject *
PyApplication_marshal_parameters_dict (GHashTable * dict)
{
  PyObject * result;
  GHashTableIter iter;
  const gchar * key;
  GVariant * raw_value;

  result = PyDict_New ();

  g_hash_table_iter_init (&iter, dict);

  while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &raw_value))
  {
    PyObject * value;

    if (strcmp (key, "started") == 0 && g_variant_is_of_type (raw_value, G_VARIANT_TYPE_STRING))
      value = PyGObject_marshal_datetime (g_variant_get_string (raw_value, NULL));
    else
      value = PyGObject_marshal_variant (raw_value);

    PyDict_SetItemString (result, key, value);

    Py_DECREF (value);
  }

  return result;
}


static PyObject *
PyProcess_new_take_handle (FridaProcess * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Process));
}

static int
PyProcess_init (PyProcess * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->name = NULL;
  self->parameters = NULL;

  return 0;
}

static void
PyProcess_init_from_handle (PyProcess * self, FridaProcess * handle)
{
  self->pid = frida_process_get_pid (handle);
  self->name = PyUnicode_FromUTF8String (frida_process_get_name (handle));
  self->parameters = PyProcess_marshal_parameters_dict (frida_process_get_parameters (handle));
}

static void
PyProcess_dealloc (PyProcess * self)
{
  Py_XDECREF (self->parameters);
  Py_XDECREF (self->name);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyProcess_repr (PyProcess * self)
{
  PyObject * result;
  FridaProcess * handle;
  GString * repr;
  gchar * str;

  handle = PY_GOBJECT_HANDLE (self);

  repr = g_string_new ("Process(");

  g_string_append_printf (repr, "pid=%u, name=\"%s\"",
      self->pid,
      frida_process_get_name (handle));

  str = PyFrida_repr (self->parameters);
  g_string_append_printf (repr, ", parameters=%s", str);
  g_free (str);

  g_string_append (repr, ")");

  result = PyRepr_FromString (repr->str);

  g_string_free (repr, TRUE);

  return result;
}

static PyObject *
PyProcess_marshal_parameters_dict (GHashTable * dict)
{
  PyObject * result;
  GHashTableIter iter;
  const gchar * key;
  GVariant * raw_value;

  result = PyDict_New ();

  g_hash_table_iter_init (&iter, dict);

  while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &raw_value))
  {
    PyObject * value;

    if (strcmp (key, "started") == 0 && g_variant_is_of_type (raw_value, G_VARIANT_TYPE_STRING))
      value = PyGObject_marshal_datetime (g_variant_get_string (raw_value, NULL));
    else
      value = PyGObject_marshal_variant (raw_value);

    PyDict_SetItemString (result, key, value);

    Py_DECREF (value);
  }

  return result;
}


static PyObject *
PySpawn_new_take_handle (FridaSpawn * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Spawn));
}

static int
PySpawn_init (PySpawn * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->identifier = NULL;

  return 0;
}

static void
PySpawn_init_from_handle (PySpawn * self, FridaSpawn * handle)
{
  self->pid = frida_spawn_get_pid (handle);
  self->identifier = PyGObject_marshal_string (frida_spawn_get_identifier (handle));
}

static void
PySpawn_dealloc (PySpawn * self)
{
  Py_XDECREF (self->identifier);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PySpawn_repr (PySpawn * self)
{
  PyObject * result;

  if (self->identifier != Py_None)
  {
    PyObject * identifier_bytes;

    identifier_bytes = PyUnicode_AsUTF8String (self->identifier);

    result = PyRepr_FromFormat ("Spawn(pid=%u, identifier=\"%s\")",
        self->pid,
        PyBytes_AsString (identifier_bytes));

    Py_DECREF (identifier_bytes);
  }
  else
  {
    result = PyRepr_FromFormat ("Spawn(pid=%u)",
        self->pid);
  }

  return result;
}


static PyObject *
PyChild_new_take_handle (FridaChild * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Child));
}

static int
PyChild_init (PyChild * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->parent_pid = 0;
  self->origin = NULL;
  self->identifier = NULL;
  self->path = NULL;
  self->argv = NULL;
  self->envp = NULL;

  return 0;
}

static void
PyChild_init_from_handle (PyChild * self, FridaChild * handle)
{
  gchar * const * argv, * const * envp;
  gint argv_length, envp_length;

  self->pid = frida_child_get_pid (handle);
  self->parent_pid = frida_child_get_parent_pid (handle);

  self->origin = PyGObject_marshal_enum (frida_child_get_origin (handle), FRIDA_TYPE_CHILD_ORIGIN);

  self->identifier = PyGObject_marshal_string (frida_child_get_identifier (handle));

  self->path = PyGObject_marshal_string (frida_child_get_path (handle));

  argv = frida_child_get_argv (handle, &argv_length);
  self->argv = PyGObject_marshal_strv (argv, argv_length);

  envp = frida_child_get_envp (handle, &envp_length);
  self->envp = PyGObject_marshal_envp (envp, envp_length);
}

static void
PyChild_dealloc (PyChild * self)
{
  Py_XDECREF (self->envp);
  Py_XDECREF (self->argv);
  Py_XDECREF (self->path);
  Py_XDECREF (self->identifier);
  Py_XDECREF (self->origin);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyChild_repr (PyChild * self)
{
  PyObject * result;
  FridaChild * handle;
  GString * repr;
  FridaChildOrigin origin;
  GEnumClass * origin_class;
  GEnumValue * origin_value;

  handle = PY_GOBJECT_HANDLE (self);

  repr = g_string_new ("Child(");

  g_string_append_printf (repr, "pid=%u, parent_pid=%u", self->pid, self->parent_pid);

  origin = frida_child_get_origin (handle);
  origin_class = g_type_class_ref (FRIDA_TYPE_CHILD_ORIGIN);
  origin_value = g_enum_get_value (origin_class, origin);
  g_string_append_printf (repr, ", origin=%s", origin_value->value_nick);
  g_type_class_unref (origin_class);

  if (self->identifier != Py_None)
  {
    gchar * identifier;

    identifier = PyFrida_repr (self->identifier);

    g_string_append_printf (repr, ", identifier=%s", identifier);

    g_free (identifier);
  }

  if (origin != FRIDA_CHILD_ORIGIN_FORK)
  {
    gchar * path, * argv, * envp;

    path = PyFrida_repr (self->path);
    argv = PyFrida_repr (self->argv);
    envp = PyFrida_repr (self->envp);

    g_string_append_printf (repr, ", path=%s, argv=%s, envp=%s", path, argv, envp);

    g_free (envp);
    g_free (argv);
    g_free (path);
  }

  g_string_append (repr, ")");

  result = PyRepr_FromString (repr->str);

  g_string_free (repr, TRUE);

  return result;
}


static int
PyCrash_init (PyCrash * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->pid = 0;
  self->process_name = NULL;
  self->summary = NULL;
  self->report = NULL;
  self->parameters = NULL;

  return 0;
}

static void
PyCrash_init_from_handle (PyCrash * self, FridaCrash * handle)
{
  self->pid = frida_crash_get_pid (handle);
  self->process_name = PyGObject_marshal_string (frida_crash_get_process_name (handle));
  self->summary = PyGObject_marshal_string (frida_crash_get_summary (handle));
  self->report = PyGObject_marshal_string (frida_crash_get_report (handle));
  self->parameters = PyGObject_marshal_parameters_dict (frida_crash_get_parameters (handle));
}

static void
PyCrash_dealloc (PyCrash * self)
{
  Py_XDECREF (self->parameters);
  Py_XDECREF (self->report);
  Py_XDECREF (self->summary);
  Py_XDECREF (self->process_name);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyCrash_repr (PyCrash * self)
{
  PyObject * result;
  FridaCrash * handle;
  GString * repr;
  gchar * str;

  handle = PY_GOBJECT_HANDLE (self);

  repr = g_string_new ("Crash(");

  g_string_append_printf (repr, "pid=%u, process_name=\"%s\", summary=\"%s\", report=<%u bytes>",
      self->pid,
      frida_crash_get_process_name (handle),
      frida_crash_get_summary (handle),
      (guint) strlen (frida_crash_get_report (handle)));

  str = PyFrida_repr (self->parameters);
  g_string_append_printf (repr, ", parameters=%s", str);
  g_free (str);

  g_string_append (repr, ")");

  result = PyRepr_FromString (repr->str);

  g_string_free (repr, TRUE);

  return result;
}


static PyObject *
PyBus_new_take_handle (FridaBus * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Bus));
}

static PyObject *
PyBus_attach (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_bus_attach_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyBus_post (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "message", "data", NULL };
  char * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|z#", keywords, "utf-8", &message, &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_bus_post (PY_GOBJECT_HANDLE (self), message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  Py_RETURN_NONE;
}


static PyObject *
PySession_new_take_handle (FridaSession * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Session));
}

static int
PySession_init (PySession * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
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
PySession_is_detached (PySession * self)
{
  gboolean is_detached;

  Py_BEGIN_ALLOW_THREADS
  is_detached = frida_session_is_detached (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  return PyBool_FromLong (is_detached);
}

static PyObject *
PySession_detach (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_detach_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PySession_resume (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_resume_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PySession_enable_child_gating (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_enable_child_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PySession_disable_child_gating (PySession * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_session_disable_child_gating_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PySession_create_script (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "source", "name", "snapshot", "runtime", NULL };
  char * source;
  char * name = NULL;
  gconstpointer snapshot_data = NULL;
  Py_ssize_t snapshot_size = 0;
  const char * runtime_value = NULL;
  FridaScriptOptions * options;
  GError * error = NULL;
  FridaScript * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esy#z", keywords, "utf-8", &source, "utf-8", &name, &snapshot_data, &snapshot_size, &runtime_value))
    return NULL;

  options = PySession_parse_script_options (name, snapshot_data, snapshot_size, runtime_value);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_session_create_script_sync (PY_GOBJECT_HANDLE (self), source, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyScript_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (name);
  PyMem_Free (source);

  return result;
}

static PyObject *
PySession_create_script_from_bytes (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "data", "name", "snapshot", "runtime", NULL };
  guint8 * data;
  Py_ssize_t size;
  char * name = NULL;
  gconstpointer snapshot_data = NULL;
  Py_ssize_t snapshot_size = 0;
  const char * runtime_value = NULL;
  GBytes * bytes;
  FridaScriptOptions * options;
  GError * error = NULL;
  FridaScript * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "y#|esy#z", keywords, &data, &size, "utf-8", &name, &snapshot_data, &snapshot_size, &runtime_value))
    return NULL;

  bytes = g_bytes_new (data, size);

  options = PySession_parse_script_options (name, snapshot_data, snapshot_size, runtime_value);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_session_create_script_from_bytes_sync (PY_GOBJECT_HANDLE (self), bytes, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyScript_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);
  g_bytes_unref (bytes);

  PyMem_Free (name);

  return result;
}

static PyObject *
PySession_compile_script (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "source", "name", "runtime", NULL };
  char * source;
  char * name = NULL;
  const char * runtime_value = NULL;
  FridaScriptOptions * options;
  GError * error = NULL;
  GBytes * bytes;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esz", keywords, "utf-8", &source, "utf-8", &name, &runtime_value))
    return NULL;

  options = PySession_parse_script_options (name, NULL, 0, runtime_value);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  bytes = frida_session_compile_script_sync (PY_GOBJECT_HANDLE (self), source, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error == NULL)
  {
    result = PyGObject_marshal_bytes_non_nullable (bytes);

    g_bytes_unref (bytes);
  }
  else
  {
    result = PyFrida_raise (error);
  }

beach:
  g_clear_object (&options);

  PyMem_Free (name);
  PyMem_Free (source);

  return result;
}

static FridaScriptOptions *
PySession_parse_script_options (const gchar * name, gconstpointer snapshot_data, gsize snapshot_size, const gchar * runtime_value)
{
  FridaScriptOptions * options;

  options = frida_script_options_new ();

  if (name != NULL)
    frida_script_options_set_name (options, name);

  if (snapshot_data != NULL)
  {
    GBytes * snapshot = g_bytes_new (snapshot_data, snapshot_size);
    frida_script_options_set_snapshot (options, snapshot);
    g_bytes_unref (snapshot);
  }

  if (runtime_value != NULL)
  {
    FridaScriptRuntime runtime;

    if (!PyGObject_unmarshal_enum (runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME, &runtime))
      goto invalid_argument;

    frida_script_options_set_runtime (options, runtime);
  }

  return options;

invalid_argument:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PySession_snapshot_script (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "embed_script", "warmup_script", "runtime", NULL };
  char * embed_script;
  char * warmup_script = NULL;
  const char * runtime_value = NULL;
  FridaSnapshotOptions * options;
  GError * error = NULL;
  GBytes * bytes;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esz", keywords, "utf-8", &embed_script, "utf-8", &warmup_script, &runtime_value))
    return NULL;

  options = PySession_parse_snapshot_options (warmup_script, runtime_value);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  bytes = frida_session_snapshot_script_sync (PY_GOBJECT_HANDLE (self), embed_script, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error == NULL)
  {
    result = PyGObject_marshal_bytes_non_nullable (bytes);

    g_bytes_unref (bytes);
  }
  else
  {
    result = PyFrida_raise (error);
  }

beach:
  g_clear_object (&options);

  PyMem_Free (warmup_script);
  PyMem_Free (embed_script);

  return result;
}

static FridaSnapshotOptions *
PySession_parse_snapshot_options (const gchar * warmup_script, const gchar * runtime_value)
{
  FridaSnapshotOptions * options;

  options = frida_snapshot_options_new ();

  if (warmup_script != NULL)
    frida_snapshot_options_set_warmup_script (options, warmup_script);

  if (runtime_value != NULL)
  {
    FridaScriptRuntime runtime;

    if (!PyGObject_unmarshal_enum (runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME, &runtime))
      goto invalid_argument;

    frida_snapshot_options_set_runtime (options, runtime);
  }

  return options;

invalid_argument:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PySession_setup_peer_connection (PySession * self, PyObject * args, PyObject * kw)
{
  gboolean success = FALSE;
  static char * keywords[] = { "stun_server", "relays", NULL };
  char * stun_server = NULL;
  PyObject * relays = NULL;
  FridaPeerOptions * options = NULL;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|esO", keywords,
        "utf-8", &stun_server,
        &relays))
    return NULL;

  options = PySession_parse_peer_options (stun_server, relays);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  frida_session_setup_peer_connection_sync (PY_GOBJECT_HANDLE (self), options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error != NULL)
    goto propagate_error;

  success = TRUE;
  goto beach;

propagate_error:
  {
    PyFrida_raise (error);
    goto beach;
  }
beach:
  {
    g_clear_object (&options);

    PyMem_Free (stun_server);

    if (!success)
      return NULL;

    Py_RETURN_NONE;
  }
}

static FridaPeerOptions *
PySession_parse_peer_options (const gchar * stun_server, PyObject * relays)
{
  FridaPeerOptions * options;
  PyObject * relay;

  options = frida_peer_options_new ();

  frida_peer_options_set_stun_server (options, stun_server);

  if (relays != NULL)
  {
    Py_ssize_t n, i;

    n = PySequence_Length (relays);
    if (n == -1)
      goto propagate_error;

    for (i = 0; i != n; i++)
    {
      relay = PySequence_GetItem (relays, i);
      if (relay == NULL)
        goto propagate_error;

      if (!PyObject_IsInstance (relay, PYFRIDA_TYPE_OBJECT (Relay)))
        goto expected_relay;

      frida_peer_options_add_relay (options, PY_GOBJECT_HANDLE (relay));

      Py_DECREF (relay);
    }
  }

  return options;

expected_relay:
  {
    Py_DECREF (relay);

    PyErr_SetString (PyExc_TypeError, "expected sequence of Relay objects");
    goto propagate_error;
  }
propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}

static PyObject *
PySession_join_portal (PySession * self, PyObject * args, PyObject * kw)
{
  PyObject * result = NULL;
  static char * keywords[] = { "address", "certificate", "token", "acl", NULL };
  char * address;
  char * certificate = NULL;
  char * token = NULL;
  PyObject * acl = NULL;
  FridaPortalOptions * options;
  GError * error = NULL;
  FridaPortalMembership * handle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|esesO", keywords,
        "utf-8", &address,
        "utf-8", &certificate,
        "utf-8", &token,
        &acl))
    return NULL;

  options = PySession_parse_portal_options (certificate, token, acl);
  if (options == NULL)
    goto beach;

  Py_BEGIN_ALLOW_THREADS
  handle = frida_session_join_portal_sync (PY_GOBJECT_HANDLE (self), address, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  result = (error == NULL)
      ? PyPortalMembership_new_take_handle (handle)
      : PyFrida_raise (error);

beach:
  g_clear_object (&options);

  PyMem_Free (token);
  PyMem_Free (certificate);
  PyMem_Free (address);

  return result;
}

static FridaPortalOptions *
PySession_parse_portal_options (const gchar * certificate_value, const gchar * token, PyObject * acl_value)
{
  FridaPortalOptions * options;

  options = frida_portal_options_new ();

  if (certificate_value != NULL)
  {
    GTlsCertificate * certificate;

    if (!PyGObject_unmarshal_certificate (certificate_value, &certificate))
      goto propagate_error;

    frida_portal_options_set_certificate (options, certificate);

    g_object_unref (certificate);
  }

  if (token != NULL)
    frida_portal_options_set_token (options, token);

  if (acl_value != NULL)
  {
    gchar ** acl;
    gint acl_length;

    if (!PyGObject_unmarshal_strv (acl_value, &acl, &acl_length))
      goto propagate_error;

    frida_portal_options_set_acl (options, acl, acl_length);

    g_strfreev (acl);
  }

  return options;

propagate_error:
  {
    g_object_unref (options);

    return NULL;
  }
}


static PyObject *
PyScript_new_take_handle (FridaScript * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (Script));
}

static PyObject *
PyScript_is_destroyed (PyScript * self)
{
  gboolean is_destroyed;

  Py_BEGIN_ALLOW_THREADS
  is_destroyed = frida_script_is_destroyed (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

  return PyBool_FromLong (is_destroyed);
}

static PyObject *
PyScript_load (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_load_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
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
  frida_script_unload_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyScript_eternalize (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_eternalize_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
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
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|z#", keywords, "utf-8", &message, &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_post (PY_GOBJECT_HANDLE (self), message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  Py_RETURN_NONE;
}

static PyObject *
PyScript_enable_debugger (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "port", NULL };
  unsigned short int port = 0;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|H", keywords, &port))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_enable_debugger_sync (PY_GOBJECT_HANDLE (self), port, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyScript_disable_debugger (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_script_disable_debugger_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}


static int
PyRelay_init (PyRelay * self, PyObject * args, PyObject * kw)
{
  int result = -1;
  static char * keywords[] = { "address", "username", "password", "kind", NULL };
  char * address = NULL;
  char * username = NULL;
  char * password = NULL;
  char * kind_value = NULL;
  FridaRelayKind kind;
  FridaRelay * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "eseseses", keywords,
        "utf-8", &address,
        "utf-8", &username,
        "utf-8", &password,
        "utf-8", &kind_value))
    return -1;

  if (!PyGObject_unmarshal_enum (kind_value, FRIDA_TYPE_RELAY_KIND, &kind))
    goto beach;

  handle = frida_relay_new (address, username, password, kind);

  PyGObject_take_handle (&self->parent, handle, PYFRIDA_TYPE (Relay));

  PyRelay_init_from_handle (self, handle);

  result = 0;

beach:
  PyMem_Free (kind_value);
  PyMem_Free (password);
  PyMem_Free (username);
  PyMem_Free (address);

  return result;
}

static void
PyRelay_init_from_handle (PyRelay * self, FridaRelay * handle)
{
  self->address = PyUnicode_FromUTF8String (frida_relay_get_address (handle));
  self->username = PyUnicode_FromUTF8String (frida_relay_get_username (handle));
  self->password = PyUnicode_FromUTF8String (frida_relay_get_password (handle));
  self->kind = PyGObject_marshal_enum (frida_relay_get_kind (handle), FRIDA_TYPE_RELAY_KIND);
}

static void
PyRelay_dealloc (PyRelay * self)
{
  Py_XDECREF (self->kind);
  Py_XDECREF (self->password);
  Py_XDECREF (self->username);
  Py_XDECREF (self->address);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyRelay_repr (PyRelay * self)
{
  PyObject * result, * address_bytes, * username_bytes, * password_bytes, * kind_bytes;

  address_bytes = PyUnicode_AsUTF8String (self->address);
  username_bytes = PyUnicode_AsUTF8String (self->username);
  password_bytes = PyUnicode_AsUTF8String (self->password);
  kind_bytes = PyUnicode_AsUTF8String (self->kind);

  result = PyRepr_FromFormat ("Relay(address=\"%s\", username=\"%s\", password=\"%s\", kind='%s')",
      PyBytes_AsString (address_bytes),
      PyBytes_AsString (username_bytes),
      PyBytes_AsString (password_bytes),
      PyBytes_AsString (kind_bytes));

  Py_DECREF (kind_bytes);
  Py_DECREF (password_bytes);
  Py_DECREF (username_bytes);
  Py_DECREF (address_bytes);

  return result;
}


static PyObject *
PyPortalMembership_new_take_handle (FridaPortalMembership * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (PortalMembership));
}

static PyObject *
PyPortalMembership_terminate (PyPortalMembership * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_membership_terminate_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}


static int
PyPortalService_init (PyPortalService * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "cluster_params", "control_params", NULL };
  PyEndpointParameters * cluster_params;
  PyEndpointParameters * control_params = NULL;
  FridaPortalService * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "O!|O!", keywords,
        PYFRIDA_TYPE_OBJECT (EndpointParameters), &cluster_params,
        PYFRIDA_TYPE_OBJECT (EndpointParameters), &control_params))
    return -1;

  g_atomic_int_inc (&toplevel_objects_alive);

  handle = frida_portal_service_new (PY_GOBJECT_HANDLE (cluster_params),
      (control_params != NULL) ? PY_GOBJECT_HANDLE (control_params) : NULL);

  PyGObject_take_handle (&self->parent, handle, PYFRIDA_TYPE (PortalService));

  PyPortalService_init_from_handle (self, handle);

  return 0;
}

static void
PyPortalService_init_from_handle (PyPortalService * self, FridaPortalService * handle)
{
  self->device = PyDevice_new_take_handle (g_object_ref (frida_portal_service_get_device (handle)));
}

static void
PyPortalService_dealloc (PyPortalService * self)
{
  FridaPortalService * handle;

  g_atomic_int_dec_and_test (&toplevel_objects_alive);

  handle = PyGObject_steal_handle (&self->parent);
  if (handle != NULL)
  {
    Py_BEGIN_ALLOW_THREADS
    frida_portal_service_stop_sync (handle, NULL, NULL);
    frida_unref (handle);
    Py_END_ALLOW_THREADS
  }

  Py_XDECREF (self->device);

  PyGObject_tp_dealloc ((PyObject *) self);
}

static PyObject *
PyPortalService_start (PyPortalService * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_start_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyPortalService_stop (PyPortalService * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_stop_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyPortalService_kick (PyScript * self, PyObject * args)
{
  unsigned int connection_id;

  if (!PyArg_ParseTuple (args, "I", &connection_id))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_kick (PY_GOBJECT_HANDLE (self), connection_id);
  Py_END_ALLOW_THREADS

  Py_RETURN_NONE;
}

static PyObject *
PyPortalService_post (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "connection_id", "message", "data", NULL };
  unsigned int connection_id;
  char * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "Ies|z#", keywords,
        &connection_id,
        "utf-8", &message,
        &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_post (PY_GOBJECT_HANDLE (self), connection_id, message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  Py_RETURN_NONE;
}

static PyObject *
PyPortalService_narrowcast (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "tag", "message", "data", NULL };
  char * tag, * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "eses|z#", keywords,
        "utf-8", &tag,
        "utf-8", &message,
        &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_narrowcast (PY_GOBJECT_HANDLE (self), tag, message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);
  PyMem_Free (tag);

  Py_RETURN_NONE;
}

static PyObject *
PyPortalService_broadcast (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "message", "data", NULL };
  char * message;
  gconstpointer data_buffer = NULL;
  Py_ssize_t data_size = 0;
  GBytes * data;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "es|z#", keywords,
        "utf-8", &message,
        &data_buffer, &data_size))
    return NULL;

  data = (data_buffer != NULL) ? g_bytes_new (data_buffer, data_size) : NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_broadcast (PY_GOBJECT_HANDLE (self), message, data);
  Py_END_ALLOW_THREADS

  g_bytes_unref (data);
  PyMem_Free (message);

  Py_RETURN_NONE;
}

static PyObject *
PyPortalService_enumerate_tags (PyScript * self, PyObject * args)
{
  PyObject * result;
  unsigned int connection_id;
  gchar ** tags;
  gint tags_length;

  if (!PyArg_ParseTuple (args, "I", &connection_id))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  tags = frida_portal_service_enumerate_tags (PY_GOBJECT_HANDLE (self), connection_id, &tags_length);
  Py_END_ALLOW_THREADS

  result = PyGObject_marshal_strv (tags, tags_length);
  g_strfreev (tags);

  return result;
}

static PyObject *
PyPortalService_tag (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "connection_id", "tag", NULL };
  unsigned int connection_id;
  char * tag;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "Ies", keywords,
        &connection_id,
        "utf-8", &tag))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_tag (PY_GOBJECT_HANDLE (self), connection_id, tag);
  Py_END_ALLOW_THREADS

  PyMem_Free (tag);

  Py_RETURN_NONE;
}

static PyObject *
PyPortalService_untag (PyScript * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "connection_id", "tag", NULL };
  unsigned int connection_id;
  char * tag;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "Ies", keywords,
        &connection_id,
        "utf-8", &tag))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_portal_service_untag (PY_GOBJECT_HANDLE (self), connection_id, tag);
  Py_END_ALLOW_THREADS

  PyMem_Free (tag);

  Py_RETURN_NONE;
}


static int
PyEndpointParameters_init (PyEndpointParameters * self, PyObject * args, PyObject * kw)
{
  int result = -1;
  static char * keywords[] = { "address", "port", "certificate", "origin", "auth_token", "auth_callback", "asset_root", NULL };
  char * address = NULL;
  unsigned short int port = 0;
  char * certificate_value = NULL;
  char * origin = NULL;
  char * auth_token = NULL;
  PyObject * auth_callback = NULL;
  char * asset_root_value = NULL;
  GTlsCertificate * certificate = NULL;
  FridaAuthenticationService * auth_service = NULL;
  GFile * asset_root = NULL;
  FridaEndpointParameters * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|esHesesesOes", keywords,
        "utf-8", &address,
        &port,
        "utf-8", &certificate_value,
        "utf-8", &origin,
        "utf-8", &auth_token,
        &auth_callback,
        "utf-8", &asset_root_value))
    return -1;

  if (certificate_value != NULL && !PyGObject_unmarshal_certificate (certificate_value, &certificate))
    goto beach;

  if (auth_token != NULL)
    auth_service = FRIDA_AUTHENTICATION_SERVICE (frida_static_authentication_service_new (auth_token));
  else if (auth_callback != NULL)
    auth_service = FRIDA_AUTHENTICATION_SERVICE (frida_python_authentication_service_new (auth_callback));

  if (asset_root_value != NULL)
    asset_root = g_file_new_for_path (asset_root_value);

  handle = frida_endpoint_parameters_new (address, port, certificate, origin, auth_service, asset_root);

  PyGObject_take_handle (&self->parent, handle, PYFRIDA_TYPE (EndpointParameters));

  result = 0;

beach:
  g_clear_object (&asset_root);
  g_clear_object (&auth_service);
  g_clear_object (&certificate);

  PyMem_Free (asset_root_value);
  PyMem_Free (auth_token);
  PyMem_Free (origin);
  PyMem_Free (certificate_value);
  PyMem_Free (address);

  return result;
}


G_DEFINE_TYPE_EXTENDED (FridaPythonAuthenticationService, frida_python_authentication_service, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE (FRIDA_TYPE_AUTHENTICATION_SERVICE, frida_python_authentication_service_iface_init))

static FridaPythonAuthenticationService *
frida_python_authentication_service_new (PyObject * callback)
{
  FridaPythonAuthenticationService * service;

  service = g_object_new (FRIDA_TYPE_PYTHON_AUTHENTICATION_SERVICE, NULL);
  service->callback = callback;
  Py_IncRef (callback);

  return service;
}

static void
frida_python_authentication_service_class_init (FridaPythonAuthenticationServiceClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = frida_python_authentication_service_dispose;
}

static void
frida_python_authentication_service_iface_init (gpointer g_iface, gpointer iface_data)
{
  FridaAuthenticationServiceIface * iface = g_iface;

  iface->authenticate = frida_python_authentication_service_authenticate;
  iface->authenticate_finish = frida_python_authentication_service_authenticate_finish;
}

static void
frida_python_authentication_service_init (FridaPythonAuthenticationService * self)
{
  self->pool = g_thread_pool_new ((GFunc) frida_python_authentication_service_do_authenticate, self, 1, FALSE, NULL);
}

static void
frida_python_authentication_service_dispose (GObject * object)
{
  FridaPythonAuthenticationService * self = FRIDA_PYTHON_AUTHENTICATION_SERVICE (object);

  if (self->pool != NULL)
  {
    g_thread_pool_free (self->pool, FALSE, FALSE);
    self->pool = NULL;
  }

  if (self->callback != NULL)
  {
    PyGILState_STATE gstate;

    gstate = PyGILState_Ensure ();

    Py_DECREF (self->callback);
    self->callback = NULL;

    PyGILState_Release (gstate);
  }

  G_OBJECT_CLASS (frida_python_authentication_service_parent_class)->dispose (object);
}

static void
frida_python_authentication_service_authenticate (FridaAuthenticationService * service, const gchar * token, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data)
{
  FridaPythonAuthenticationService * self;
  GTask * task;

  self = FRIDA_PYTHON_AUTHENTICATION_SERVICE (service);

  task = g_task_new (self, cancellable, callback, user_data);
  g_task_set_task_data (task, g_strdup (token), g_free);

  g_thread_pool_push (self->pool, task, NULL);
}

static gchar *
frida_python_authentication_service_authenticate_finish (FridaAuthenticationService * service, GAsyncResult * result, GError ** error)
{
  return g_task_propagate_pointer (G_TASK (result), error);
}

static void
frida_python_authentication_service_do_authenticate (GTask * task, FridaPythonAuthenticationService * self)
{
  const gchar * token;
  PyGILState_STATE gstate;
  PyObject * result;
  gchar * session_info = NULL;
  gchar * message = NULL;

  token = g_task_get_task_data (task);

  gstate = PyGILState_Ensure ();

  result = PyObject_CallFunction (self->callback, "s", token);
  if (result == NULL || !PyGObject_unmarshal_string (result, &session_info))
  {
    PyObject * type, * value, * traceback;

    PyErr_Fetch (&type, &value, &traceback);

    if (value != NULL)
    {
      PyObject * message_value = PyObject_Str (value);
      PyGObject_unmarshal_string (message_value, &message);
      Py_DECREF (message_value);
    }
    else
    {
      message = g_strdup ("Internal error");
    }

    Py_DECREF (type);
    Py_XDECREF (value);
    Py_XDECREF (traceback);
  }

  Py_XDECREF (result);

  PyGILState_Release (gstate);

  if (session_info != NULL)
    g_task_return_pointer (task, session_info, g_free);
  else
    g_task_return_new_error (task, FRIDA_ERROR, FRIDA_ERROR_INVALID_ARGUMENT, "%s", message);

  g_free (message);
  g_object_unref (task);
}


static int
PyCompiler_init (PyCompiler * self, PyObject * args, PyObject * kw)
{
  PyDeviceManager * manager;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTuple (args, "O!", PYFRIDA_TYPE_OBJECT (DeviceManager), &manager))
    return -1;

  PyGObject_take_handle (&self->parent, frida_compiler_new (PY_GOBJECT_HANDLE (manager)), PYFRIDA_TYPE (Compiler));

  return 0;
}

static PyObject *
PyCompiler_build (PyCompiler * self, PyObject * args, PyObject * kw)
{
  PyObject * result;
  static char * keywords[] = { "entrypoint", "project_root", "source_maps", "compression", NULL };
  const char * entrypoint;
  const char * project_root = NULL;
  const char * source_maps = NULL;
  const char * compression = NULL;
  FridaBuildOptions * options;
  GError * error = NULL;
  gchar * bundle;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "s|sss", keywords, &entrypoint, &project_root, &source_maps, &compression))
    return NULL;

  options = frida_build_options_new ();
  if (!PyCompiler_set_options (FRIDA_COMPILER_OPTIONS (options), project_root, source_maps, compression))
    goto invalid_option_value;

  Py_BEGIN_ALLOW_THREADS
  bundle = frida_compiler_build_sync (PY_GOBJECT_HANDLE (self), entrypoint, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  result = PyUnicode_FromUTF8String (bundle);
  g_free (bundle);

  return result;

invalid_option_value:
  {
    g_object_unref (options);
    return NULL;
  }
}

static PyObject *
PyCompiler_watch (PyCompiler * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "entrypoint", "project_root", "source_maps", "compression", NULL };
  const char * entrypoint;
  const char * project_root = NULL;
  const char * source_maps = NULL;
  const char * compression = NULL;
  FridaWatchOptions * options;
  GError * error = NULL;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "s|sss", keywords, &entrypoint, &project_root, &source_maps, &compression))
    return NULL;

  options = frida_watch_options_new ();
  if (!PyCompiler_set_options (FRIDA_COMPILER_OPTIONS (options), project_root, source_maps, compression))
    goto invalid_option_value;

  Py_BEGIN_ALLOW_THREADS
  frida_compiler_watch_sync (PY_GOBJECT_HANDLE (self), entrypoint, options, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  g_object_unref (options);

  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;

invalid_option_value:
  {
    g_object_unref (options);
    return NULL;
  }
}

static gboolean
PyCompiler_set_options (FridaCompilerOptions * options, const gchar * project_root_value, const gchar * source_maps_value,
    const gchar * compression_value)
{
  if (project_root_value != NULL)
    frida_compiler_options_set_project_root (options, project_root_value);

  if (source_maps_value != NULL)
  {
    FridaSourceMaps source_maps;

    if (!PyGObject_unmarshal_enum (source_maps_value, FRIDA_TYPE_SOURCE_MAPS, &source_maps))
      return FALSE;

    frida_compiler_options_set_source_maps (options, source_maps);
  }

  if (compression_value != NULL)
  {
    FridaJsCompression compression;

    if (!PyGObject_unmarshal_enum (compression_value, FRIDA_TYPE_JS_COMPRESSION, &compression))
      return FALSE;

    frida_compiler_options_set_compression (options, compression);
  }

  return TRUE;
}


static int
PyFileMonitor_init (PyFileMonitor * self, PyObject * args, PyObject * kw)
{
  const char * path;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTuple (args, "s", &path))
    return -1;

  PyGObject_take_handle (&self->parent, frida_file_monitor_new (path), PYFRIDA_TYPE (FileMonitor));

  return 0;
}

static PyObject *
PyFileMonitor_enable (PyFileMonitor * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  frida_file_monitor_enable_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
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
  frida_file_monitor_disable_sync (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}


static PyObject *
PyIOStream_new_take_handle (GIOStream * handle)
{
  return PyGObject_new_take_handle (handle, PYFRIDA_TYPE (IOStream));
}

static int
PyIOStream_init (PyIOStream * self, PyObject * args, PyObject * kw)
{
  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  self->input = NULL;
  self->output = NULL;

  return 0;
}

static void
PyIOStream_init_from_handle (PyIOStream * self, GIOStream * handle)
{
  self->input = g_io_stream_get_input_stream (handle);
  self->output = g_io_stream_get_output_stream (handle);
}

static PyObject *
PyIOStream_repr (PyIOStream * self)
{
  GIOStream * handle = PY_GOBJECT_HANDLE (self);

  return PyRepr_FromFormat ("IOStream(handle=%p, is_closed=%s)",
      handle,
      g_io_stream_is_closed (handle) ? "TRUE" : "FALSE");
}

static PyObject *
PyIOStream_is_closed (PyIOStream * self)
{
  return PyBool_FromLong (g_io_stream_is_closed (PY_GOBJECT_HANDLE (self)));
}

static PyObject *
PyIOStream_close (PyIOStream * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  g_io_stream_close (PY_GOBJECT_HANDLE (self), g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyIOStream_read (PyIOStream * self, PyObject * args)
{
  PyObject * result;
  unsigned long count;
  PyObject * buffer;
  GError * error = NULL;
  gssize bytes_read;

  if (!PyArg_ParseTuple (args, "k", &count))
    return NULL;

  buffer = PyBytes_FromStringAndSize (NULL, count);
  if (buffer == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  bytes_read = g_input_stream_read (self->input, PyBytes_AsString (buffer), count, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error == NULL)
  {
    if ((unsigned long) bytes_read == count)
    {
      result = buffer;
    }
    else
    {
      result = PyBytes_FromStringAndSize (PyBytes_AsString (buffer), bytes_read);

      Py_DECREF (buffer);
    }
  }
  else
  {
    result = PyFrida_raise (error);

    Py_DECREF (buffer);
  }

  return result;
}

static PyObject *
PyIOStream_read_all (PyIOStream * self, PyObject * args)
{
  PyObject * result;
  unsigned long count;
  PyObject * buffer;
  gsize bytes_read;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "k", &count))
    return NULL;

  buffer = PyBytes_FromStringAndSize (NULL, count);
  if (buffer == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  g_input_stream_read_all (self->input, PyBytes_AsString (buffer), count, &bytes_read, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error == NULL)
  {
    result = buffer;
  }
  else
  {
    result = PyFrida_raise (error);

    Py_DECREF (buffer);
  }

  return result;
}

static PyObject *
PyIOStream_write (PyIOStream * self, PyObject * args)
{
  const char * data;
  Py_ssize_t size;
  GError * error = NULL;
  gssize bytes_written;

  if (!PyArg_ParseTuple (args, "y#", &data, &size))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  bytes_written = g_output_stream_write (self->output, data, size, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error != NULL)
    return PyFrida_raise (error);

  return PyLong_FromSsize_t (bytes_written);
}

static PyObject *
PyIOStream_write_all (PyIOStream * self, PyObject * args)
{
  const char * data;
  Py_ssize_t size;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "y#", &data, &size))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  g_output_stream_write_all (self->output, data, size, NULL, g_cancellable_get_current (), &error);
  Py_END_ALLOW_THREADS

  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}


static PyObject *
PyCancellable_new_take_handle (GCancellable * handle)
{
  PyObject * object;

  object = (handle != NULL) ? PyGObject_try_get_from_handle (handle) : NULL;
  if (object == NULL)
  {
    object = PyObject_CallFunction (PYFRIDA_TYPE_OBJECT (Cancellable), "z#", (char *) &handle, (Py_ssize_t) sizeof (handle));
  }
  else
  {
    g_object_unref (handle);
    Py_INCREF (object);
  }

  return object;
}

static int
PyCancellable_init (PyCancellable * self, PyObject * args, PyObject * kw)
{
  static char * keywords[] = { "handle", NULL };
  GCancellable ** handle_buffer = NULL;
  Py_ssize_t handle_size = 0;
  GCancellable * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|z#", keywords, &handle_buffer, &handle_size))
    return -1;

  if (handle_size == sizeof (gpointer))
    handle = *handle_buffer;
  else
    handle = g_cancellable_new ();

  PyGObject_take_handle (&self->parent, handle, PYFRIDA_TYPE (Cancellable));

  return 0;
}

static PyObject *
PyCancellable_repr (PyCancellable * self)
{
  GCancellable * handle = PY_GOBJECT_HANDLE (self);

  return PyRepr_FromFormat ("Cancellable(handle=%p, is_cancelled=%s)",
      handle,
      g_cancellable_is_cancelled (handle) ? "TRUE" : "FALSE");
}

static PyObject *
PyCancellable_is_cancelled (PyCancellable * self)
{
  return PyBool_FromLong (g_cancellable_is_cancelled (PY_GOBJECT_HANDLE (self)));
}

static PyObject *
PyCancellable_raise_if_cancelled (PyCancellable * self)
{
  GError * error = NULL;

  g_cancellable_set_error_if_cancelled (PY_GOBJECT_HANDLE (self), &error);
  if (error != NULL)
    return PyFrida_raise (error);

  Py_RETURN_NONE;
}

static PyObject *
PyCancellable_get_fd (PyCancellable * self)
{
  return PyLong_FromLong (g_cancellable_get_fd (PY_GOBJECT_HANDLE (self)));
}

static PyObject *
PyCancellable_release_fd (PyCancellable * self)
{
  g_cancellable_release_fd (PY_GOBJECT_HANDLE (self));

  Py_RETURN_NONE;
}

static PyObject *
PyCancellable_get_current (PyCancellable * self)
{
  GCancellable * handle;

  handle = g_cancellable_get_current ();

  if (handle != NULL)
    g_object_ref (handle);

  return PyCancellable_new_take_handle (handle);
}

static PyObject *
PyCancellable_push_current (PyCancellable * self)
{
  g_cancellable_push_current (PY_GOBJECT_HANDLE (self));

  Py_RETURN_NONE;
}

static PyObject *
PyCancellable_pop_current (PyCancellable * self)
{
  GCancellable * handle = PY_GOBJECT_HANDLE (self);

  if (g_cancellable_get_current () != handle)
    goto invalid_operation;

  g_cancellable_pop_current (handle);

  Py_RETURN_NONE;

invalid_operation:
  {
    return PyFrida_raise (g_error_new (
          FRIDA_ERROR,
          FRIDA_ERROR_INVALID_OPERATION,
          "Cancellable is not on top of the stack"));
  }
}

static PyObject *
PyCancellable_connect (PyCancellable * self, PyObject * args)
{
  GCancellable * handle = PY_GOBJECT_HANDLE (self);
  gulong handler_id;
  PyObject * callback;

  if (!PyArg_ParseTuple (args, "O", &callback))
    return NULL;

  if (!PyCallable_Check (callback))
    goto not_callable;

  if (handle != NULL)
  {
    Py_IncRef (callback);

    Py_BEGIN_ALLOW_THREADS
    handler_id = g_cancellable_connect (handle, G_CALLBACK (PyCancellable_on_cancelled), callback,
        (GDestroyNotify) PyCancellable_destroy_callback);
    Py_END_ALLOW_THREADS
  }
  else
  {
    handler_id = 0;
  }

  return PyLong_FromUnsignedLong (handler_id);

not_callable:
  {
    PyErr_SetString (PyExc_TypeError, "object must be callable");
    return NULL;
  }
}

static PyObject *
PyCancellable_disconnect (PyCancellable * self, PyObject * args)
{
  gulong handler_id;

  if (!PyArg_ParseTuple (args, "k", &handler_id))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  g_cancellable_disconnect (PY_GOBJECT_HANDLE (self), handler_id);
  Py_END_ALLOW_THREADS

  Py_RETURN_NONE;
}

static void
PyCancellable_on_cancelled (GCancellable * cancellable, PyObject * callback)
{
  PyGILState_STATE gstate;
  PyObject * result;

  gstate = PyGILState_Ensure ();

  result = PyObject_CallObject (callback, NULL);
  if (result != NULL)
    Py_DECREF (result);
  else
    PyErr_Print ();

  PyGILState_Release (gstate);
}

static void
PyCancellable_destroy_callback (PyObject * callback)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();
  Py_DecRef (callback);
  PyGILState_Release (gstate);
}

static PyObject *
PyCancellable_cancel (PyCancellable * self)
{
  Py_BEGIN_ALLOW_THREADS
  g_cancellable_cancel (PY_GOBJECT_HANDLE (self));
  Py_END_ALLOW_THREADS

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

  if (error->domain == FRIDA_ERROR)
  {
    exception = g_hash_table_lookup (frida_exception_by_error_code, GINT_TO_POINTER (error->code));
    g_assert (exception != NULL);
  }
  else
  {
    g_assert (error->domain == G_IO_ERROR);
    g_assert (error->code == G_IO_ERROR_CANCELLED);
    exception = cancelled_exception;
  }

  message = g_string_new ("");
  g_string_append_unichar (message, g_unichar_tolower (g_utf8_get_char (error->message)));
  g_string_append (message, g_utf8_offset_to_pointer (error->message, 1));

  PyErr_SetString (exception, message->str);

  g_string_free (message, TRUE);
  g_error_free (error);

  return NULL;
}

static gboolean
PyFrida_is_string (PyObject * obj)
{
  return PyUnicode_Check (obj);
}

static gchar *
PyFrida_repr (PyObject * obj)
{
  gchar * result;
  PyObject * repr_value;

  repr_value = PyObject_Repr (obj);

  PyGObject_unmarshal_string (repr_value, &result);

  Py_DECREF (repr_value);

  return result;
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
  Py_XDECREF (spec);

  return result;
}


MOD_INIT (_frida)
{
  PyObject * inspect, * datetime, * module;

  inspect = PyImport_ImportModule ("inspect");
  inspect_getargspec = PyObject_GetAttrString (inspect, PYFRIDA_GETARGSPEC_FUNCTION);
  inspect_ismethod = PyObject_GetAttrString (inspect, "ismethod");
  Py_DECREF (inspect);

  datetime = PyImport_ImportModule ("datetime");
  datetime_constructor = PyObject_GetAttrString (datetime, "datetime");
  Py_DECREF (datetime);

  frida_init ();

  PyGObject_class_init ();

  MOD_DEF (module, "_frida", "Frida", NULL);

  PyModule_AddStringConstant (module, "__version__", frida_version_string ());

  PYFRIDA_REGISTER_TYPE (GObject, G_TYPE_OBJECT);
  PyGObject_tp_init = PyType_GetSlot ((PyTypeObject *) PYFRIDA_TYPE_OBJECT (GObject), Py_tp_init);
  PyGObject_tp_dealloc = PyType_GetSlot ((PyTypeObject *) PYFRIDA_TYPE_OBJECT (GObject), Py_tp_dealloc);

  PYFRIDA_REGISTER_TYPE (DeviceManager, FRIDA_TYPE_DEVICE_MANAGER);
  PYFRIDA_REGISTER_TYPE (Device, FRIDA_TYPE_DEVICE);
  PYFRIDA_REGISTER_TYPE (Application, FRIDA_TYPE_APPLICATION);
  PYFRIDA_REGISTER_TYPE (Process, FRIDA_TYPE_PROCESS);
  PYFRIDA_REGISTER_TYPE (Spawn, FRIDA_TYPE_SPAWN);
  PYFRIDA_REGISTER_TYPE (Child, FRIDA_TYPE_CHILD);
  PYFRIDA_REGISTER_TYPE (Crash, FRIDA_TYPE_CRASH);
  PYFRIDA_REGISTER_TYPE (Bus, FRIDA_TYPE_BUS);
  PYFRIDA_REGISTER_TYPE (Session, FRIDA_TYPE_SESSION);
  PYFRIDA_REGISTER_TYPE (Script, FRIDA_TYPE_SCRIPT);
  PYFRIDA_REGISTER_TYPE (Relay, FRIDA_TYPE_RELAY);
  PYFRIDA_REGISTER_TYPE (PortalMembership, FRIDA_TYPE_PORTAL_MEMBERSHIP);
  PYFRIDA_REGISTER_TYPE (PortalService, FRIDA_TYPE_PORTAL_SERVICE);
  PYFRIDA_REGISTER_TYPE (EndpointParameters, FRIDA_TYPE_ENDPOINT_PARAMETERS);
  PYFRIDA_REGISTER_TYPE (Compiler, FRIDA_TYPE_COMPILER);
  PYFRIDA_REGISTER_TYPE (FileMonitor, FRIDA_TYPE_FILE_MONITOR);
  PYFRIDA_REGISTER_TYPE (IOStream, G_TYPE_IO_STREAM);
  PYFRIDA_REGISTER_TYPE (Cancellable, G_TYPE_CANCELLABLE);

  frida_exception_by_error_code = g_hash_table_new_full (NULL, NULL, NULL, PyFrida_object_decref);
#define PYFRIDA_DECLARE_EXCEPTION(code, name) \
    do \
    { \
      PyObject * exception = PyErr_NewException ("frida." name "Error", NULL, NULL); \
      g_hash_table_insert (frida_exception_by_error_code, GINT_TO_POINTER (G_PASTE (FRIDA_ERROR_, code)), exception); \
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

  cancelled_exception = PyErr_NewException ("frida.OperationCancelledError", NULL, NULL);
  Py_INCREF (cancelled_exception);
  PyModule_AddObject (module, "OperationCancelledError", cancelled_exception);

  return MOD_SUCCESS_VAL (module);
}
