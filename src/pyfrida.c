#include <frida.h>

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

#define FRIDA_FUNCPTR_TO_POINTER(f) (GSIZE_TO_POINTER (f))

static PyObject * json_loads;
static PyObject * json_dumps;

static GMainLoop * main_loop;
static GMainContext * main_context;


typedef struct _PyDeviceManager  PyDeviceManager;
typedef struct _PyDevice         PyDevice;
typedef struct _PyProcess        PyProcess;
typedef struct _PyIcon           PyIcon;
typedef struct _PySession        PySession;
typedef struct _PyScript         PyScript;

struct _PyDeviceManager
{
  PyObject_HEAD

  DeviceManager * handle;
  GList * on_change;
};

struct _PyDevice
{
  PyObject_HEAD

  Device * handle;

  guint id;
  const gchar * name;
  const gchar * kind;

  GList * on_close;
};

struct _PyProcess
{
  PyObject_HEAD

  ZedHostProcessInfo * handle;

  guint pid;
  const gchar * name;
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

  Session * handle;
  GList * on_close;
};

struct _PyScript
{
  PyObject_HEAD

  Script * handle;
  GList * on_message;
};

static int PyDeviceManager_init (PyDeviceManager * self);
static void PyDeviceManager_dealloc (PyDeviceManager * self);
static PyObject * PyDeviceManager_close (PyDeviceManager * self);
static PyObject * PyDeviceManager_enumerate_devices (PyDeviceManager * self);
static PyObject * PyDeviceManager_on (PyDeviceManager * self, PyObject * args);
static PyObject * PyDeviceManager_off (PyDeviceManager * self, PyObject * args);
static void PyDeviceManager_on_change (PyDeviceManager * self, DeviceManager * handle);

static PyObject * PyDevice_from_handle (Device * handle);
static int PyDevice_init (PyDevice * self);
static void PyDevice_dealloc (PyDevice * self);
static PyObject * PyDevice_repr (PyDevice * self);
static PyObject * PyDevice_enumerate_processes (PyDevice * self);
static PyObject * PyDevice_spawn (PyDevice * self, PyObject * args);
static PyObject * PyDevice_resume (PyDevice * self, PyObject * args);
static PyObject * PyDevice_attach (PyDevice * self, PyObject * args);
static PyObject * PyDevice_on (PyDevice * self, PyObject * args);
static PyObject * PyDevice_off (PyDevice * self, PyObject * args);
static void PyDevice_on_close (PyDevice * self, Device * handle);

static PyObject * PyProcess_from_handle (ZedHostProcessInfo * handle);
static int PyProcess_init (PyProcess * self);
static void PyProcess_dealloc (PyProcess * self);
static PyObject * PyProcess_repr (PyProcess * self);
static PyObject * PyProcess_get_small_icon (PyProcess * self);
static PyObject * PyProcess_get_large_icon (PyProcess * self);

static PyObject * PyIcon_from_handle (ZedImageData * handle);
static int PyIcon_init (PyIcon * self);
static void PyIcon_dealloc (PyIcon * self);
static PyObject * PyIcon_repr (PyIcon * self);

static PyObject * PySession_from_handle (Session * handle);
static int PySession_init (PySession * self);
static void PySession_dealloc (PySession * self);
static PyObject * PySession_close (PySession * self);
static PyObject * PySession_create_script (PySession * self, PyObject * args);
static PyObject * PySession_on (PySession * self, PyObject * args);
static PyObject * PySession_off (PySession * self, PyObject * args);
static void PySession_on_close (PySession * self, Session * handle);

static PyObject * PyScript_from_handle (Script * handle);
static int PyScript_init (PyScript * self);
static void PyScript_dealloc (PyScript * self);
static PyObject * PyScript_load (PyScript * self);
static PyObject * PyScript_unload (PyScript * self);
static PyObject * PyScript_post_message (PyScript * self, PyObject * args);
static PyObject * PyScript_on (PyScript * self, PyObject * args);
static PyObject * PyScript_off (PyScript * self, PyObject * args);
static void PyScript_on_message (PyScript * self, const gchar * message, const gchar * data, gint data_size, Script * handle);

static gboolean PyFrida_parse_signal_method_args (PyObject * args, const char ** signal, PyObject ** callback);

static PyMethodDef PyDeviceManager_methods[] =
{
  { "close", (PyCFunction) PyDeviceManager_close, METH_NOARGS, "Close the device manager." },
  { "enumerate_devices", (PyCFunction) PyDeviceManager_enumerate_devices, METH_NOARGS, "Enumerate devices." },
  { "on", (PyCFunction) PyDeviceManager_on, 2, "Add an event handler." },
  { "off", (PyCFunction) PyDeviceManager_off, 2, "Remove an event handler." },
  { NULL }
};

static PyMethodDef PyDevice_methods[] =
{
  { "enumerate_processes", (PyCFunction) PyDevice_enumerate_processes, METH_NOARGS, "Enumerate processes." },
  { "spawn", (PyCFunction) PyDevice_spawn, 1, "Spawn a process into an attachable state." },
  { "resume", (PyCFunction) PyDevice_resume, 1, "Resume a process from the attachable state." },
  { "attach", (PyCFunction) PyDevice_attach, 1, "Attach to a PID." },
  { "on", (PyCFunction) PyDevice_on, 2, "Add an event handler." },
  { "off", (PyCFunction) PyDevice_off, 2, "Remove an event handler." },
  { NULL }
};

static PyMemberDef PyDevice_members[] =
{
  { "id", T_UINT, G_STRUCT_OFFSET (PyDevice, id), READONLY, "Device ID."},
  { "name", T_STRING, G_STRUCT_OFFSET (PyDevice, name), READONLY, "Human-readable device name."},
  { "kind", T_STRING, G_STRUCT_OFFSET (PyDevice, kind), READONLY, "Device kind. One of: local, tether, remote."},
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
  { "close", (PyCFunction) PySession_close, METH_NOARGS, "Close the session." },
  { "create_script", (PyCFunction) PySession_create_script, 1, "Create a new script." },
  { "on", (PyCFunction) PySession_on, 2, "Add an event handler." },
  { "off", (PyCFunction) PySession_off, 2, "Remove an event handler." },
  { NULL }
};

static PyMethodDef PyScript_methods[] =
{
  { "load", (PyCFunction) PyScript_load, METH_NOARGS, "Load the script." },
  { "unload", (PyCFunction) PyScript_unload, METH_NOARGS, "Unload the script." },
  { "post_message", (PyCFunction) PyScript_post_message, 1, "Post a JSON-formatted message to the script." },
  { "on", (PyCFunction) PyScript_on, 2, "Add an event handler." },
  { "off", (PyCFunction) PyScript_off, 2, "Remove an event handler." },
  { NULL }
};

static PyTypeObject PyDeviceManagerType =
{
  PyObject_HEAD_INIT (NULL)
  0,                                            /* ob_size           */
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
  PyObject_HEAD_INIT (NULL)
  0,                                            /* ob_size           */
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

static PyTypeObject PyProcessType =
{
  PyObject_HEAD_INIT (NULL)
  0,                                            /* ob_size           */
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

static PyTypeObject PyIconType =
{
  PyObject_HEAD_INIT (NULL)
  0,                                            /* ob_size           */
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
  PyObject_HEAD_INIT (NULL)
  0,                                            /* ob_size           */
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
  PyObject_HEAD_INIT (NULL)
  0,                                            /* ob_size           */
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
  self->handle = device_manager_new (main_context);
  self->on_change = NULL;

  g_object_set_data (G_OBJECT (self->handle), "pyobject", self);

  return 0;
}

static void
PyDeviceManager_dealloc (PyDeviceManager * self)
{
  if (self->on_change != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDeviceManager_on_change), self);
    g_list_free_full (self->on_change, (GDestroyNotify) Py_DecRef);
  }

  if (self->handle != NULL)
  {
    g_object_set_data (G_OBJECT (self->handle), "pyobject", NULL);
    Py_BEGIN_ALLOW_THREADS
    g_object_unref (self->handle);
    Py_END_ALLOW_THREADS
  }

  self->ob_type->tp_free ((PyObject *) self);
}

static PyObject *
PyDeviceManager_close (PyDeviceManager * self)
{
  Py_BEGIN_ALLOW_THREADS
  device_manager_close (self->handle);
  Py_END_ALLOW_THREADS

  Py_RETURN_NONE;
}

static PyObject *
PyDeviceManager_enumerate_devices (PyDeviceManager * self)
{
  GError * error = NULL;
  GeeList * result;
  gint result_length, i;
  PyObject * devices;

  Py_BEGIN_ALLOW_THREADS
  result = device_manager_enumerate_devices (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

  result_length = gee_collection_get_size (GEE_COLLECTION (result));
  devices = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    PyList_SET_ITEM (devices, i, PyDevice_from_handle (DEVICE (gee_list_get (result, i))));
  }
  g_object_unref (result);

  return devices;
}

static PyObject *
PyDeviceManager_on (PyDeviceManager * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "change") == 0)
  {
    if (self->on_change == NULL)
    {
      g_signal_connect_swapped (self->handle, "changed", G_CALLBACK (PyDeviceManager_on_change), self);
    }

    Py_INCREF (callback);
    self->on_change = g_list_append (self->on_change, callback);
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

  if (strcmp (signal, "change") == 0)
  {
    GList * entry;

    entry = g_list_find (self->on_change, callback);
    if (entry != NULL)
    {
      self->on_change = g_list_delete_link (self->on_change, entry);
      Py_DECREF (callback);
    }
    else
    {
      PyErr_SetString (PyExc_ValueError, "unknown callback");
      return NULL;
    }

    if (self->on_change == NULL)
    {
      g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDeviceManager_on_change), self);
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
PyDeviceManager_on_change (PyDeviceManager * self, DeviceManager * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    GList * callbacks, * cur;

    g_list_foreach (self->on_change, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_change);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallFunction ((PyObject *) cur->data, NULL);
      if (result == NULL)
        PyErr_Clear ();
      else
        Py_DECREF (result);
    }

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);
  }

  PyGILState_Release (gstate);
}


static PyObject *
PyDevice_from_handle (Device * handle)
{
  PyObject * device;

  device = g_object_get_data (G_OBJECT (handle), "pyobject");
  if (device == NULL)
  {
    PyDevice * dev;

    device = PyObject_CallFunction ((PyObject *) &PyDeviceType, NULL);

    dev = (PyDevice *) device;
    dev->handle = handle;
    dev->id = device_get_id (handle);
    dev->name = device_get_name (handle);
    dev->kind = device_get_kind (handle);

    g_object_set_data (G_OBJECT (handle), "pyobject", device);
  }
  else
  {
    g_object_unref (handle);
    Py_INCREF (device);
  }

  return device;
}

static int
PyDevice_init (PyDevice * self)
{
  self->handle = NULL;
  self->on_close = NULL;

  return 0;
}

static void
PyDevice_dealloc (PyDevice * self)
{
  if (self->on_close != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDevice_on_close), self);
    g_list_free_full (self->on_close, (GDestroyNotify) Py_DecRef);
  }

  if (self->handle != NULL)
  {
    g_object_set_data (G_OBJECT (self->handle), "pyobject", NULL);
    Py_BEGIN_ALLOW_THREADS
    g_object_unref (self->handle);
    Py_END_ALLOW_THREADS
  }

  self->ob_type->tp_free ((PyObject *) self);
}

static PyObject *
PyDevice_repr (PyDevice * self)
{
  return PyString_FromFormat ("Device(id=%u, name=\"%s\", kind='%s')", self->id, self->name, self->kind);
}

static PyObject *
PyDevice_enumerate_processes (PyDevice * self)
{
  GError * error = NULL;
  GeeList * result;
  gint result_length, i;
  PyObject * processes;

  Py_BEGIN_ALLOW_THREADS
  result = device_enumerate_processes (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

  result_length = gee_collection_get_size (GEE_COLLECTION (result));
  processes = PyList_New (result_length);
  for (i = 0; i != result_length; i++)
  {
    ZedHostProcessInfo * handle = (ZedHostProcessInfo *) gee_list_get (result, i);
    PyList_SET_ITEM (processes, i, PyProcess_from_handle (handle));
  }
  g_object_unref (result);

  return processes;
}

static PyObject *
PyDevice_spawn (PyDevice * self, PyObject * args)
{
  const char * command_line;
  gint argc;
  gchar ** argv;
  gchar ** envp;
  int envp_length;
  GError * error = NULL;
  guint pid;

  if (!PyArg_ParseTuple (args, "s", &command_line))
    return NULL;

  if (!g_shell_parse_argv (command_line, &argc, &argv, &error))
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

#ifdef HAVE_MAC
  envp = *_NSGetEnviron ();
  envp_length = g_strv_length (envp);
#else
  envp = NULL;
  envp_length = 0;
#endif

  Py_BEGIN_ALLOW_THREADS
  pid = device_spawn (self->handle, argv[0], argv, argc, envp, envp_length, &error);
  Py_END_ALLOW_THREADS

  g_strfreev (argv);

  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

  return PyInt_FromLong (pid);
}

static PyObject *
PyDevice_resume (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  device_resume (self->handle, (guint) pid, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject *
PyDevice_attach (PyDevice * self, PyObject * args)
{
  long pid;
  GError * error = NULL;
  Session * handle;

  if (!PyArg_ParseTuple (args, "l", &pid))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  handle = device_attach (self->handle, (guint) pid, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

  return PySession_from_handle (handle);
}

static PyObject *
PyDevice_on (PyDevice * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "close") == 0)
  {
    if (self->on_close == NULL)
    {
      g_signal_connect_swapped (self->handle, "closed", G_CALLBACK (PyDevice_on_close), self);
    }

    Py_INCREF (callback);
    self->on_close = g_list_append (self->on_close, callback);
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

  if (strcmp (signal, "close") == 0)
  {
    GList * entry;

    entry = g_list_find (self->on_close, callback);
    if (entry != NULL)
    {
      self->on_close = g_list_delete_link (self->on_close, entry);
      Py_DECREF (callback);
    }
    else
    {
      PyErr_SetString (PyExc_ValueError, "unknown callback");
      return NULL;
    }

    if (self->on_close == NULL)
    {
      g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyDevice_on_close), self);
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
PyDevice_on_close (PyDevice * self, Device * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    GList * callbacks, * cur;

    g_list_foreach (self->on_close, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_close);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallFunction ((PyObject *) cur->data, NULL);
      if (result == NULL)
        PyErr_Clear ();
      else
        Py_DECREF (result);
    }

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);
  }

  PyGILState_Release (gstate);
}


static PyObject *
PyProcess_from_handle (ZedHostProcessInfo * handle)
{
  PyObject * result;
  PyProcess * process;

  result = PyObject_CallFunction ((PyObject *) &PyProcessType, NULL);

  process = (PyProcess *) result;
  process->handle = handle;
  process->pid = zed_host_process_info_get_pid (handle);
  process->name = zed_host_process_info_get_name (handle);

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
    zed_host_process_info_free (self->handle);

  self->ob_type->tp_free ((PyObject *) self);
}

static PyObject *
PyProcess_repr (PyProcess * self)
{
  return PyString_FromFormat ("Process(pid=%u, name=\"%s\")", self->pid, self->name);
}

static PyObject *
PyProcess_get_small_icon (PyProcess * self)
{
  return PyIcon_from_handle (&self->handle->_small_icon);
}

static PyObject *
PyProcess_get_large_icon (PyProcess * self)
{
  return PyIcon_from_handle (&self->handle->_large_icon);
}


static PyObject *
PyIcon_from_handle (ZedImageData * handle)
{
  if (zed_image_data_get_width (handle) != 0)
  {
    PyObject * result;
    PyIcon * icon;
    guchar * pixels;
    gsize pixels_length;

    result = PyObject_CallFunction ((PyObject *) &PyIconType, NULL);

    icon = (PyIcon *) result;
    icon->width = zed_image_data_get_width (handle);
    icon->height = zed_image_data_get_height (handle);
    icon->rowstride = zed_image_data_get_rowstride (handle);
    pixels = g_base64_decode (zed_image_data_get_pixels (handle), &pixels_length);
    icon->pixels = PyString_FromStringAndSize ((char *) pixels, (Py_ssize_t) pixels_length);
    g_free (pixels);

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

  self->ob_type->tp_free ((PyObject *) self);
}

static PyObject *
PyIcon_repr (PyIcon * self)
{
  return PyString_FromFormat ("Icon(width=%d, height=%d, rowstride=%d, pixels=<%zd bytes>)", self->width, self->height, self->rowstride, PyString_GET_SIZE (self->pixels));
}


static PyObject *
PySession_from_handle (Session * handle)
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
    g_object_unref (handle);
    Py_INCREF (session);
  }

  return session;
}

static int
PySession_init (PySession * self)
{
  self->handle = NULL;
  self->on_close = NULL;

  return 0;
}

static void
PySession_dealloc (PySession * self)
{
  if (self->on_close != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PySession_on_close), self);
    g_list_free_full (self->on_close, (GDestroyNotify) Py_DecRef);
  }

  if (self->handle != NULL)
  {
    g_object_set_data (G_OBJECT (self->handle), "pyobject", NULL);
    Py_BEGIN_ALLOW_THREADS
    g_object_unref (self->handle);
    Py_END_ALLOW_THREADS
  }

  self->ob_type->tp_free ((PyObject *) self);
}

static PyObject *
PySession_close (PySession * self)
{
  Py_BEGIN_ALLOW_THREADS
  session_close (self->handle);
  Py_END_ALLOW_THREADS

  Py_RETURN_NONE;
}

static PyObject *
PySession_create_script (PySession * self, PyObject * args)
{
  const char * source;
  GError * error = NULL;
  Script * handle;

  if (!PyArg_ParseTuple (args, "s", &source))
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  handle = session_create_script (self->handle, source, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

  return PyScript_from_handle (handle);
}

static PyObject *
PySession_on (PySession * self, PyObject * args)
{
  const char * signal;
  PyObject * callback;

  if (!PyFrida_parse_signal_method_args (args, &signal, &callback))
    return NULL;

  if (strcmp (signal, "close") == 0)
  {
    if (self->on_close == NULL)
    {
      g_signal_connect_swapped (self->handle, "closed", G_CALLBACK (PySession_on_close), self);
    }

    Py_INCREF (callback);
    self->on_close = g_list_append (self->on_close, callback);
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

  if (strcmp (signal, "close") == 0)
  {
    GList * entry;

    entry = g_list_find (self->on_close, callback);
    if (entry != NULL)
    {
      self->on_close = g_list_delete_link (self->on_close, entry);
      Py_DECREF (callback);
    }
    else
    {
      PyErr_SetString (PyExc_ValueError, "unknown callback");
      return NULL;
    }

    if (self->on_close == NULL)
    {
      g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PySession_on_close), self);
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
PySession_on_close (PySession * self, Session * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    GList * callbacks, * cur;

    g_list_foreach (self->on_close, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_close);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallFunction ((PyObject *) cur->data, NULL);
      if (result == NULL)
        PyErr_Clear ();
      else
        Py_DECREF (result);
    }

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);
  }

  PyGILState_Release (gstate);
}


static PyObject *
PyScript_from_handle (Script * handle)
{
  PyObject * script;

  script = g_object_get_data (G_OBJECT (handle), "pyobject");
  if (script == NULL)
  {
    script = PyObject_CallFunction ((PyObject *) &PyScriptType, NULL);
    ((PyScript *) script)->handle = handle;
    g_object_set_data (G_OBJECT (handle), "pyobject", script);
  }
  else
  {
    g_object_unref (handle);
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
  if (self->on_message != NULL)
  {
    g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyScript_on_message), self);
    g_list_free_full (self->on_message, (GDestroyNotify) Py_DecRef);
  }

  if (self->handle != NULL)
  {
    g_object_set_data (G_OBJECT (self->handle), "pyobject", NULL);
    Py_BEGIN_ALLOW_THREADS
    g_object_unref (self->handle);
    Py_END_ALLOW_THREADS
  }

  self->ob_type->tp_free ((PyObject *) self);
}

static PyObject *
PyScript_load (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  script_load (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject *
PyScript_unload (PyScript * self)
{
  GError * error = NULL;

  Py_BEGIN_ALLOW_THREADS
  script_unload (self->handle, &error);
  Py_END_ALLOW_THREADS
  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject *
PyScript_post_message (PyScript * self, PyObject * args)
{
  PyObject * message_object, * message;
  GError * error = NULL;

  if (!PyArg_ParseTuple (args, "O", &message_object))
    return NULL;

  message = PyObject_CallFunction (json_dumps, "O", message_object);
  if (message == NULL)
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  script_post_message (self->handle, PyString_AsString (message), &error);
  Py_END_ALLOW_THREADS

  Py_DECREF (message);

  if (error != NULL)
  {
    PyErr_SetString (PyExc_SystemError, error->message);
    g_error_free (error);
    return NULL;
  }

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
    if (self->on_message == NULL)
    {
      g_signal_connect_swapped (self->handle, "message", G_CALLBACK (PyScript_on_message), self);
    }

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

    if (self->on_message == NULL)
    {
      g_signal_handlers_disconnect_by_func (self->handle, FRIDA_FUNCPTR_TO_POINTER (PyScript_on_message), self);
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
PyScript_on_message (PyScript * self, const gchar * message, const gchar * data, gint data_size, Script * handle)
{
  PyGILState_STATE gstate;

  gstate = PyGILState_Ensure ();

  if (g_object_get_data (G_OBJECT (handle), "pyobject") == self)
  {
    GList * callbacks, * cur;
    PyObject * args, * message_object;

    g_list_foreach (self->on_message, (GFunc) Py_IncRef, NULL);
    callbacks = g_list_copy (self->on_message);

    message_object = PyObject_CallFunction (json_loads, "s", message);
    g_assert (message_object != NULL);
    args = Py_BuildValue ("Os#", message_object, data, data_size);
    Py_DECREF (message_object);

    for (cur = callbacks; cur != NULL; cur = cur->next)
    {
      PyObject * result = PyObject_CallObject ((PyObject *) cur->data, args);
      if (result == NULL)
        PyErr_Clear ();
      else
        Py_DECREF (result);
    }

    Py_DECREF (args);

    g_list_free_full (callbacks, (GDestroyNotify) Py_DecRef);
  }

  PyGILState_Release (gstate);
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


static gpointer
run_main_loop (gpointer data)
{
  (void) data;

  g_main_context_push_thread_default (main_context);
  g_main_loop_run (main_loop);
  g_main_context_pop_thread_default (main_context);

  return NULL;
}

PyMODINIT_FUNC
init_frida (void)
{
  PyObject * json;
  PyObject * module;

  PyEval_InitThreads ();

  json = PyImport_ImportModule ("json");
  json_loads = PyObject_GetAttrString (json, "loads");
  json_dumps = PyObject_GetAttrString (json, "dumps");
  Py_DECREF (json);

  g_type_init ();
  gum_init_with_features ((GumFeatureFlags) (GUM_FEATURE_ALL & ~GUM_FEATURE_SYMBOL_LOOKUP));

  main_context = g_main_context_new ();
  main_loop = g_main_loop_new (main_context, FALSE);
  g_thread_create (run_main_loop, NULL, FALSE, NULL);

  PyDeviceManagerType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyDeviceManagerType) < 0)
    return;

  PyDeviceType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyDeviceType) < 0)
    return;

  PyProcessType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyProcessType) < 0)
    return;

  PyIconType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyIconType) < 0)
    return;

  PySessionType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PySessionType) < 0)
    return;

  PyScriptType.tp_new = PyType_GenericNew;
  if (PyType_Ready (&PyScriptType) < 0)
    return;

  module = Py_InitModule ("_frida", NULL);

  Py_INCREF (&PyDeviceManagerType);
  PyModule_AddObject (module, "DeviceManager", (PyObject *) &PyDeviceManagerType);

  Py_INCREF (&PyDeviceType);
  PyModule_AddObject (module, "Device", (PyObject *) &PyDeviceType);

  Py_INCREF (&PyProcessType);
  PyModule_AddObject (module, "Process", (PyObject *) &PyProcessType);

  Py_INCREF (&PyIconType);
  PyModule_AddObject (module, "Icon", (PyObject *) &PyIconType);

  Py_INCREF (&PySessionType);
  PyModule_AddObject (module, "Session", (PyObject *) &PySessionType);

  Py_INCREF (&PyScriptType);
  PyModule_AddObject (module, "Script", (PyObject *) &PyScriptType);
}
