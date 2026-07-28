/* TEMPORARY DEBUG HACK: needs a GLib built with G_ENABLE_DEBUG. */
extern void g_task_print_alive_tasks (void);

static PyObject *
PyFrida_print_alive_tasks (PyObject * module,
                           PyObject * args)
{
  g_task_print_alive_tasks ();

  Py_RETURN_NONE;
}
