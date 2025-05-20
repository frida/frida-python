static void
PyGObject_class_init (void)
{
  pygobject_type_spec_by_type = g_hash_table_new_full (NULL, NULL, NULL, NULL);
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
PyGObject_take_handle (PyGObject * self,
                       gpointer handle,
                       const PyGObjectType * type)
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
    G_GNUC_UNUSED guint num_matches;

    num_matches = g_signal_handlers_disconnect_matched (handle, G_SIGNAL_MATCH_CLOSURE, closure->signal_id, 0, &closure->parent, NULL, NULL);
    g_assert (num_matches == 1);
  }
  g_clear_pointer (&self->signal_closures, g_slist_free);

  g_object_set_data (G_OBJECT (handle), "pyobject", NULL);

  self->handle = NULL;

  return handle;
}

static void
PyGObject_register_type (GType instance_type,
                         PyGObjectType * python_type)
{
  g_hash_table_insert (pygobject_type_spec_by_type, GSIZE_TO_POINTER (instance_type), python_type);
}
