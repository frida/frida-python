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
