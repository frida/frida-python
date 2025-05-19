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
