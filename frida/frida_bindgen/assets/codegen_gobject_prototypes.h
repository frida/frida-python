static void PyGObject_class_init (void);
static int PyGObject_init (PyGObject * self);
static void PyGObject_dealloc (PyGObject * self);
static gpointer PyGObject_steal_handle (PyGObject * self);
static void PyGObject_register_type (GType instance_type, PyGObjectType * python_type);
