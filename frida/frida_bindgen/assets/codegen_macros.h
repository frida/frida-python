#define PYFRIDA_TYPE(name) \
  (&_PYFRIDA_TYPE_VAR (name, type))
#define PYFRIDA_TYPE_OBJECT(name) \
  PYFRIDA_TYPE (name)->object
#define _PYFRIDA_TYPE_VAR(name, var) \
  G_PASTE (G_PASTE (G_PASTE (Py, name), _), var)
#define PYFRIDA_DEFINE_BASETYPE(pyname, cname, ...) \
  _PYFRIDA_DEFINE_TYPE_SLOTS (cname, __VA_ARGS__); \
  _PYFRIDA_DEFINE_TYPE_SPEC (cname, pyname, Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE); \
  static PyGObjectType _PYFRIDA_TYPE_VAR (cname, type) = \
  { \
    .parent = NULL, \
    .object = NULL, \
  }
#define PYFRIDA_DEFINE_TYPE(pyname, cname, parent_cname, ...) \
  _PYFRIDA_DEFINE_TYPE_SLOTS (cname, __VA_ARGS__); \
  _PYFRIDA_DEFINE_TYPE_SPEC (cname, pyname, Py_TPFLAGS_DEFAULT); \
  static PyGObjectType _PYFRIDA_TYPE_VAR (cname, type) = \
  { \
    .parent = PYFRIDA_TYPE (parent_cname), \
    .object = NULL, \
  }
#define PYFRIDA_REGISTER_TYPE(cname, gtype) \
  G_BEGIN_DECLS \
  { \
    PyGObjectType * t = PYFRIDA_TYPE (cname); \
    t->object = PyType_FromSpecWithBases (&_PYFRIDA_TYPE_VAR (cname, spec), \
        (t->parent != NULL) ? PyTuple_Pack (1, t->parent->object) : NULL); \
    PyGObject_register_type (gtype, t); \
    Py_IncRef (t->object); \
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

#define PyFrida_RETURN_NONE \
  G_STMT_START \
  { \
    Py_IncRef (Py_None); \
    return Py_None; \
  } \
  G_STMT_END
