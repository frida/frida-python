static gboolean
PyGObject_unmarshal_certificate (const gchar * str,
                                GTlsCertificate ** certificate)
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
PyEndpointParameters_init (PyEndpointParameters * self,
                           PyObject * args,
                           PyObject * kw)
{
  int result = -1;
  static char * keywords[] = { "address", "port", "certificate", "origin", "auth_service", "asset_root", NULL };
  char * address = NULL;
  unsigned short int port = 0;
  char * certificate_value = NULL;
  char * origin = NULL;
  PyObject * auth_service_obj = NULL;
  char * asset_root_value = NULL;
  GTlsCertificate * certificate = NULL;
  FridaAuthenticationService * auth_service = NULL;
  GFile * asset_root = NULL;
  FridaEndpointParameters * handle;

  if (PyGObject_tp_init ((PyObject *) self, args, kw) < 0)
    return -1;

  if (!PyArg_ParseTupleAndKeywords (args, kw, "|esHesesOes", keywords,
        "utf-8", &address,
        &port,
        "utf-8", &certificate_value,
        "utf-8", &origin,
        &auth_service_obj,
        "utf-8", &asset_root_value))
    return -1;

  if (certificate_value != NULL && !PyGObject_unmarshal_certificate (certificate_value, &certificate))
    goto beach;

  if (auth_service_obj != NULL && auth_service_obj != Py_None)
    auth_service = g_object_ref (PY_GOBJECT_HANDLE (auth_service_obj));

  if (asset_root_value != NULL)
    asset_root = g_file_new_for_path (asset_root_value);

  handle = frida_endpoint_parameters_new (address, port, certificate, origin, auth_service, asset_root);

  PyGObject_take_handle ((PyGObject *) self, handle, PYFRIDA_TYPE (EndpointParameters));

  result = 0;

beach:
  g_clear_object (&asset_root);
  g_clear_object (&auth_service);
  g_clear_object (&certificate);

  PyMem_Free (asset_root_value);
  PyMem_Free (origin);
  PyMem_Free (certificate_value);
  PyMem_Free (address);

  return result;
}
