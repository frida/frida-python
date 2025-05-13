from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from typing import (Callable, Iterator, List, Mapping, Optional, Sequence,
                    Tuple, Union)

CORE_NAMESPACE = "http://www.gtk.org/introspection/core/1.0"
C_NAMESPACE = "http://www.gtk.org/introspection/c/1.0"
GLIB_NAMESPACE = "http://www.gtk.org/introspection/glib/1.0"
GIR_NAMESPACES = {"": CORE_NAMESPACE, "glib": GLIB_NAMESPACE}

CORE_TAG_PREFIX = f"{{{CORE_NAMESPACE}}}"

NUMERIC_GIR_TYPES = {
    "gsize",
    "gssize",
    "gint",
    "guint",
    "glong",
    "gulong",
    "gint8",
    "gint16",
    "gint32",
    "gint64",
    "guint8",
    "guint16",
    "guint32",
    "guint64",
    "GType",
    "GQuark",
}

PRIMITIVE_GIR_TYPES = NUMERIC_GIR_TYPES | {
    "gpointer",
    "gboolean",
    "gchar",
    "utf8",
    "utf8[]",
}

ResolveTypeCallback = Callable[[str], Tuple[str, ET.Element]]


@dataclass
class Customizations:
    custom_types: Mapping[str, CustomType] = field(default_factory=OrderedDict)
    type_customizations: Mapping[str, TypeCustomizations] = field(
        default_factory=OrderedDict
    )
    facade_exports: List[str] = field(default_factory=list)
    facade_code: str = ""
    helper_imports: List[str] = field(default_factory=list)
    helper_code: str = ""


@dataclass
class Model:
    namespace: Namespace
    _object_types: OrderedDict[str, ObjectType]
    enumerations: OrderedDict[str, Enumeration]
    customizations: Customizations = field(default_factory=Customizations)

    @cached_property
    def object_types(self) -> OrderedDict[str, ObjectType]:
        result = OrderedDict()
        type_customizations = self.customizations.type_customizations
        for k, v in self._object_types.items():
            custom = type_customizations.get(k)
            if custom is None or not custom.drop:
                result[k] = v
        return result

    @cached_property
    def public_types(self) -> OrderedDict[str, Union[ObjectType, Enumeration]]:
        return OrderedDict(
            [(k, v) for k, v in self.object_types.items() if v.is_public]
            + list(self.enumerations.items())
        )

    @cached_property
    def interface_types_with_abstract_base(self) -> List[InterfaceObjectType]:
        return [
            t
            for t in self.object_types.values()
            if isinstance(t, InterfaceObjectType) and t.has_abstract_base
        ]

    def resolve_object_type(self, name: str) -> ObjectType:
        bare_name = name.split(".", maxsplit=1)[-1]
        return self.object_types[bare_name]

    def resolve_js_type(self, t: Type) -> str:
        js = js_type_from_gir(t.name)
        otype = self.object_types.get(js)
        if otype is not None:
            return otype.js_name
        return js


@dataclass
class Namespace:
    name: str
    identifier_prefixes: str
    element: ET.Element

    @cached_property
    def type_elements(self) -> Mapping[str, ET.Element]:
        result = {}
        for toplevel in self.element.findall("./*[@name]", GIR_NAMESPACES):
            name = toplevel.get("name")
            result[name] = toplevel
            for callback in toplevel.findall("./callback", GIR_NAMESPACES):
                result[name + callback.get("name")] = callback
        return result


@dataclass
class ObjectType:
    name: str
    c_type: str
    get_type: str
    type_struct: str
    _parent: Optional[str]
    _constructors: List[ET.Element]
    _methods: List[ET.Element]
    _properties: List[ET.Element]
    _signals: List[ET.Element]
    resolve_type: ResolveTypeCallback

    model: Optional[Model]

    @cached_property
    def js_name(self) -> str:
        custom = self.customizations
        if custom is not None and custom.js_name is not None:
            return custom.js_name
        return self.name

    @cached_property
    def prefixed_js_name(self) -> str:
        return f"_{self.js_name}" if self.needs_wrapper else self.js_name

    @cached_property
    def abstract_base_c_type(self) -> str:
        return f"FdnAbstract{self.name}"

    @cached_property
    def parent(self) -> ObjectType:
        if self._parent is None:
            return None
        return self.model.resolve_object_type(self._parent)

    @property
    def is_public(self) -> bool:
        return not self.is_frida_list

    @cached_property
    def is_frida_options(self) -> bool:
        return self.c_type.startswith("Frida") and self.c_type.endswith("Options")

    @cached_property
    def is_frida_list(self) -> bool:
        return self.c_type.startswith("Frida") and self.c_type.endswith("List")

    @cached_property
    def needs_wrapper(self) -> bool:
        custom = self.customizations
        if custom is None:
            return False
        if custom.custom_code is not None:
            return True
        ctor = self.constructors[0] if self.constructors else None
        if ctor is not None and ctor.needs_wrapper:
            return True
        return self.wrapped_methods or self.wrapped_signals

    @cached_property
    def customizations(self) -> Optional[ObjectTypeCustomizations]:
        return self.model.customizations.type_customizations.get(self.name)

    @cached_property
    def c_symbol_prefix(self) -> str:
        return f"fdn_{to_snake_case(self.name)}"

    @cached_property
    def abstract_base_c_symbol_prefix(self) -> str:
        return f"fdn_abstract_{to_snake_case(self.name)}"

    @cached_property
    def c_cast_macro(self) -> str:
        return to_macro_case(self.c_type)

    @cached_property
    def abstract_base_c_cast_macro(self) -> str:
        return to_macro_case(self.abstract_base_c_type)

    @cached_property
    def constructors(self) -> List[Constructor]:
        constructors = []
        custom = self.customizations
        for element in self._constructors:
            if element.get("introspectable") == "0" or element.get("deprecated") == "1":
                continue

            name = element.get("name")

            if custom is not None:
                ccust = custom.constructor
                if ccust is not None and ccust.drop:
                    continue

            (
                c_identifier,
                finish_c_identifier,
                param_list,
                has_closure_param,
                throws,
                result_element,
            ) = extract_callable_details(element, element, self, self.resolve_type)
            if has_closure_param or finish_c_identifier is not None:
                continue

            constructors.append(
                Constructor(
                    name, c_identifier, finish_c_identifier, param_list, throws, self
                )
            )
        return constructors

    @cached_property
    def methods(self) -> List[Method]:
        methods = []
        c_prop_names = {prop.c_name for prop in self.properties}
        custom = self.customizations
        for element in self._methods:
            name = element.get("name")

            if (
                element.get("introspectable") == "0"
                or name.startswith("_")
                or name.endswith("_sync")
                or name.endswith("_finish")
            ):
                continue

            if custom is not None:
                mcust = custom.methods.get(name, None)
                if mcust is not None and mcust.drop:
                    continue

            finish_func = element.get(f"{{{GLIB_NAMESPACE}}}finish-func")
            if finish_func is None:
                finish_func = f"{name}_finish"
            result_element = next(
                (m for m in self._methods if m.get("name") == finish_func), element
            )

            (
                c_identifier,
                finish_c_identifier,
                param_list,
                has_closure_param,
                throws,
                result_element,
            ) = extract_callable_details(
                element, result_element, self, self.resolve_type
            )
            if has_closure_param:
                continue

            retval_element = result_element.find(".//return-value", GIR_NAMESPACES)
            rettype = extract_type_from_entity(retval_element, self.resolve_type)
            if rettype is not None:
                if rettype.is_frida_options:
                    continue

                nullable = retval_element.get("nullable") == "1"

                ownership_val = retval_element.get("transfer-ownership")
                transfer_ownership = (
                    TransferOwnership[ownership_val]
                    if ownership_val is not None
                    else TransferOwnership.none
                )

                retval = ReturnValue(rettype, nullable, transfer_ownership, self)
            else:
                retval = None

            if element.get(f"{{{GLIB_NAMESPACE}}}get-property") is not None:
                is_property_accessor = True
            else:
                tokens = name.split("_", maxsplit=1)
                is_property_accessor = (
                    len(tokens) == 2
                    and tokens[0] in {"get", "set"}
                    and tokens[1] in c_prop_names
                )

            methods.append(
                Method(
                    name,
                    c_identifier,
                    finish_c_identifier,
                    param_list,
                    throws,
                    retval,
                    is_property_accessor,
                    self,
                )
            )
        return methods

    @cached_property
    def wrapped_methods(self) -> List[Method]:
        return [m for m in self.methods if m.needs_wrapper]

    @cached_property
    def properties(self) -> List[Property]:
        properties = []
        custom = self.customizations
        for element in self._properties:
            name = element.get("name")

            if custom is not None:
                pcust = custom.properties.get(name, None)
                if pcust is not None and pcust.drop:
                    continue

            c_name = name.replace("-", "_")
            type = extract_type_from_entity(element, self.resolve_type)
            if type.is_frida_options:
                continue
            writable = element.get("writable") == "1"
            construct_only = element.get("construct-only") == "1"

            getter = element.get("getter")
            if getter is None:
                getter = f"get_{c_name}"

            setter = element.get("setter")
            if setter is None and writable and not construct_only:
                setter = f"set_{c_name}"

            properties.append(
                Property(
                    name,
                    c_name,
                    type,
                    writable,
                    construct_only,
                    getter,
                    setter,
                    self,
                )
            )
        return properties

    @cached_property
    def signals(self) -> List[Signal]:
        signals = []
        custom = self.customizations
        for element in self._signals:
            name = element.get("name")

            if custom is not None:
                scust = custom.signals.get(name, None)
                if scust is not None and scust.drop:
                    continue

            c_name = name.replace("-", "_")
            param_list = extract_parameters(
                element.findall("./parameters/parameter", GIR_NAMESPACES),
                nullable_implies_optional=False,
                object_type=self,
                resolve_type=self.resolve_type,
            )
            signals.append(Signal(name, c_name, param_list, self))
        return signals

    @cached_property
    def wrapped_signals(self) -> List[Signal]:
        return [s for s in self.signals if s.needs_wrapper]


@dataclass
class ClassObjectType(ObjectType):
    _implements: List[str]

    @cached_property
    def implements(self) -> List[InterfaceObjectType]:
        return [self.model.resolve_object_type(i) for i in self._implements]


@dataclass
class InterfaceObjectType(ObjectType):
    @cached_property
    def has_abstract_base(self) -> bool:
        custom = self.customizations
        if custom is None:
            return True
        return not custom.drop_abstract_base


@dataclass
class Procedure:
    name: str
    c_identifier: str
    finish_c_identifier: Optional[str]
    parameters: List[Parameter]
    throws: bool

    @property
    def is_async(self) -> bool:
        return self.finish_c_identifier is not None

    @cached_property
    def input_parameters(self) -> List[Parameter]:
        return [p for p in self.parameters if p.direction != Direction.OUT]


@dataclass
class Constructor(Procedure):
    object_type: ObjectType

    @cached_property
    def param_typings(self) -> List[str]:
        custom = self.customizations
        if custom is not None and custom.param_typings is not None:
            return custom.param_typings
        return [param.typing for param in self.parameters]

    @property
    def needs_wrapper(self) -> bool:
        custom = self.customizations
        if custom is None:
            return False
        return custom.custom_logic is not None

    @cached_property
    def customizations(self) -> Optional[ConstructorCustomizations]:
        custom = self.object_type.customizations
        if custom is None:
            return None
        return custom.constructor


@dataclass
class Method(Procedure):
    return_value: Optional[ReturnValue]
    is_property_accessor: bool

    object_type: ObjectType

    @cached_property
    def js_name(self) -> str:
        custom = self.customizations
        if custom is not None and custom.js_name is not None:
            return custom.js_name
        return to_camel_case(self.name)

    @cached_property
    def prefixed_js_name(self) -> str:
        custom = self.customizations
        if self.needs_wrapper or (custom is not None and custom.hide):
            return f"_{self.js_name}"
        return self.js_name

    @cached_property
    def cself_name(self) -> str:
        return to_snake_case(self.object_type.name).split("_")[-1]

    @cached_property
    def param_ctypings(self) -> List[str]:
        result = [f"{self.object_type.c_type} * {self.cself_name}"]
        result += [param.ctyping for param in self.parameters]
        if self.is_async:
            result += ["GAsyncReadyCallback callback", "gpointer user_data"]
        return result

    @cached_property
    def finish_param_ctypings(self) -> List[str]:
        result = [
            f"{self.object_type.c_type} * {self.cself_name}",
            "GAsyncResult * result",
        ]
        if self.throws:
            result.append("GError ** error")
        return result

    @cached_property
    def param_typings(self) -> List[str]:
        custom = self.customizations
        if custom is not None and custom.param_typings is not None:
            return custom.param_typings
        return self.prefixed_param_typings

    @cached_property
    def prefixed_param_typings(self) -> List[str]:
        return [param.typing for param in self.input_parameters]

    @cached_property
    def return_ctyping(self) -> str:
        retval = self.return_value
        return retval.ctyping if retval is not None else "void"

    @cached_property
    def return_typing(self) -> str:
        custom = self.customizations
        if custom is not None and custom.return_typing is not None:
            return custom.return_typing
        return self.prefixed_return_typing

    @cached_property
    def prefixed_return_typing(self) -> str:
        retval = self.return_value
        typing = retval.typing if retval is not None else "void"
        return f"Promise<{typing}>" if self.is_async else typing

    @property
    def needs_wrapper(self) -> bool:
        custom = self.customizations
        if custom is None:
            return False
        return custom.custom_logic is not None or custom.return_wrapper is not None

    @cached_property
    def customizations(self) -> Optional[MethodCustomizations]:
        custom = self.object_type.customizations
        if custom is None:
            return None
        return custom.methods.get(self.name)

    @cached_property
    def operation_type_name(self) -> str:
        return f"Fdn{self.object_type.name}{to_pascal_case(self.name)}Operation"

    @cached_property
    def abstract_base_operation_type_name(self) -> str:
        return f"FdnAbstract{self.object_type.name}{to_pascal_case(self.name)}Operation"

    @cached_property
    def is_select_method(self) -> bool:
        return self.name.startswith("select_") or self.name.startswith("add_")

    @cached_property
    def select_noun(self) -> str:
        assert (
            self.is_select_method
        ), "select_noun can only be called on selector methods"
        return self.name.split("_", maxsplit=1)[1]

    @cached_property
    def select_plural_noun(self) -> str:
        return f"{self.select_noun}s"

    @cached_property
    def select_element_type(self) -> Type:
        assert (
            self.is_select_method
        ), "select_element_type can only be called on selector methods"
        return self.parameters[0].type


@dataclass
class Property:
    name: str
    c_name: str
    type: Type
    writable: bool
    construct_only: bool
    getter: Optional[str]
    setter: Optional[str]

    object_type: ObjectType

    @cached_property
    def js_name(self) -> str:
        custom = self.customizations
        if custom is not None and custom.js_name is not None:
            return custom.js_name
        return to_camel_case(self.c_name)

    @cached_property
    def typing(self) -> str:
        custom = self.customizations
        if custom is not None and custom.typing is not None:
            return custom.typing
        readonly = "readonly " if not self.writable else ""
        optional_str = "?" if self.object_type.is_frida_options else ""
        return f"{readonly}{self.js_name}{optional_str}: {self.object_type.model.resolve_js_type(self.type)}"

    @cached_property
    def customizations(self) -> Optional[PropertyCustomizations]:
        custom = self.object_type.customizations
        if custom is None:
            return None
        return custom.properties.get(self.name)


@dataclass
class Signal:
    name: str
    c_name: str
    parameters: List[Parameter]

    object_type: ObjectType

    @cached_property
    def js_name(self) -> str:
        return to_camel_case(self.c_name)

    @cached_property
    def prefixed_js_name(self) -> str:
        return f"_{self.js_name}" if self.needs_wrapper else self.js_name

    @cached_property
    def handler_type_name(self) -> str:
        # XXX: Special-cases to avoid breaking API:
        class_name = self.object_type.name
        if class_name == "DeviceManager":
            prefix = "Device"
        elif class_name == "Device":
            prefix = "Device" if self.name == "lost" else ""
        elif class_name == "PortalService":
            prefix = "Portal"
        elif class_name == "Cancellable":
            prefix = ""
        else:
            prefix = class_name
        return f"{prefix}{to_pascal_case(self.c_name)}Handler"

    @cached_property
    def prefixed_handler_type_name(self) -> str:
        return (
            f"_{self.handler_type_name}"
            if self.needs_wrapper
            else self.handler_type_name
        )

    @cached_property
    def typing(self) -> str:
        params = ", ".join([p.typing for p in self.parameters])
        return f"({params}) => void"

    @property
    def needs_wrapper(self) -> bool:
        custom = self.customizations
        if custom is None:
            return False
        return custom.transform is not None or custom.intercept is not None

    @cached_property
    def customizations(self) -> Optional[SignalCustomizations]:
        custom = self.object_type.customizations
        if custom is None:
            return None
        return custom.signals.get(self.name)


TransferOwnership = Enum("TransferOwnership", ["none", "full", "container"])


@dataclass
class Parameter:
    name: str
    type: Type
    optional: bool
    nullable: bool
    transfer_ownership: TransferOwnership
    direction: Direction

    object_type: ObjectType

    @cached_property
    def js_name(self) -> str:
        return to_camel_case(self.name)

    @cached_property
    def ctyping(self) -> str:
        return f"{self.type.c} {self.name}"

    @cached_property
    def typing(self) -> str:
        optional_str = "?" if self.optional else ""
        t = f"{self.js_name}{optional_str}: {self.object_type.model.resolve_js_type(self.type)}"
        if self.nullable and not self.type.is_frida_options:
            t += " | null"
        return t

    @cached_property
    def copy_func(self) -> Optional[str]:
        return self.type.copy_func

    @cached_property
    def destroy_func(self) -> Optional[str]:
        return self.type.destroy_func


@dataclass
class ReturnValue:
    type: Type
    nullable: bool
    transfer_ownership: TransferOwnership

    object_type: ObjectType

    @cached_property
    def ctyping(self) -> str:
        return self.type.c

    @cached_property
    def typing(self) -> str:
        t = self.object_type.model.resolve_js_type(self.type)
        if self.nullable:
            t += " | null"
        return t

    @cached_property
    def destroy_func(self) -> Optional[str]:
        if self.transfer_ownership == TransferOwnership.none:
            return None
        return self.type.destroy_func


@dataclass
class Type:
    name: str
    nick: str
    c: str
    default_value: Optional[str]
    copy_func: Optional[str]
    destroy_func: Optional[str]

    @cached_property
    def from_pointer_func(self) -> Optional[str]:
        if self.name in {"gssize", "gsize", "glong", "gulong", "gint64", "guint64"}:
            return "GPOINTER_TO_SIZE"
        if self.name in {"gint", "gint8", "gint16", "gint32"}:
            return "GPOINTER_TO_INT"
        if self.name in {"gboolean", "guint", "guint8", "guint16", "guint32"}:
            return "GPOINTER_TO_UINT"
        return None

    @cached_property
    def to_pointer_func(self) -> Optional[str]:
        if self.name in {"gssize", "gsize", "glong", "gulong", "gint64", "guint64"}:
            return "GSIZE_TO_POINTER"
        if self.name in {"gint", "gint8", "gint16", "gint32"}:
            return "GINT_TO_POINTER"
        if self.name in {"gboolean", "guint", "guint8", "guint16", "guint32"}:
            return "GUINT_TO_POINTER"
        return None

    @cached_property
    def is_frida_options(self) -> bool:
        return self.c.startswith("Frida") and self.c.endswith("Options *")


class Direction(Enum):
    IN = "in"
    OUT = "out"
    INOUT = "inout"


@dataclass
class Enumeration:
    name: str
    c_type: str
    get_type: str
    _members: List[ET.Element]

    model: Optional[Model]

    @property
    def js_name(self) -> str:
        return self.name

    @property
    def prefixed_js_name(self) -> str:
        return self.name

    @cached_property
    def members(self) -> List[EnumerationMember]:
        members = []
        for element in self._members:
            members.append(EnumerationMember(element.get("name"), self))
        return members

    @property
    def is_frida_options(self) -> bool:
        return False

    @cached_property
    def customizations(self) -> Optional[EnumerationCustomizations]:
        return self.model.customizations.type_customizations.get(self.name)

    @cached_property
    def c_symbol_prefix(self) -> str:
        return f"fdn_{to_snake_case(self.name)}"


@dataclass
class EnumerationMember:
    name: str

    enumeration: Enumeration

    @cached_property
    def js_name(self) -> str:
        custom = self.customizations
        if custom is not None and custom.js_name is not None:
            return custom.js_name
        return to_pascal_case(self.name)

    @cached_property
    def nick(self) -> str:
        return self.name.replace("_", "-")

    @cached_property
    def customizations(self) -> Optional[EnumerationMemberCustomizations]:
        custom = self.enumeration.customizations
        if custom is None:
            return None
        return custom.members.get(self.name)


@dataclass
class CustomType:
    kind: CustomTypeKind
    typing: str


class CustomTypeKind(Enum):
    TYPE = "type"
    INTERFACE = "interface"
    ENUM = "enum"


@dataclass
class TypeCustomizations:
    pass


@dataclass
class ObjectTypeCustomizations(TypeCustomizations):
    js_name: Optional[str] = None
    drop: bool = False
    drop_abstract_base: bool = False
    constructor: Optional[ConstructorCustomizations] = None
    methods: Mapping[str, MethodCustomizations] = field(
        default_factory=lambda: defaultdict(dict)
    )
    properties: Mapping[str, PropertyCustomizations] = field(
        default_factory=lambda: defaultdict(dict)
    )
    signals: Mapping[str, SignalCustomizations] = field(
        default_factory=lambda: defaultdict(dict)
    )
    custom_code: Optional[CustomCode] = None
    cleanup: Optional[str] = None
    keep_alive: Optional[KeepAliveCustomization] = None


@dataclass
class KeepAliveCustomization:
    is_destroyed_function: str
    destroy_signal_name: str


@dataclass
class ConstructorCustomizations:
    drop: bool = False
    param_typings: Optional[List[str]] = None
    custom_logic: Optional[str] = None


@dataclass
class MethodCustomizations:
    js_name: Optional[str] = None
    drop: bool = False
    hide: bool = False
    param_typings: Optional[List[str]] = None
    return_typing: Optional[str] = None
    custom_logic: Optional[str] = None
    return_wrapper: Optional[str] = None
    return_cconversion: Optional[str] = None
    ref_keep_alive: bool = False
    unref_keep_alive: bool = False


@dataclass
class PropertyCustomizations:
    js_name: Optional[str] = None
    drop: bool = False
    typing: Optional[str] = None


@dataclass
class SignalCustomizations:
    drop: bool = False
    behavior: str = "FDN_SIGNAL_ALLOW_EXIT"
    transform: Optional[Mapping[int, Tuple[str, Optional[str]]]] = None
    intercept: Optional[str] = None


@dataclass
class CustomCode:
    declarations: List[CustomDeclaration] = field(default_factory=list)
    methods: List[CustomMethod] = field(default_factory=list)


@dataclass
class CustomDeclaration:
    typing: Optional[str]
    code: str


@dataclass
class CustomMethod:
    typing: Optional[str]
    code: str


@dataclass
class EnumerationCustomizations(TypeCustomizations):
    members: Mapping[str, EnumerationMemberCustomizations] = field(
        default_factory=lambda: defaultdict(dict)
    )


@dataclass
class EnumerationMemberCustomizations:
    js_name: Optional[str] = None


def parse_gir(file_path: str, dependencies: Sequence[Model]) -> Model:
    tree = ET.parse(file_path)

    el = tree.getroot().find("./namespace", GIR_NAMESPACES)
    namespace = Namespace(
        el.get("name"), el.get(f"{{{C_NAMESPACE}}}identifier-prefixes"), el
    )

    def resolve_type(name: str) -> Tuple[str, ET.Element]:
        assert (
            name not in PRIMITIVE_GIR_TYPES
        ), f"unexpectedly asked to resolve primitive type: {name}"

        tokens = name.split(".", maxsplit=1)
        if len(tokens) == 2:
            ns_name, bare_name = tokens
            if ns_name == namespace.name:
                ns = namespace
            else:
                ns = next(
                    (
                        dep.namespace
                        for dep in dependencies
                        if dep.namespace.name == ns_name
                    ),
                    None,
                )
                if ns is None:
                    assert ns is not None, f"unable to resolve namespace {ns_name}"
        else:
            ns = namespace
            bare_name = name
        qualified_name = f"{ns.name}.{bare_name}"

        element = ns.type_elements.get(bare_name)
        assert element is not None, f"unable to resolve type {bare_name}"

        return (qualified_name, element)

    object_types = OrderedDict()

    for element in namespace.element.findall("./class", GIR_NAMESPACES):
        name = element.get("name")
        c_type = element.get(f"{{{C_NAMESPACE}}}type")
        get_type = element.get(f"{{{GLIB_NAMESPACE}}}get-type")
        type_struct = element.get(f"{{{GLIB_NAMESPACE}}}type-struct")
        if type_struct is not None:
            type_struct = namespace.identifier_prefixes + type_struct
        else:
            type_struct = c_type + "Class"
        parent = element.get("parent")
        if parent is not None:
            parent, _ = resolve_type(parent)
        constructors = element.findall(".//constructor", GIR_NAMESPACES)
        methods = element.findall(".//method", GIR_NAMESPACES)
        properties = element.findall(".//property", GIR_NAMESPACES)
        signals = element.findall(".//glib:signal", GIR_NAMESPACES)
        implements = [
            e.get("name") for e in element.findall(".//implements", GIR_NAMESPACES)
        ]

        object_types[name] = ClassObjectType(
            name,
            c_type,
            get_type,
            type_struct,
            parent,
            constructors,
            methods,
            properties,
            signals,
            resolve_type,
            None,
            implements,
        )

    for element in namespace.element.findall("./interface", GIR_NAMESPACES):
        name = element.get("name")
        c_type = element.get(f"{{{C_NAMESPACE}}}type")
        get_type = element.get(f"{{{GLIB_NAMESPACE}}}get-type")
        type_struct = element.get(f"{{{GLIB_NAMESPACE}}}type-struct")
        if type_struct is not None:
            type_struct = namespace.identifier_prefixes + type_struct
        else:
            type_struct = c_type + "Iface"
        prereq = element.find(".//prerequisite", GIR_NAMESPACES)
        parent = prereq.get("name") if prereq is not None else None
        if parent is not None:
            parent, _ = resolve_type(parent)
        constructors = []
        methods = element.findall(".//method", GIR_NAMESPACES)
        properties = element.findall(".//property", GIR_NAMESPACES)
        signals = element.findall(".//glib:signal", GIR_NAMESPACES)

        object_types[name] = InterfaceObjectType(
            name,
            c_type,
            get_type,
            type_struct,
            parent,
            constructors,
            methods,
            properties,
            signals,
            resolve_type,
            None,
        )

    enumerations = OrderedDict()

    for element in namespace.element.findall("./enumeration", GIR_NAMESPACES):
        if element.get(f"{{{GLIB_NAMESPACE}}}error-domain") is not None:
            continue
        enum_name = element.get("name")
        enum_c_type = element.get(f"{{{C_NAMESPACE}}}type")
        get_type = element.get(f"{{{GLIB_NAMESPACE}}}get-type")
        members = element.findall(".//member", GIR_NAMESPACES)
        enumerations[enum_name] = Enumeration(
            enum_name, enum_c_type, get_type, members, None
        )

    model = Model(namespace, object_types, enumerations)

    for t in object_types.values():
        t.model = model
    for t in enumerations.values():
        t.model = model

    return model


def extract_callable_details(
    element: ET.Element,
    result_element: ET.Element,
    object_type: ObjectType,
    resolve_type: ResolveTypeCallback,
) -> Tuple[str, Optional[str], List[Parameter], bool, bool, ET.Element]:
    c_identifier = element.get(f"{{{C_NAMESPACE}}}identifier")

    parameters = element.findall("./parameters/parameter", GIR_NAMESPACES)
    full_param_list = extract_parameters(
        parameters,
        nullable_implies_optional=True,
        object_type=object_type,
        resolve_type=resolve_type,
    )
    param_list = list(all_regular_parameters(full_param_list))
    has_closure_param = any((param.get("closure") == "1" for param in parameters))

    is_async = any(
        param.type.name == "Gio.AsyncReadyCallback" for param in full_param_list
    )
    if not is_async:
        result_element = element

    finish_c_identifier = (
        result_element.get(f"{{{C_NAMESPACE}}}identifier") if is_async else None
    )

    throws = result_element.get("throws") == "1"

    return (
        c_identifier,
        finish_c_identifier,
        param_list,
        has_closure_param,
        throws,
        result_element,
    )


def extract_parameters(
    parameter_elements: List[ET.Element],
    nullable_implies_optional: bool,
    object_type: ObjectType,
    resolve_type: ResolveTypeCallback,
) -> List[Parameter]:
    entries = []
    for param in parameter_elements:
        nullable = param.get("nullable") == "1"
        entries.append((param, nullable))

    last_required_index = None
    for i, (param, nullable) in enumerate(entries):
        optional = nullable and nullable_implies_optional
        if not optional:
            last_required_index = i

    param_list = []
    for i, (param, nullable) in enumerate(entries):
        name = param.get("name")
        type = extract_type_from_entity(param, resolve_type)

        if last_required_index is None or i > last_required_index:
            optional = nullable and nullable_implies_optional
        else:
            optional = False

        ownership_val = param.get("transfer-ownership")
        transfer_ownership = (
            TransferOwnership[ownership_val]
            if ownership_val is not None
            else TransferOwnership.none
        )

        raw_direction = param.get("direction")
        direction = (
            Direction(raw_direction) if raw_direction is not None else Direction.IN
        )

        param_list.append(
            Parameter(
                name,
                type,
                optional,
                nullable,
                transfer_ownership,
                direction,
                object_type,
            )
        )
    return param_list


def all_regular_parameters(parameters: List[Parameter]) -> Iterator[Parameter]:
    callback_index = None
    for i, param in enumerate(parameters):
        if param.type.name == "Gio.AsyncReadyCallback":
            callback_index = i
            continue

        if callback_index is not None and i == callback_index + 1:
            continue

        yield param


def extract_type_from_entity(
    parent_element: ET.Element, resolve_type: ResolveTypeCallback
) -> Optional[Type]:
    child = parent_element.find("type", GIR_NAMESPACES)
    if child is None:
        child = parent_element.find("array", GIR_NAMESPACES)
        assert child is not None
        element_type = extract_type_from_entity(child, resolve_type)
        if element_type.name == "utf8":
            return Type(
                "utf8[]",
                "strv",
                "gchar **",
                "NULL",
                "g_strdupv",
                "g_strfreev",
            )
        elif element_type.name == "gchar":
            return Type("char[]", "chararray", "gchar *", "NULL", "NULL", "NULL")
        elif element_type.name == "GObject.Value":
            return Type("Value[]", "valuearray", "GValue *", "NULL", "NULL", "NULL")
        else:
            assert (
                element_type.name == "guint8"
            ), f"unsupported array type: {element_type.name}"
            return Type("uint8[]", "bytearray", "guint8 *", "NULL", "NULL", "NULL")

    return parse_type(child, resolve_type)


def parse_type(
    element: ET.Element, resolve_type: ResolveTypeCallback
) -> Optional[Type]:
    name = element.get("name")
    assert name is not None
    if name == "none":
        return None

    is_primitive = name in PRIMITIVE_GIR_TYPES
    c_type = element.get(f"{{{C_NAMESPACE}}}type")

    core_tag = None
    if is_primitive:
        type_element = element
        if c_type is None:
            c_type = name
    else:
        name, type_element = resolve_type(name)
        if type_element.tag.startswith(CORE_TAG_PREFIX):
            core_tag = type_element.tag[len(CORE_TAG_PREFIX) :]
        c_type = type_element.get(f"{{{C_NAMESPACE}}}type")
        if core_tag in {"class", "interface", "record"}:
            c_type += "*"

    nick = type_nick_from_name(name, element, resolve_type)
    c = c_type.replace("*", " *")

    default_value = "NULL" if "*" in c else None

    if name == "utf8":
        copy_func = "g_strdup"
        destroy_func = "g_free"
    elif name == "utf8[]":
        copy_func = "g_strdupv"
        destroy_func = "g_strfreev"
    elif name == "GLib.HashTable":
        copy_func = "g_hash_table_ref"
        destroy_func = "g_hash_table_unref"
    elif name == "GLib.Quark":
        copy_func = None
        destroy_func = None
    elif name == "GObject.Value":
        copy_func = "g_value_copy"
        destroy_func = "g_value_reset"
    elif name == "GObject.Closure":
        copy_func = "g_closure_ref"
        destroy_func = "g_closure_unref"
    elif core_tag in {"class", "interface"}:
        copy_func = "g_object_ref"
        destroy_func = "g_object_unref"
    elif is_primitive or core_tag in {"bitfield", "callback", "enumeration"}:
        copy_func = None
        destroy_func = None
    else:
        copy_func = type_element.get("copy-function")
        destroy_func = type_element.get("free-function")
        assert (
            destroy_func is not None
        ), f"unable to resolve destroy function for {name}, core_tag={core_tag}"

    return Type(name, nick, c, default_value, copy_func, destroy_func)


def type_nick_from_name(
    name: str, element: ET.Element, resolve_type: ResolveTypeCallback
) -> str:
    if name == "GLib.PollFD":
        return "pollfd"

    tokens = name.split(".", maxsplit=1)
    if len(tokens) == 1:
        result = tokens[0]
        if result.startswith("g"):
            result = result[1:]
    else:
        result = to_snake_case(tokens[1])

    if result == "hash_table":
        key_type = parse_type(element[0], resolve_type)
        value_type = parse_type(element[1], resolve_type)
        assert (
            key_type.name == "utf8" and value_type.name == "GLib.Variant"
        ), "only GHashTable<string, Variant> is supported for now"
        result = "vardict"

    return result


def js_type_from_gir(name: str) -> str:
    if name == "gboolean":
        return "boolean"
    if name in NUMERIC_GIR_TYPES:
        return "number"
    if name == "utf8":
        return "string"
    if name == "utf8[]":
        return "string[]"
    if name == "GLib.Bytes":
        return "Buffer"
    if name == "GLib.HashTable":
        return "VariantDict"
    if name == "GLib.Variant":
        return "any"
    if name in {"Gio.File", "Gio.TlsCertificate"}:
        return "string"
    if name.startswith("Frida.") and name.endswith("List"):
        return name[6:-4] + "[]"
    return name.split(".")[-1]


def to_snake_case(name: str) -> str:
    result = []
    i = 0
    n = len(name)
    while i < n:
        if name[i].isupper():
            if i > 0:
                result.append("_")
            start = i
            if i + 1 < n and name[i + 1].islower():
                while i + 1 < n and name[i + 1].islower():
                    i += 1
            else:
                while i + 1 < n and name[i + 1].isupper():
                    i += 1
                if i + 1 < n:
                    i -= 1
            result.append(name[start : i + 1].lower())
        else:
            result.append(name[i])
        i += 1
    return "".join(result)


def to_pascal_case(name: str) -> str:
    return "".join(word.capitalize() for word in name.split("_"))


def to_camel_case(name: str) -> str:
    words = name.split("_")
    return words[0] + "".join(word.capitalize() for word in words[1:])


def to_macro_case(identifier: str) -> str:
    result = []
    for i, char in enumerate(identifier):
        if char.isupper() and i != 0:
            result.append("_")
        result.append(char)
    return "".join(result).upper()
