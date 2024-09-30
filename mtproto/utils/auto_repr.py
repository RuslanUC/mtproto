from reprlib import recursive_repr


class AutoRepr:
    @recursive_repr()
    def __repr__(self) -> str:  # pragma: no cover
        cls = self.__class__
        add_fields = getattr(cls, "AUTOREPR_ADD_FIELDS", [])
        exclude_fields = set(getattr(cls, "AUTOREPR_EXCLUDE_FIELDS", []))

        fields_names = set(getattr(cls, "__slots__", self.__dict__.keys()))
        fields_names.update(*add_fields)
        fields_names.difference_update(*exclude_fields)

        fields = ", ".join([
            f"{name}={getattr(self, name, None)!r}"
            for name in fields_names
        ])

        return f"{cls.__name__}({fields})"
