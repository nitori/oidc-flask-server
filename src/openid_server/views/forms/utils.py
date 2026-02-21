from wtforms import TextAreaField, FileField
from flask_wtf.file import FileSize, FileAllowed


def strip_filter(text: str | None) -> str:
    return text if text is None else text.strip()


def text_to_lines(text: str | list[str] | None) -> list[str]:
    if isinstance(text, list):
        return text
    if isinstance(text, str):
        lines = text.splitlines()
        return [line.strip() for line in lines if line and line.strip()]
    return []


class TextAreaListField(TextAreaField):
    """Same as TextAreaField, just used to output a list of strings"""

    def __init__(self, *args, **kwargs):
        filters = kwargs.get("filters", [])[:]
        filters.append(text_to_lines)
        kwargs["filters"] = filters
        super().__init__(*args, **kwargs)

    def _value(self):
        if isinstance(self.data, (list, tuple)):
            return "\n".join(map(str, self.data))
        return str(self.data) if self.data is not None else ""


class WrappedFileField(FileField):
    @property
    def max_file_size(self) -> int | None:
        return next(
            (v.max_size for v in self.validators if isinstance(v, FileSize)), None
        )

    @property
    def extensions_allowed(self) -> list[str] | None:
        upload_set = next(
            (v.upload_set for v in self.validators if isinstance(v, FileAllowed)), None
        )
        return upload_set
