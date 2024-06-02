# pprint_custom.py
from common import SUFFIX_LEN
import pprint

class CustomPrettyPrinter(pprint.PrettyPrinter):
    """
    Overrides part of the PrettyPrinter to shorten long byte strings in the object
    """
    def _format(self, object, *args, **kwargs):
        if isinstance(object, bytes):
            if len(object) > SUFFIX_LEN:
                object = object[-SUFFIX_LEN:]
        return pprint.PrettyPrinter._format(self, object, *args, **kwargs)

    def _safe_repr(self, object, context, maxlevels, level):
        # Special case when a dict is fed to this function and the dict is not lage,
        # it won't process it separate because it can basically do `repr` on each key value
        if isinstance(object, bytes) and len(object) > SUFFIX_LEN:
            object = object[-SUFFIX_LEN:]
        return pprint.PrettyPrinter._safe_repr(self, object, context, maxlevels, level)

