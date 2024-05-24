from common import SUFFIX_LEN
import pprint

class CustomPrettyPrinter(pprint.PrettyPrinter):
    """
    Overrides part of the PrettyPrinter to shorten long strings in the object
    """
    def _format(self, object, *args, **kwargs):
        if isinstance(object, bytes):
            if len(object) > SUFFIX_LEN:
                object = object[-SUFFIX_LEN:]
        return pprint.PrettyPrinter._format(self, object, *args, **kwargs)

