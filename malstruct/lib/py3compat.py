import sys
import platform

PY = sys.version_info[:2]
PYPY = '__pypy__' in sys.builtin_module_names
ONWINDOWS = platform.system() == "Windows"

INT2BYTE_CACHE = {i: bytes([i]) for i in range(256)}

# these 2 function probably should be moved to malstruct.lib.binary
def int2byte(character: int) -> bytes:
    """Converts integer in range 0..255 into 1-byte string."""
    return INT2BYTE_CACHE[character]


def byte2int(character: bytes) -> int:
    """Converts 1-byte string into integer in range 0..255."""
    return character[0]

# these 2 probably should be inlined where they are used
def str2bytes(string: str) -> bytes:
    """Converts '...' string into b'...' string. On PY2 they are equivalent. On PY3 its utf8 encoded."""
    return string.encode("utf8")


def bytes2str(string: bytes) -> str:
    """Converts b'...' string into '...' string. On PY2 they are equivalent. On PY3 its utf8 decoded."""
    return string.decode("utf8")

# Deprecated, kept for backwards compatibility:
PY2 = False
PY3 = True
stringtypes = (bytes, str)
integertypes = (int,)
unicodestringtype = str
bytestringtype = bytes
reprstring = repr
integers2bytes = bytes
bytes2integers = list

def trimstring(data: 'str | bytes') -> str:
    """Trims b- u- prefix"""
    return repr(data).lstrip('b')
