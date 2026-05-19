import datetime
import uuid

from malstruct.lib import (
    Container,
    HexDisplayedBytes,
    HexDisplayedDict,
    HexDisplayedInteger,
    HexDumpDisplayedBytes,
    HexDumpDisplayedDict,
)

from .bytes_ import Bytes
from .core import Adapter, Construct
from .exceptions import *
from .integers import BitsInteger, BytesInteger, Int16ub, Int32ul, Int64sl
from .transforms import BitStruct


class TimestampAdapter(Adapter):
    """Used internally."""


def Timestamp(subcon, unit, epoch):
    r"""
    Datetime, represented as `Arrow <https://pypi.org/project/arrow/>`_ object.

    Note that accuracy is not guaranteed, because building rounds the value to integer (even when Float subcon is used), due to floating-point errors in general, and because MSDOS scheme has only 5-bit (32 values) seconds field (seconds are rounded to multiple of 2).

    Unit is a fraction of a second. 1 is second resolution, 10**-3 is milliseconds resolution, 10**-6 is microseconds resolution, etc. Usually its 1 on Unix and MacOSX, 10**-7 on Windows. Epoch is a year (if integer) or a specific day (if Arrow object). Usually its 1970 on Unix, 1904 on MacOSX, 1600 on Windows. MSDOS format doesnt support custom unit or epoch, it uses 2-seconds resolution and 1980 epoch.

    :param subcon: Construct instance like Int* Float*, or Int32ub with msdos format
    :param unit: integer or float, or msdos string
    :param epoch: integer, or Arrow instance, or msdos string

    :raises ImportError: arrow could not be imported during ctor
    :raises TimestampError: subcon is not a Construct instance
    :raises TimestampError: unit or epoch is a wrong type

    Example::

        >>> d = Timestamp(Int64ub, 1., 1970)
        >>> d.parse(b'\x00\x00\x00\x00ZIz\x00')
        <Arrow [2018-01-01T00:00:00+00:00]>
        >>> d = Timestamp(Int32ub, "msdos", "msdos")
        >>> d.parse(b'H9\x8c"')
        <Arrow [2016-01-25T17:33:04+00:00]>
    """
    import arrow

    if not isinstance(subcon, Construct):
        raise TimestampError(
            "subcon should be Int*, experimentally Float*, or Int32ub when using msdos format"
        )
    if not isinstance(unit, (int, float, str)):
        raise TimestampError("unit must be one of: int float string")
    if not isinstance(epoch, (int, arrow.Arrow, str)):
        raise TimestampError("epoch must be one of: int Arrow string")

    if unit == "msdos" or epoch == "msdos":
        st = BitStruct(
            "year" / BitsInteger(7),
            "month" / BitsInteger(4),
            "day" / BitsInteger(5),
            "hour" / BitsInteger(5),
            "minute" / BitsInteger(6),
            "second" / BitsInteger(5),
        )

        class MsdosTimestampAdapter(TimestampAdapter):
            def _decode(self, obj, context, path):
                return arrow.Arrow(1980, 1, 1).shift(
                    years=obj.year,
                    months=obj.month - 1,
                    days=obj.day - 1,
                    hours=obj.hour,
                    minutes=obj.minute,
                    seconds=obj.second * 2,
                )

            def _encode(self, obj, context, path):
                t = obj.timetuple()
                return Container(
                    year=t.tm_year - 1980,
                    month=t.tm_mon,
                    day=t.tm_mday,
                    hour=t.tm_hour,
                    minute=t.tm_min,
                    second=t.tm_sec // 2,
                )

        macro = MsdosTimestampAdapter(st)

    else:
        if isinstance(epoch, int):
            epoch = arrow.Arrow(epoch, 1, 1)

        class EpochTimestampAdapter(TimestampAdapter):
            def _decode(self, obj, context, path):
                return epoch.shift(seconds=obj * unit)

            def _encode(self, obj, context, path):
                return int((obj - epoch).total_seconds() / unit)

        macro = EpochTimestampAdapter(subcon)

    return macro


# TODO: Implement _encode.
class _DateTimeDateDataAdapter(Adapter):
    r"""
    Adapter for a C# DateTime.dateData object to DateTime format. Obtain the DateTime.Ticks and the DateTime.Kind
    property to format datetime.

    Example::

        >>> _DateTimeDateDataAdapter(Int64sl).parse(b'\x80\xb4N3\xd1\xd4\xd1H')
        '2014-11-23 01:09:01 UTC'
    """

    def _decode(self, obj, context, path):
        ticks = obj & 0x3FFFFFFFFFFFFFFF
        kind = (obj >> 62) & 0x03
        converted_ticks = datetime.datetime(1, 1, 1) + datetime.timedelta(
            microseconds=ticks / 10
        )
        if kind == 0:
            return converted_ticks.strftime("%Y-%m-%d %H:%M:%S")
        elif kind == 1:
            return converted_ticks.strftime("%Y-%m-%d %H:%M:%S UTC")
        elif kind == 2:
            return converted_ticks.strftime("%Y-%m-%d %H:%M:%S Local")


DateTimeDateData = _DateTimeDateDataAdapter(Int64sl)


# TODO: Implement _encode
class EpochTimeAdapter(Adapter):
    r"""
    Adapter to convert time_t, EpochTime, to an isoformat

    Example::

        >>> EpochTimeAdapter(Int32ul, tz=datetime.timezone.utc).parse(b'\xff\x93\x37\x57')
        '2016-05-14T21:09:19+00:00'
        >>> EpochTimeAdapter(Int32ul).parse(b'\xff\x93\x37\x57')
        '2016-05-14T17:09:19'
    """

    def __init__(self, subcon, tz=None):
        """
        :param tz: Optional timezone object, default is localtime
        :param subcon: subcon to parse EpochTime.
        """
        super().__init__(subcon)
        self._tz = tz

    def _decode(self, obj, context, path):
        try:
            return datetime.datetime.fromtimestamp(obj, tz=self._tz).isoformat()
        except OSError as e:
            raise ConstructError(e)


# Add common helpers
EpochTime = EpochTimeAdapter(Int32ul)
EpochTimeUTC = EpochTimeAdapter(Int32ul, tz=datetime.timezone.utc)


class Hex(Adapter):
    r"""
    Adapter for displaying hexadecimal/hexlified representation of integers/bytes/RawCopy dictionaries.

    Parsing results in int-alike bytes-alike or dict-alike object, whose only difference from original is pretty-printing. If you look at the result, you will be presented with its `repr` which remains as-is. If you print it, then you will see its `str` whic is a hexlified representation. Building and sizeof defer to subcon.

    To obtain a hexlified string (like before Hex HexDump changed semantics) use binascii.(un)hexlify on parsed results.

    Example::

        >>> d = Hex(Int32ub)
        >>> obj = d.parse(b"\x00\x00\x01\x02")
        >>> obj
        258
        >>> print(obj)
        0x00000102

        >>> d = Hex(GreedyBytes)
        >>> obj = d.parse(b"\x00\x00\x01\x02")
        >>> obj
        b'\x00\x00\x01\x02'
        >>> print(obj)
        unhexlify('00000102')

        >>> d = Hex(RawCopy(Int32ub))
        >>> obj = d.parse(b"\x00\x00\x01\x02")
        >>> obj
        {'data': b'\x00\x00\x01\x02',
         'length': 4,
         'offset1': 0,
         'offset2': 4,
         'value': 258}
        >>> print(obj)
        unhexlify('00000102')
    """

    def _decode(self, obj, context, path):
        if isinstance(obj, int):
            return HexDisplayedInteger.new(
                obj, "0%sX" % (2 * self.subcon._sizeof(context, path))
            )
        if isinstance(obj, bytes):
            return HexDisplayedBytes(obj)
        if isinstance(obj, dict):
            return HexDisplayedDict(obj)
        return obj

    def _encode(self, obj, context, path):
        return obj


class HexDump(Adapter):
    r"""
    Adapter for displaying hexlified representation of bytes/RawCopy dictionaries.

    Parsing results in bytes-alike or dict-alike object, whose only difference from original is pretty-printing. If you look at the result, you will be presented with its `repr` which remains as-is. If you print it, then you will see its `str` whic is a hexlified representation. Building and sizeof defer to subcon.

    To obtain a hexlified string (like before Hex HexDump changed semantics) use malstruct.lib.hexdump on parsed results.

    Example::

        >>> d = HexDump(GreedyBytes)
        >>> obj = d.parse(b"\x00\x00\x01\x02")
        >>> obj
        b'\x00\x00\x01\x02'
        >>> print(obj)
        hexundump('''
        0000   00 00 01 02                                       ....
        ''')

        >>> d = HexDump(RawCopy(Int32ub))
        >>> obj = d.parse(b"\x00\x00\x01\x02")
        >>> obj
        {'data': b'\x00\x00\x01\x02',
         'length': 4,
         'offset1': 0,
         'offset2': 4,
         'value': 258}
        >>> print(obj)
        hexundump('''
        0000   00 00 01 02                                       ....
        ''')
    """

    def _decode(self, obj, context, path):
        if isinstance(obj, bytes):
            return HexDumpDisplayedBytes(obj)
        if isinstance(obj, dict):
            return HexDumpDisplayedDict(obj)
        return obj

    def _encode(self, obj, context, path):
        return obj


class HexString(Adapter):
    r"""
    Adapter used to convert an int into a hex string equivalent.

    Example::

        >>> HexString(Int32ul).build('0x123')
        b'#\x01\x00\x00'
        >>> HexString(Int32ul).parse(b'\x20\x01\x00\x00')
        '0x120'
        >>> HexString(Int16ub).parse(b'\x12\x34')
        '0x1234'
        >>> HexString(BytesInteger(20)).parse(b'\x01' * 20)
        '0x101010101010101010101010101010101010101'
    """

    def _encode(self, obj, context, path):
        return int(obj, 16)

    def _decode(self, obj, context, path):
        hex_string = hex(obj)
        if hex_string.endswith("L"):
            hex_string = hex_string[:-1]
        return hex_string


class UUIDAdapter(Adapter):
    r"""
    Adapter used to convert parsed bytes to a string representing the UUID.
    Adapter can decode 16 bytes straight or in little-endian order if you set le=True.

    Example::

        >>> UUIDAdapter(Bytes(16)).build('{12345678-1234-5678-1234-567812345678}')
        b'xV4\x124\x12xV\x124Vx\x124Vx'
        >>> UUIDAdapter(Bytes(16), le=False).build('{12345678-1234-5678-1234-567812345678}')
        b'\x124Vx\x124Vx\x124Vx\x124Vx'
        >>> UUIDAdapter(Bytes(16)).parse(b'xV4\x124\x12xV\x124Vx\x124Vx')
        '{12345678-1234-5678-1234-567812345678}'
    """

    def __init__(self, subcon, le=True):
        super().__init__(subcon)
        self.le = le

    def _encode(self, obj, context, path):
        obj = uuid.UUID(obj)
        if self.le:
            return obj.bytes_le
        else:
            return obj.bytes

    def _decode(self, obj, context, path):
        if self.le:
            _uuid = uuid.UUID(bytes_le=obj)
        else:
            _uuid = uuid.UUID(bytes=obj)
        return "{" + str(_uuid) + "}"


def UUID(le=True):
    r"""A convenience function for using the UUIDAdapter with 16 bytes.

    :param le: Whether to use "bytes_le" or "bytes" when constructing the UUID.

    Example::

        >>> UUID().build('{12345678-1234-5678-1234-567812345678}')
        b'xV4\x124\x12xV\x124Vx\x124Vx'
        >>> UUID(le=False).build('{12345678-1234-5678-1234-567812345678}')
        b'\x124Vx\x124Vx\x124Vx\x124Vx'
        >>> UUID().parse(b'xV4\x124\x12xV\x124Vx\x124Vx')
        '{12345678-1234-5678-1234-567812345678}'
        >>> UUID(le=False).parse(b'\x124Vx\x124Vx\x124Vx\x124Vx')
        '{12345678-1234-5678-1234-567812345678}'
    """
    return UUIDAdapter(Bytes(16), le=le)
