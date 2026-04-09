Changelog
=========

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_\ ,

2.10.71
------

Changed
^^^^^^^
- Reverted default behavior changed by https://github.com/construct/construct/pull/1015
    - OffsettedEnd, Prefixed, FixedSize, NullTerminated, NullStriped, ProcessXor use offsets relative to the last occurrence of these subconstructs
    - To use offsets relative to the beginning of the stream set `absolute=True` when constructing these constructs
- Moved optional dependencies to required dependencies
