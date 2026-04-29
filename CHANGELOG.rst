Changelog
=========

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_\ ,
and this project adheres to `Calendar Versioning <https://calver.org/>`_ with the schema MAJOR.MINOR.YYYY0M0D.


3.0.20260429 - 2026-04-29
-------------------------

Changed
^^^^^^^
- Split out `core` functionality across `adapters`, `alignment`, `analysis`, `bytes_`, `conditional`, `exceptions`, `expr`, `helpers`, `integers`, `lazy`, `mappings`, `miscellaneous`, `stream`, `strings`, and `transforms`
- Moved binary file analysis to `malstruct.binaryfiles`
- Moved remaining `malstruct.utils` functionality to base level
- Added `pecon` utility as an installed package
- Move from "flat" layout to "src" layout
- Use `pyproject.toml` configuration file for packaging

Removed
^^^^^^^
- Removed usage of `__all__` in init
- Removed usage of compilation feature and benchmarks
- Removed `py3compat` functionality
- Removed `pefileutils` and `elffileutils`
- Removed functionality from `machoutils` unrelated to malstructs/adapters


2.10.71
-------

Changed
^^^^^^^
- Reverted default behavior changed by https://github.com/construct/construct/pull/1015
    - OffsettedEnd, Prefixed, FixedSize, NullTerminated, NullStriped, ProcessXor use offsets relative to the last occurrence of these subconstructs
    - To use offsets relative to the beginning of the stream set `absolute=True` when constructing these constructs
- Moved optional dependencies to required dependencies
