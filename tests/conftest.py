import pytest

from malstruct import SizeofError


@pytest.fixture()
def raises():
    def _raises(func, *args, **kw):
        try:
            return func(*args, **kw)
        except Exception as e:
            return e.__class__

    return _raises


@pytest.fixture()
def common(raises):
    """
    Common test function
    """

    def _common(fmt, datasample, objsample, sizesample=SizeofError, **kw):
        # following are implied (re-parse and re-build)
        # assert fmt.parse(fmt.build(obj)) == obj
        # assert fmt.build(fmt.parse(data)) == data
        obj = fmt.parse(datasample, **kw)
        assert obj == objsample
        data = fmt.build(objsample, **kw)
        assert data == datasample

        if isinstance(sizesample, int):
            size = fmt.sizeof(**kw)
            assert size == sizesample
        else:
            size = raises(fmt.sizeof, **kw)
            assert size == sizesample

    return _common
