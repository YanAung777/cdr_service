import importlib
import sys
import traceback

# Import the test module
test_mod = importlib.import_module('tests.test_download_stream')

# Collect test functions (those starting with 'test_')
functions = [getattr(test_mod, name) for name in dir(test_mod) if name.startswith('test_')]

failed = 0
for fn in functions:
    try:
        # If the test expects a fixture argument, we need to provide it.
        # The only fixture used is 'fake_blob_client' which is a pytest fixture.
        # We'll manually construct it.
        if 'fake_blob_client' in fn.__code__.co_varnames:
            from tests.test_download_stream import FakeBlobClient
            fn(FakeBlobClient())
        else:
            fn()
        print(f"{fn.__name__}: PASS")
    except AssertionError as e:
        failed += 1
        print(f"{fn.__name__}: FAIL – AssertionError: {e}")
    except Exception:
        failed += 1
        print(f"{fn.__name__}: FAIL – Exception")
        traceback.print_exc()

if failed:
    sys.exit(1)
else:
    print('All tests passed')
