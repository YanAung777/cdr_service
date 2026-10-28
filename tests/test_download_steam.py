import pytest
import json
from unittest import mock
import azure.functions as func

# Import the module under test
import importlib
function_app = importlib.import_module('function_app')

# Helper to create a fake HttpRequest
def make_request(blob_id: str, headers: dict = None):
    headers = headers or {}
    return func.HttpRequest(
        method='GET',
        url=f'http://localhost/api/download/{blob_id}',
        body=None,
        headers=headers,
        route_params={'blob_id': blob_id}
    )

# Simple fake blob property container
class FakeBlobProperties:
    def __init__(self, metadata=None):
        self.metadata = metadata or {}

class FakeStream:
    def __init__(self, chunks):
        self._chunks = chunks
    def chunks(self):
        for c in self._chunks:
            yield c

class FakeBlobClient:
    def __init__(self, exists=True, owner='owner123', content=b'hello world'):
        self._exists = exists
        self._owner = owner
        self._content = content
    def exists(self):
        return self._exists
    def get_blob_properties(self):
        return FakeBlobProperties(metadata={'owner': self._owner})
    def download_blob(self):
        # Simulate streaming in two chunks
        return FakeStream([self._content[:5], self._content[5:]])

class FakeContainerClient:
    def __init__(self, blob_client: FakeBlobClient):
        self._blob_client = blob_client
    def get_blob_client(self, blob_id):
        # ignore blob_id – return the pre‑configured fake
        return self._blob_client

class FakeBlobService:
    def __init__(self, blob_client: FakeBlobClient):
        self._blob_client = blob_client
    def get_container_client(self, container_name):
        return FakeContainerClient(self._blob_client)

# ---------------------------------------------------------------------------
# Tests for the authorization helper
# ---------------------------------------------------------------------------
def test_is_authorized_download_owner():
    assert function_app._is_authorized_download('user1', None, 'user1') is True

def test_is_authorized_download_recruiter_role():
    # Caller is not owner but has a recruiter role – should be allowed
    assert function_app._is_authorized_download('user2', 'Recruiter', 'owner123') is True

def test_is_authorized_download_forbidden():
    # No matching owner and no privileged role
    assert function_app._is_authorized_download('user2', None, 'owner123') is False

# ---------------------------------------------------------------------------
# Tests for the download endpoint – using monkeypatch to replace blob service
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_blob_client():
    return FakeBlobClient()

def test_download_success_owner(monkeypatch, fake_blob_client):
    # Patch the service getter to return our fake service
    monkeypatch.setattr(function_app, '_get_blob_service', lambda: FakeBlobService(fake_blob_client))
    # Simulate a request from the owner (no role needed)
    req = make_request('someblob', headers={'X-Ms-Client-Principal-Id': 'owner123'})
    resp = function_app.download_document(req)
    # Verify 200 OK
    assert resp.status_code == 200
    # Verify security headers are present
    assert resp.headers.get('Content-Disposition').startswith('attachment;')
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    # The body should be a generator – we can consume it to verify content
    content = b''.join(list(resp.body))
    assert content == b'hello world'

def test_download_success_recruiter(monkeypatch, fake_blob_client):
    monkeypatch.setattr(function_app, '_get_blob_service', lambda: FakeBlobService(fake_blob_client))
    req = make_request('someblob', headers={
        'X-Ms-Client-Principal-Id': 'someuser',
        'X-Ms-Client-Principal-Role': 'Recruiter'
    })
    resp = function_app.download_document(req)
    assert resp.status_code == 200
    # Owner metadata on the fake blob is "owner123", not the caller – recruiter bypasses check
    content = b''.join(list(resp.body))
    assert content == b'hello world'

def test_download_forbidden(monkeypatch, fake_blob_client):
    monkeypatch.setattr(function_app, '_get_blob_service', lambda: FakeBlobService(fake_blob_client))
    req = make_request('someblob', headers={'X-Ms-Client-Principal-Id': 'otheruser'})
    resp = function_app.download_document(req)
    assert resp.status_code == 403
    payload = json.loads(resp.get_body().decode())
    assert payload['error'] == 'Forbidden'

def test_download_not_found(monkeypatch):
    # Configure a blob client that reports non‑existence
    missing_blob = FakeBlobClient(exists=False)
    monkeypatch.setattr(function_app, '_get_blob_service', lambda: FakeBlobService(missing_blob))
    req = make_request('missing', headers={'X-Ms-Client-Principal-Id': 'owner123'})
    resp = function_app.download_document(req)
    assert resp.status_code == 404
    payload = json.loads(resp.get_body().decode())
    assert payload['error'] == 'Not found'
