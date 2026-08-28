import os
import sys
import pytest
from pathlib import Path

# Insert parent dir so we can import target_app.app
sys.path.insert(0, str(Path(__file__).parent.parent))

from target_app.app import app, init_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        init_db()
        yield client

def test_user_route(client):
    response = client.get("/user?username=alice")
    assert response.status_code == 200
    assert b"alice" in response.data

def test_ping_route(client):
    response = client.get("/ping?host=127.0.0.1")
    assert response.status_code == 200

def test_file_route(client):
    response = client.get("/file?name=readme.txt")
    assert response.status_code == 200
    assert b"Sample readme file" in response.data

def test_admin_route_success(client):
    # If the app is patched, it relies on os.environ["ADMIN_SECRET"]
    # If it's unpatched, it expects "test_secret_for_differential_replay"
    import target_app.app
    key = getattr(target_app.app, "ADMIN_SECRET", None) or "test_secret_for_differential_replay"
    
    response = client.get(f"/admin?key={key}")
    assert response.status_code == 200
    assert b"Welcome, admin!" in response.data

def test_admin_route_failure(client):
    response = client.get("/admin?key=wrong_secret")
    assert response.status_code == 403
    assert b"denied" in response.data
