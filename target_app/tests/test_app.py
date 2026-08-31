import os
import sys
import pytest
from pathlib import Path

# Insert parent dir so we can import target_app.app
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from target_app.app import app, init_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        init_db()
        yield client

def test_user_route(client):
    response = client.get("/search?username=admin")
    assert response.status_code == 200
    assert b"admin" in response.data

def test_ping_route(client):
    response = client.get("/ping?host=127.0.0.1")
    assert response.status_code == 200

def test_file_route(client, tmp_path):
    import os
    from pathlib import Path
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    readme = data_dir / "readme.txt"
    readme.write_text("Sample readme file")
    
    response = client.get("/read?name=readme.txt")
    assert b"Sample readme file" in response.data

def test_admin_route_success(client):
    import os
    os.environ["ADMIN_SECRET"] = "test_secret_for_differential_replay"
    key = "test_secret_for_differential_replay"
    
    response = client.get(f"/admin?key={key}")
    assert response.status_code == 200
    assert b"Admin access granted!" in response.data

def test_admin_route_failure(client):
    response = client.get("/admin?key=wrong_secret")
    assert response.status_code == 403
    assert b"denied" in response.data
