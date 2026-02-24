from hello import app

def test_home_route():
    with app.test_client() as c:
        response = c.get("/")
        assert response.data == b"<p>Hello, World!</p>"
        assert response.status_code == 200