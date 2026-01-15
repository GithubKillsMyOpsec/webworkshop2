# Web Workshop 2

A silly, intentionally insecure Flask app that shows how cookies give HTTP state. It includes a "Post Board" where someone leaks their cookie every 5 minutes.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Visit http://localhost:8081

## Run with Docker

```bash
docker build -t webworkshop2 .
docker run --rm -p 8081:8081 webworkshop2
```

## Demo idea

1. Log in with any username/password.
2. Visit the Post Board and copy the leaked cookie value.
3. Paste it into your browser cookies as `demo_session`.
4. Refresh the Secret page to see you're logged in as the poster.

This is a teaching demo. Do not build real auth like this.
