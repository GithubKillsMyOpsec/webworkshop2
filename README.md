# Web Workshop 2

Contains two applications.

 - A silly, intentionally insecure Flask app that shows how cookies give HTTP state. It includes a "Post Board" where someone leaks their cookie every 5 minutes.
 - Another silly insecure flask app which has an XSS vuln. The insecure nature of the cookies make them able to be stolen with XSS. 

## Run with Docker Compose (workshop + CTF)

```bash
docker compose up --build
```

Visit http://localhost:8081 for the cookie demo.
Visit http://localhost:8082 for the XSS cookie-heist challenge.

The CTF service includes a headless Firefox bot that reviews reported posts. The container
is read-only, uses a tmpfs `/tmp`, and disables downloads in the browser profile. The demo
expects players to run their own cookie collector endpoint.

