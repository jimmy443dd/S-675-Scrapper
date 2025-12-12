# Advanced Penetration Testing Suite

A web-based automated pentesting dashboard that scans for IDOR, token leaks, batch abuse, and more.

## 🔧 Deploy on Render

1. Push to GitHub
2. Create new Web Service on [Render](https://render.com)
3. Set runtime to `Docker`
4. Set port to `3000`
5. Optionally add environment variable:
   - `TARGET_URL=https://your.target.url`

## 🛠️ Local Dev

```bash
docker build -t pentest-suite .
docker run -p 3000:3000 pentest-suite
