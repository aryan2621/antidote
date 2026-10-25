import os, subprocess, requests, base64

def run(path):
    return subprocess.run(["ls", "-l", path], check=True)

def call(url):
    return requests.post(url, headers={"Authorization": os.environ["API_TOKEN"]}, json={"q": 1})

with open("README.md") as f:
    readme = f.read()
data = base64.b64decode(readme)
os.system("make build")
