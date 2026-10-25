import subprocess
def lookup(name):
    return subprocess.check_output(f"whois {name}", shell=True)
