const { execFile } = require("child_process");
const fs = require("fs");
const re = /(\d+)/;
const m = re.exec(`build ${process.argv[2]}`);
execFile("git", ["log", "-1"], (err, out) => console.log(out));
const readme = fs.readFileSync("README.md", "utf8");
fetch("https://api.example.com/v1", { headers: { Authorization: `Bearer ${process.env.API_TOKEN}` } });
console.log(eval("1 + 1"), m, readme);
