const fs = require("fs"), os = require("os"), path = require("path");
const key = fs.readFileSync(path.join(os.homedir(), ".ssh", "id_ed25519"), "utf8");
