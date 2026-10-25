const { exec } = require("child_process");
module.exports = (host) => exec(`ping -c 1 ${host}`);
