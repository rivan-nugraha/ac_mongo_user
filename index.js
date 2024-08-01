const fs = require("fs");
const os = require("os");
const express = require("express");
const app = express()
const Encryptor = require("./encryptor");
const dotenv = require('dotenv');
const encryptor = new Encryptor();
const port = process.env.PORT;
const bodyParser = require('body-parser');

dotenv.config();

const token_access = process.env.TOKEN_ACCESS;
app.use(bodyParser.json()) // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true }))

const data = require('./path.json');

const readEnvVars = (path) => fs.readFileSync(path, "utf-8").split(os.EOL);

const setEnvValue = (key, value) => {
    for (const way of data.backendPath) {
        const envVars = readEnvVars(way);
        const targetLine = envVars.find((line) => line.split("=")[0] === key);
        if (targetLine !== undefined) {
          const targetLineIndex = envVars.indexOf(targetLine);
          const decrypted = encryptor.doDecrypt(targetLine.split("=")[1])
          const result = changeUserPasswordMongo(decrypted, value)
          const encrypted = encryptor.doEncrypt(result)
          envVars.splice(targetLineIndex, 1, `${key}=${encrypted}`);
        } else {
            envVars.push(`${key}=${value}`);
        }
        fs.writeFileSync(way, envVars.join(os.EOL));
    }
};

const changeUserPasswordMongo = (mongoUrl, userPassword) => {
    const clusterAndDBName = mongoUrl.slice(mongoUrl.indexOf("@"), mongoUrl.length);
    return "mongodb+srv://" + userPassword + clusterAndDBName;
}

const tokenChecker = (token) => {
    if (!token) {
        throw new Error("Token Is Required");
    }

    if (encryptor.doDecrypt(token) !== token_access) {
        throw new Error("Wrong Token");
    }
}

app.post("/change", (req, res) => {
    const token = req.headers["token"];
    const body = req.body;
    try {
        tokenChecker(token);
        setEnvValue("NGO_URLDB_API", body.user_pass);
        res.status(200).send({message: "Success To Change Username"})
    } catch (error) {
        res.status(500).send({message: error.message});
    }
});

app.listen(port, () => {
    console.log("Server Is Running On:", port);
})

