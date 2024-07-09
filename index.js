const fs = require("fs");
const os = require("os");
const express = require("express");
const app = express()
const Encryptor = require("./encryptor");
const encryptor = new Encryptor();
const port = 4010;
const bodyParser = require('body-parser')

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

app.post("/change", (req, res) => {
    const body = req.body;
    try {
        setEnvValue("NGO_URLDB_API", body.user_pass);
        res.status(200).send({message: "Success To Change Username"})
    } catch (error) {
        console.log(error);
        res.status(500).send(error);        
    }
});

app.listen(port, () => {
    console.log("Server Is Running On:", port);
})

