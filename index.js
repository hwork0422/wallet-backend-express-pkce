


// Dependencies
const fs = require("fs");
const http = require("http");
const https = require("https");
const express = require("express");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const util = require("./util");
const alchemy = require("./alchemy");
dotenv.config();

const hashSchema = mongoose.Schema({
  pkce_challenge: String,
  eth_address: String,
  public_key: String,
});
const metadataSchema = mongoose.Schema({
  hash_type: String,
  eth_address: String,
  public_key_encoded: String,
  imei: String,
  iccid: String,
});
const relayerSchema = mongoose.Schema({
  numTransaction: Number,
  eth_address: String,
  public_key_encoded: String,
  imei: String,
  iccid: String,
  pkce_challenge: String,
});

// const temp = async () => {
//   console.log('1')
//   // const issue = await util.isTransactionSuccessFromGoerli('0x25cd3c4dd3f6fef1e0a87441d8edfb2a9b6321e755f6ff0231303942d559ab60');
//   const isS = await util.signTransactionFromGoerli(13);
//   console.log(isS);
//   console.log('2')
// }
// temp();

const Hash = mongoose.model("Hash", hashSchema);
const Metadata = mongoose.model("Metadata", metadataSchema);
const Relayer = mongoose.model("Relayer", relayerSchema);

const app = express();

// // Certificate
// const privateKey = fs.readFileSync('/etc/letsencrypt/live/api.blockauthy.io/privkey.pem', 'utf8');
// const certificate = fs.readFileSync('/etc/letsencrypt/live/api.blockauthy.io/cert.pem', 'utf8');
// const ca = fs.readFileSync('/etc/letsencrypt/live/api.blockauthy.io/chain.pem', 'utf8');

// const credentials = {
// 	key: privateKey,
// 	cert: certificate,
// 	ca: ca
// };

// // Starting both http & https servers
// const httpServer = http.createServer(app);
// const httpsServer = https.createServer(credentials, app);

// httpServer.listen(80, () => {
// 	console.log('HTTP Server running on port 80');
// });

// httpsServer.listen(443, () => {
// 	console.log('HTTPS Server running on port 443');
// });

app.enable("trust proxy");
app.use((req, res, next) => {
  req.secure ? next() : res.redirect("https://" + req.headers.host + req.url);
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies
//universal routes

app.get("/", function (req, response) {
  response.json("Welcome to BlockAuthy!");
});
app.post("/token", function (req, response) {
  if (req.body.data) {
    const token = util.generateAccessToken(req.body.public_key, req.body.data);
    response.json({ status: true, data: token });
  } else {
    response.status(500).json("Check your format");
  }
});
// //middleware
// app.use(authenticateToken);

app.post("/challenge/:tx_hash&:pkce_challenge", async function (req, response) {
  if (!req.params.tx_hash || !req.params.pkce_challenge) {
    return response
      .status(500)
      .json({ status: false, data: "Missing Parameters" });
  }
  const { tx_hash, pkce_challenge } = req.params;
  const eth_address = await util.isTransactionSuccessFromGoerli(tx_hash);
  if (eth_address == "pending") {
    return response
      .status(204)
      .json({ status: false, data: "Transaction is pending yet" });
  }
  if (eth_address) {
    const { eth_address, public_key } = req.body;
    if (!eth_address || !public_key) {
      return response
        .status(500)
        .json({ status: false, data: "Missing Parameters" });
    }
    const public_key_from_api = public_key;
    const public_key_from_contract =
      await util.getPublicKeyFromContractFromGoerli(eth_address);
    if (public_key_from_api === public_key_from_contract) {
      Hash.findOne(
        { eth_address: eth_address.toLowerCase() },
        function (err, res) {
          if (res) {
            Hash.updateOne(
              { eth_address },
              { pkce_challenge, eth_address, public_key },
              function (err, res) {
                if (err) {
                  return response.status(500).json({
                    status: false,
                    data: "Find data from DB but can't update value.",
                  });
                } else {
                  return response.json({
                    status: true,
                    data: "Find data from DB and Update Successfully.",
                  });
                }
              }
            );
          } else {
            const newHash = new Hash({
              pkce_challenge,
              eth_address,
              public_key,
            });
            newHash.save(function (err, _Hash) {
              if (err) {
                return response
                  .status(500)
                  .json({
                    status: false,
                    data: "Can't save information to db!",
                  });
              } else {
                return response.json({
                  status: true,
                  data: "Success to save data!",
                });
              }
            });
          }
        }
      );
    } else {
      return response
        .status(500)
        .json({ status: false, data: "Wrong public key data!" });
    }
  } else {
    return response.status(500).json({
      status: false,
      data: "Can't find eth address from transaction!.",
    });
  }
});

app.post("/verifier/:pkce_verifier", async function (req, response) {
  if (!req.params.pkce_verifier) {
    return response
      .status(500)
      .json({ status: false, data: "Missing parameter." });
  }
  const { pkce_verifier } = req.params;
  const pkce_challenge = util.getCodeChallenge(pkce_verifier);
  const { payload } = req.body;

  if (!payload) {
    return response
      .status(500)
      .json({ status: false, data: "Missing payload." });
  }
  Hash.findOne({ pkce_challenge: pkce_challenge }, async function (err, res) {
    if (!res) {
      return response
        .status(false)
        .json("Can't find relevant challenge from DB.");
    } else {
      const { eth_address, public_key } = res;
      const data = await util.authenticateToken(public_key, payload);
      if (data) {
        const eth_address_from_jwt = data.eth_address;
        const public_key_from_jwt = data.public_key;
        const hash_type = data.hash_type;
        const imei = data.imei;
        const iccid = data.iccid;
        if (
          eth_address_from_jwt.toLowerCase() == eth_address.toLowerCase() &&
          public_key_from_jwt == public_key
        ) {
          const newMetadata = new Metadata({
            hash_type,
            eth_address,
            public_key_encoded: public_key,
            imei,
            iccid,
          });
          newMetadata.save(function (err, _metadata) {
            if (err) {
              return response
                .status(500)
                .json({ status: false, data: "Failed to save metadata!" });
            } else {
              return response.json({
                status: true,
                data: "Success to save metadata",
              });
            }
          });
        } else {
          return response
            .status(500)
            .json({ status: false, data: "Two values are not same." });
        }
      } else {
        return response.status(500).json({
          status: true,
          data: "Failed to get jwt payload from public key",
        });
      }
    }
  });
});

app.post("/relayer/:tx_hash&:pkce_challenge", async function (req, response) {
  if (!req.params.tx_hash || !req.params.pkce_challenge) {
    return response
      .status(500)
      .json({ status: false, data: "Missing parameters." });
  }
  const { payload } = req.body;
  if (!payload) {
    return response
      .status(500)
      .json({ status: false, data: "Missing payload." });
  }
  const { tx_hash, pkce_challenge } = req.params;
  const eth_address = await util.isTransactionSuccessFromGoerli(tx_hash);
  if (eth_address == "pending") {
    return response
      .status(204)
      .json({ status: false, data: "Transaction is pending yet" });
  }
  console.log({ eth_address, tx_hash });
  if (eth_address) {
    Metadata.findOne(
      { eth_address: eth_address.toLowerCase() },
      async function (err, res) {
        console.log(err, res);
        if (!res) {
          return response.status(500).json({
            status: false,
            data: "Can't find relevant meta data from DB.",
          });
        }
        const { public_key_encoded } = res;
        if (public_key_encoded) {
          const data = await util.authenticateToken(
            public_key_encoded,
            payload
          );
          const { numTransaction } = data;
          const newRelayer = new Relayer({
            numTransaction,
            eth_address,
            public_key_encoded,
            pkce_challenge,
          });
          newRelayer.save(function (err, _relayer) {
            if (err) {
              return response.status(500).json({
                status: false,
                data: "Failed to save relayer data to DB.",
              });
            }
            return response.json({
              status: true,
              data: "Success to save data to DB",
            });
          });
        } else {
          return response.status(500).json({
            status: false,
            data: "No public key data for this address.",
          });
        }
      }
    );
  } else {
    return response
      .status(500)
      .json({ status: false, data: "Can't get eth address." });
  }
});

app.post("/sign/:pkce_verifier", async function (req, response) {
  const { pkce_verifier } = req.params;
  const { payload } = req.body;
  if (!pkce_verifier) {
    return response
      .status(500)
      .json({ status: false, data: "Missing parameter." });
  }
  if (!payload) {
    return response
      .status(500)
      .json({ status: false, data: "Missing payload." });
  }
  const pkce_challenge = util.getCodeChallenge(pkce_verifier);
  Relayer.findOne({ pkce_challenge }, async function (err, res) {
    if (!res) {
      return response
        .status(500)
        .json({ status: false, data: "Not found data from DB." });
    }
    const { public_key_encoded, numTransaction } = res;
    const data = await util.authenticateToken(public_key_encoded, payload);
    const { imei, iccid } = data;
    Metadata.findOne(
      { imei, iccid, public_key_encoded },
      async function (err, metadata) {
        if (metadata) {
          console.log(numTransaction);
          const isSuccess = await util.signTransactionFromGoerli(
            numTransaction
          );
          if (isSuccess) {
            return response.json({
              status: true,
              data: "Success to sign transaction",
            });
          } else {
            return response
              .status(500)
              .json({ status: false, data: "Failed to sign transaction" });
          }
        } else {
          return response
            .status(500)
            .json({ status: false, data: "Can't find data from DB." });
        }
      }
    );
  });
});

app.post(
  "/gettransaction/:address&:network_type",
  async function (req, response) {
    const { address, network_type } = req.params;
    if (!address || util.isValidAddress(address)) {
      return response
        .status(500)
        .json({ status: false, data: "Invalid address" });
    }
    if (
      !network_type ||
      (network_type != "mainnet" && network_type != "goerli")
    ) {
      return response
        .status(500)
        .json({ status: false, data: "Invalid address" });
    }
    if (network_type == "mainnet") {
      const transactions = await util.getPublicKeyFromContractFromMain(address);
      return response.status(500).json({ status: true, data: transactions });
    } else if (network_type == "goerli") {
      const transactions = await util.getPublicKeyFromContractFromGoerli(address);
      return response.status(500).json({ status: true, data: transactions });
    } else {
      return response.status(500).json({ status: false });
    }
  }
);

const server = app.listen(8000, function () {
  const host = server.address().address;
  const port = server.address().port;
  console.log("App listening at http://%s:%s", host, port);
});

mongoose
  .connect("mongodb://localhost/hash_data")
  .then((e) => console.log("Mongo DB connected"))
  .catch((e) => console.log(e));
