import aws from "aws-sdk";
import * as asn1 from "asn1.js";
import * as ethutil from "ethereumjs-util";
// import { Transaction, TxData } from "ethereumjs-tx";
import BN from "bn.js";
import { keccak256 } from "js-sha3";

export const credentials = {
  iam: {
    accessKeyId: process.env.IAM_accessKeyId, //credentials for your IAM user
    secretAccessKey: process.env.IAM_secretAccessKey, //credentials for your IAM user
    region: process.env.IAM_region,
  },
  KeyId: process.env.KMS_KeyId,
};

export const generators = {
  kmsEncryptParams: function (buffer) {
    return {
      KeyId: credentials.KeyId, // The identifier of the CMK to use for encryption. You can use the key ID or Amazon Resource Name (ARN) of the CMK, or the name or ARN of an alias that refers to the CMK.
      Plaintext: buffer,
    }; // The data to encrypt.
  },
  kmsSignParams: function (buffer) {
    return {
      KeyId: credentials.KeyId, // The identifier of the CMK to use for encryption. You can use the key ID or Amazon Resource Name (ARN) of the CMK, or the name or ARN of an alias that refers to the CMK.
      Message: buffer, // The data to encrypt.
      // 'ECDSA_SHA_256' is the one compatible with ECC_SECG_P256K1.
      SigningAlgorithm: "ECDSA_SHA_256",
      MessageType: "DIGEST",
    };
  },
  getKMS: function () {
    return new aws.KMS(credentials.iam);
  },
};

export const KMS = generators.getKMS();

const ecdsa = {
  pubkey_parse: asn1.define("EcdsaPubKey", function (this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj(
      this.key("algo").seq().obj(this.key("a").objid(), this.key("b").objid()),
      this.key("pubKey").bitstr()
    );
  }),
  asn_pase: asn1.define("EcdsaSig", function (this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
    this.seq().obj(this.key("r").int(), this.key("s").int());
  }),
};

export const methods = {
  enc_dec: {
    encrypt: function (buffer: any) {
      return new Promise((resolve, reject) => {
        const params = generators.kmsEncryptParams(buffer);
        KMS.encrypt(params, (err: any, data: any) => {
          if (err) {
            reject(err);
          } else {
            resolve(data.CiphertextBlob);
          }
        });
      });
    },
    decrypt: function (buffer) {
      return new Promise((resolve, reject) => {
        const params = {
          CiphertextBlob: buffer, // The data to dencrypt.
        };
        KMS.decrypt(params, (err, data) => {
          if (err) {
            reject(err);
          } else {
            resolve(data.Plaintext);
          }
        });
      });
    },
  },
  sign: function (buffer: Buffer) {
    return new Promise((resolve, reject) => {
      const params = generators.kmsSignParams(buffer);
      // console.log(params);
      KMS.sign(params, (err: any, data: any) => {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    });
  },
  getPublicKey: function () {
    return KMS.getPublicKey({
      KeyId: credentials.KeyId,
    }).promise();
  },
  sign_rs: async function (buffer: Buffer) {
    let signature = await this.sign(buffer);
    if (signature["Signature"] == undefined) {
      throw new Error("Signature is undefined.");
    }

    let decoded = ecdsa.asn_pase.decode(signature["Signature"], "der");
    let r = decoded.r;
    let s = decoded.s;

    let secp256k1N = new BN(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      16
    ); // max value on the curve
    let secp256k1halfN = secp256k1N.div(new BN(2)); // half of the curve
    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    if (s.gt(secp256k1halfN)) {
      // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
      // if s < half the curve we need to invert it
      s = secp256k1N.sub(s);
      return { r, s };
    }
    // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
    return { r, s };
  },
  sign_v: async function (msg: Buffer, r: BN, s: BN, v: number) {
    let rBuffer = r.toBuffer();
    let sBuffer = s.toBuffer();
    let pubKey = ethutil.ecrecover(msg, v, rBuffer, sBuffer);
    let addrBuf = ethutil.pubToAddress(pubKey);
    var RecoveredEthAddr = ethutil.bufferToHex(addrBuf);
    // console.log("Recovered ethereum address: " + RecoveredEthAddr);
    return RecoveredEthAddr;
  },
  recover: async function (msg: Buffer, r: BN, s: BN, expectedEthAddr: string) {
    // This is the wrapper function to find the right v value
    // There are two matching signatues on the elliptic curve
    // we need to find the one that matches to our public key
    // it can be v = 27 or v = 28
    let v = 27;
    let pubKey = this.sign_v(msg, r, s, v);
    if (pubKey != expectedEthAddr) {
      // if the pub key for v = 27 does not match
      // it has to be v = 28
      v = 28;
      pubKey = this.sign_v(msg, r, s, v);
    }
    // console.log("Found the right ETH Address: " + pubKey + " v: " + v);
    return { pubKey, v };
  },
  utils: {
    getAddressFromASN1: function (asn1PubKey: Buffer) {
      // console.log("Encoded Pub Key: " + publicKey.toString("hex"));

      // The public key is ASN1 encoded in a format according to
      // https://tools.ietf.org/html/rfc5480#section-2
      // I used https://lapo.it/asn1js to figure out how to parse this
      // and defined the schema in the EcdsaPubKey object
      // console.log(publicKey);
      let res = ecdsa.pubkey_parse.decode(asn1PubKey, "der");
      let pubKeyBuffer: Buffer = res.pubKey.data;

      // The public key starts with a 0x04 prefix that needs to be removed
      // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
      pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length);

      const address = keccak256(pubKeyBuffer); // keccak256 hash of publicKey
      const buf2 = Buffer.from(address, "hex");
      const EthAddr = "0x" + buf2.slice(-20).toString("hex"); // take last 20 bytes as ethereum adress
      // console.log("Generated Ethreum address: " + EthAddr);
      return EthAddr;
    },
  },
};
