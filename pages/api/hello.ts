// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
import aws from "aws-sdk";
import { utils } from "ethers";
import * as asn1 from "asn1.js";
import * as ethutil from "ethereumjs-util";
// import { Transaction, TxData } from "ethereumjs-tx";
import crypto, { BinaryToTextEncoding } from "crypto";
import BN from "bn.js";
import { keccak256 } from "js-sha3";

const credentials = {
  iam: {
    accessKeyId: process.env.IAM_accessKeyId, //credentials for your IAM user
    secretAccessKey: process.env.IAM_secretAccessKey, //credentials for your IAM user
    region: process.env.IAM_region,
  },
  KeyId: process.env.KMS_KeyId,
  kmsEncryptParams: function (buffer) {
    return {
      KeyId: this.KeyId, // The identifier of the CMK to use for encryption. You can use the key ID or Amazon Resource Name (ARN) of the CMK, or the name or ARN of an alias that refers to the CMK.
      Plaintext: buffer,
    }; // The data to encrypt.
  },
  kmsSignParams: function (buffer) {
    return {
      KeyId: this.KeyId, // The identifier of the CMK to use for encryption. You can use the key ID or Amazon Resource Name (ARN) of the CMK, or the name or ARN of an alias that refers to the CMK.
      Message: buffer, // The data to encrypt.
      // 'ECDSA_SHA_256' is the one compatible with ECC_SECG_P256K1.
      SigningAlgorithm: "ECDSA_SHA_256",
      MessageType: "RAW",
    };
  },
  getKMS: function () {
    return new aws.KMS(this.iam);
  },
};

const methods = {
  sign: function (buffer: any) {
    const kms = credentials.getKMS();
    return new Promise((resolve, reject) => {
      const params = credentials.kmsSignParams(buffer);
      // console.log(params);
      kms.sign(params, (err: any, data: any) => {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    });
  },
  encrypt: function (buffer: any) {
    const kms = credentials.getKMS();
    return new Promise((resolve, reject) => {
      const params = credentials.kmsEncryptParams(buffer);
      kms.encrypt(params, (err: any, data: any) => {
        if (err) {
          reject(err);
        } else {
          resolve(data.CiphertextBlob);
        }
      });
    });
  },
  decrypt: function (buffer) {
    const kms = credentials.getKMS();
    return new Promise((resolve, reject) => {
      const params = {
        CiphertextBlob: buffer, // The data to dencrypt.
      };
      kms.decrypt(params, (err, data) => {
        if (err) {
          reject(err);
        } else {
          resolve(data.Plaintext);
        }
      });
    });
  },
  getPublicKey: function () {
    const kms = credentials.getKMS();
    return kms
      .getPublicKey({
        KeyId: credentials.KeyId,
      })
      .promise();
  },
};

const EcdsaPubKey = asn1.define("EcdsaPubKey", function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
  this.seq().obj(
    this.key("algo").seq().obj(this.key("a").objid(), this.key("b").objid()),
    this.key("pubKey").bitstr()
  );
});

const EcdsaSigAsnParse = asn1.define("EcdsaSig", function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

async function findEthereumSig(signature) {
  // console.log("encoded sig: " + signature.Signature.toString("hex"));

  let decoded = EcdsaSigAsnParse.decode(signature.Signature, "der");
  let r = decoded.r;
  let s = decoded.s;
  // console.log("r: " + r.toString(10));
  // console.log("s: " + s.toString(10));

  let tempsig = r.toString(16) + s.toString(16);

  let secp256k1N = new BN(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    16
  ); // max value on the curve
  let secp256k1halfN = secp256k1N.div(new BN(2)); // half of the curve
  // Because of EIP-2 not all elliptic curve signatures are accepted
  // the value of s needs to be SMALLER than half of the curve
  // i.e. we need to flip s if it's greater than half of the curve
  if (s.gt(secp256k1halfN)) {
    // console.log(
    //   "s is on the wrong side of the curve... flipping - tempsig: " +
    //     tempsig +
    //     " length: " +
    //     tempsig.length
    // );
    // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
    // if s < half the curve we need to invert it
    // s = curve.n - s
    s = secp256k1N.sub(s);
    // console.log("new s: " + s.toString(10));
    return { r, s };
  }
  // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
  return { r, s };
}

function recoverPubKeyFromSig(msg: Buffer, r: BN, s: BN, v: number) {
  // console.log(
  //   "Recovering public key with msg " +
  //     msg.toString("hex") +
  //     " r: " +
  //     r.toString(16) +
  //     " s: " +
  //     s.toString(16)
  // );
  let rBuffer = r.toBuffer();
  let sBuffer = s.toBuffer();
  let pubKey = ethutil.ecrecover(msg, v, rBuffer, sBuffer);
  let addrBuf = ethutil.pubToAddress(pubKey);
  var RecoveredEthAddr = ethutil.bufferToHex(addrBuf);
  // console.log("Recovered ethereum address: " + RecoveredEthAddr);
  return RecoveredEthAddr;
}

function findRightKey(msg: Buffer, r: BN, s: BN, expectedEthAddr: string) {
  // This is the wrapper function to find the right v value
  // There are two matching signatues on the elliptic curve
  // we need to find the one that matches to our public key
  // it can be v = 27 or v = 28
  let v = 27;
  let pubKey = recoverPubKeyFromSig(msg, r, s, v);
  if (pubKey != expectedEthAddr) {
    // if the pub key for v = 27 does not match
    // it has to be v = 28
    v = 28;
    pubKey = recoverPubKeyFromSig(msg, r, s, v);
  }
  // console.log("Found the right ETH Address: " + pubKey + " v: " + v);
  return { pubKey, v };
}

function getEthereumAddress(publicKey: Buffer): string {
  // console.log("Encoded Pub Key: " + publicKey.toString("hex"));

  // The public key is ASN1 encoded in a format according to
  // https://tools.ietf.org/html/rfc5480#section-2
  // I used https://lapo.it/asn1js to figure out how to parse this
  // and defined the schema in the EcdsaPubKey object
  let res = EcdsaPubKey.decode(publicKey, "der");
  let pubKeyBuffer: Buffer = res.pubKey.data;

  // The public key starts with a 0x04 prefix that needs to be removed
  // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
  pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length);

  const address = keccak256(pubKeyBuffer); // keccak256 hash of publicKey
  const buf2 = Buffer.from(address, "hex");
  const EthAddr = "0x" + buf2.slice(-20).toString("hex"); // take last 20 bytes as ethereum adress
  // console.log("Generated Ethreum address: " + EthAddr);
  return EthAddr;
}

async function digestMessage(message) {
  // Defining the algorithm
  let algorithm = "sha256";

  // Defining the key
  let key = message;

  // Digest format
  let format: BinaryToTextEncoding = "hex";

  // Creating the digest in hex encoding
  let digest1 = crypto.createHash(algorithm).update(key).digest();
  return { raw: digest1, digest: digest1.toString(format) };
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  let pubKey = await methods.getPublicKey();
  let ethAddr = getEthereumAddress(pubKey.PublicKey as Buffer);
  let ethAddrHash = ethutil.keccak(Buffer.from(ethAddr));

  // console.log(`Address: ${ethAddr} || AddHash: ${ethAddrHash}`);

  const stringMessage = "Hello My Men";
  const message = await digestMessage(stringMessage);
  // console.log(message);
  const signature = await methods.sign(stringMessage);

  // console.log(signature["Signature"].toString("hex"));

  const recovered = await findEthereumSig(signature);

  console.log("0x" + message.digest);
  console.log(utils.id(stringMessage));

  // console.log(signature);
  let recoveredPubAddr = findRightKey(
    message.raw,
    recovered.r,
    recovered.s,
    ethAddr
  );

  // console.log(recoveredPubAddr);

  // console.log({
  //   r: recovered.r.toBuffer(),
  //   s: recovered.s.toBuffer(),
  //   v: recoveredPubAddr.v,
  // });

  const expanded = {
    r: "0x" + recovered.r.toBuffer().toString("hex"),
    s: "0x" + recovered.s.toBuffer().toString("hex"),
    v: recoveredPubAddr.v,
    recoveryParam: recoveredPubAddr.v - 27,
  };
  const signatureMixed = utils.joinSignature(expanded);
  // console.log(signatureMixed);

  const recoveredAddress = utils.verifyMessage(stringMessage, signatureMixed);

  // console.log(recoveredAddress);

  res.status(200).json({
    address: {
      expected: ethAddr,
      recovered: recoveredPubAddr.pubKey,
    },
    rsv: {
      r: recovered.r.toBuffer().toString("hex"),
      s: recovered.s.toBuffer().toString("hex"),
      v: recoveredPubAddr.v,
    },
  });
}
