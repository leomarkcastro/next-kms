// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
import { BigNumber, providers, utils } from "ethers";

import { resolveProperties } from "@ethersproject/properties";
import { keccak256 as eth_keccak256 } from "@ethersproject/keccak256";
import { serialize } from "@ethersproject/transactions";
import { methods } from "@/lib/aws_kms";
import { _serializeEip1559 } from "@/lib/ether_fx";
import { Interface } from "ethers/lib/utils";

type Transaction = {
  to: string;
  data: string;
  value: BigNumber;
  type: number;
  nonce: number;
  chainId: number;
  maxPriorityFeePerGas: BigNumber;
  maxFeePerGas: BigNumber;
  gasLimit: string;
};

const steps = {
  async getWalletAddress() {
    let pubKey = await methods.getPublicKey();
    let ethAddr = methods.utils.getAddressFromASN1(pubKey.PublicKey as Buffer);
    return ethAddr;
  },
  async generateTransaction(
    provider: providers.JsonRpcProvider,
    data: {
      to: string;
      data: string;
      value: BigNumber;
      gasLimit: string;
    },
    from: string
  ) {
    let nonce = await provider.getTransactionCount(from);
    console.log("Nonce:", nonce);

    let feeData = await provider.getFeeData();
    console.log("Fee Data:", feeData);

    // get chain ID of network
    let chainId = await provider.getNetwork();
    console.log("Chain ID:", chainId);

    const _data = data;

    const tx = {
      type: 2,
      nonce: nonce,
      chainId: chainId.chainId, // Ethereum network id

      maxPriorityFeePerGas: feeData["maxPriorityFeePerGas"],
      maxFeePerGas: feeData["maxFeePerGas"],

      gasLimit: _data.gasLimit,
      ..._data,
    };
    console.log("Transaction Data:", tx);

    const rtx = await resolveProperties(tx);
    console.log("Resolved Transaction Data:", rtx);
    return { rtx, tx };
  },
  digestTransaction(rtx: Transaction) {
    const rtx_digest = eth_keccak256(serialize(rtx));
    console.log("Resolved Transaction Data Digest:", rtx_digest);

    // convert rtx_digest to buffer
    const rtx_digest_buf = Buffer.from(rtx_digest.slice(2), "hex");
    return rtx_digest_buf;
  },
  serializeTransaction(
    tx: Transaction,
    signatureData: { r: string; s: string; recoveryParam: number }
  ) {
    const serializedTX = _serializeEip1559(tx, signatureData);
    console.log("Serialized TX:", serializedTX);

    const txHash = utils.keccak256(serializedTX);
    console.log(
      `Transaction Hash (+ Link): https://mumbai.polygonscan.com/tx/${txHash}`
    );
    return { serializedTX, txHash };
  },
  async signTransactionDigest(rtx_digest_buf: Buffer, ethAddr: string) {
    let rtx_sig = await methods.sign_rs(rtx_digest_buf);
    console.log("Resolved Transaction Data Signature:", rtx_sig);

    // recover recoveryParam Here
    let rtx_sig_recov = await methods.recover(
      rtx_digest_buf,
      rtx_sig.r,
      rtx_sig.s,
      ethAddr
    );

    // Compile the signature
    const signatureData = {
      r: "0x" + rtx_sig.r.toBuffer().toString("hex"),
      s: "0x" + rtx_sig.s.toBuffer().toString("hex"),
      recoveryParam: rtx_sig_recov.v - 27,
    };
    console.log("Signature Data:", signatureData);
    return signatureData;
  },
};

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  // get nonce of the ethereum address using ethers.js
  const provider = new providers.JsonRpcProvider(
    "https://polygon-mumbai.g.alchemy.com/v2/D8zWjAjZyN5bh6hioc9pA_6E34HZzUAn"
  );

  let senderPublicKey = await steps.getWalletAddress();

  // create transaction
  const iface = new Interface([
    // State mutating method
    "function burn(uint256 _amount)",
    "function dispenceToken()",
  ]);
  // const tx_sc_data = iface.encodeFunctionData("dispenceToken", [
  //   // senderPublicKey,
  //   // utils.parseEther("0.001"),
  // ]);
  const tx_sc_data = iface.encodeFunctionData("burn", [utils.parseEther("1")]);
  console.log("Transaction Data:", tx_sc_data);

  // estimate gas
  const gasEstimate = await provider.estimateGas({
    from: senderPublicKey,
    to: "0xdD809BB276DbCEc0A86461cCEdec072642a1AeC4",
    data: tx_sc_data,
  });
  console.log("Gas Estimate:", gasEstimate.toString());

  const { rtx } = await steps.generateTransaction(
    provider,
    {
      to: "0xdD809BB276DbCEc0A86461cCEdec072642a1AeC4",
      data: tx_sc_data,
      value: utils.parseEther("0"),
      gasLimit: gasEstimate.mul(5).div(4).toString(),
    },
    senderPublicKey
  );

  const rtx_digest_buf = steps.digestTransaction(rtx);

  // sign data here
  const signatureData = await steps.signTransactionDigest(
    rtx_digest_buf,
    senderPublicKey
  );

  const { serializedTX, txHash } = steps.serializeTransaction(
    rtx,
    signatureData
  );

  console.log("Serialized TX:", serializedTX);

  // const txData = await provider.sendTransaction(serializedTX);
  // console.log("Transaction Data:", txData);

  res.status(200).json({
    address: {
      sender: senderPublicKey,
      txPage: `https://mumbai.polygonscan.com/tx/${txHash}`,
      // recovered: recoveredPubAddr.pubKey,
      // txHash: txHash.toString("hex"),
    },
  });
}
