import { BigNumber, BigNumberish } from "ethers";
import { getAddress, stripZeros } from "ethers/lib/utils";
import { hexConcat } from "@ethersproject/bytes";
import {
  UnsignedTransaction,
  AccessListish,
  accessListify,
} from "@ethersproject/transactions";
import * as RLP from "@ethersproject/rlp";

function formatAccessList(
  value: AccessListish
): Array<[string, Array<string>]> {
  return accessListify(value).map((set) => [set.address, set.storageKeys]);
}

function formatNumber(value: BigNumberish, name: string): Uint8Array {
  const result = stripZeros(BigNumber.from(value).toHexString());
  if (result.length > 32) {
    console.log("invalid length for " + name, "transaction:" + name, value);
  }
  return result;
}

export function _serializeEip1559(
  transaction: UnsignedTransaction,
  signature?: { r: string; s: string; recoveryParam: number }
): string {
  // If there is an explicit gasPrice, make sure it matches the
  // EIP-1559 fees; otherwise they may not understand what they
  // think they are setting in terms of fee.
  if (transaction.gasPrice != null) {
    const gasPrice = BigNumber.from(transaction.gasPrice);
    const maxFeePerGas = BigNumber.from(transaction.maxFeePerGas || 0);
    if (!gasPrice.eq(maxFeePerGas)) {
      console.log("mismatch EIP-1559 gasPrice != maxFeePerGas", "tx", {
        gasPrice,
        maxFeePerGas,
      });
    }
  }

  const fields: any = [
    formatNumber(transaction.chainId || 0, "chainId"),
    formatNumber(transaction.nonce || 0, "nonce"),
    formatNumber(transaction.maxPriorityFeePerGas || 0, "maxPriorityFeePerGas"),
    formatNumber(transaction.maxFeePerGas || 0, "maxFeePerGas"),
    formatNumber(transaction.gasLimit || 0, "gasLimit"),
    transaction.to != null ? getAddress(transaction.to) : "0x",
    formatNumber(transaction.value || 0, "value"),
    transaction.data || "0x",
    formatAccessList(transaction.accessList || []),
  ];

  if (signature) {
    const sig = signature;
    fields.push(formatNumber(sig.recoveryParam, "recoveryParam"));
    fields.push(stripZeros(sig.r));
    fields.push(stripZeros(sig.s));
  }

  return hexConcat(["0x02", RLP.encode(fields)]);
}
