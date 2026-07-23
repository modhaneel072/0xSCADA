import {
  Contract,
  JsonRpcProvider,
  Wallet,
  getAddress,
} from "ethers";

const BOUNTY_PAYMENT_ABI = [
  "function claimBounty(uint256 issueNumber, address claimant)",
  "function payBounty(uint256 issueNumber, uint256 prNumber, address recipient)",
] as const;

function requireEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function normalizePrivateKey(value: string): string {
  return value.startsWith("0x") ? value : `0x${value}`;
}

async function connect(): Promise<Contract> {
  const rpcUrl = requireEnvironment("RPC_URL");
  const contractAddress = getAddress(
    requireEnvironment("BOUNTY_CONTRACT_ADDRESS"),
  );
  const privateKey = normalizePrivateKey(
    requireEnvironment("BOUNTY_PRIVATE_KEY"),
  );

  const provider = new JsonRpcProvider(rpcUrl);
  const code = await provider.getCode(contractAddress);
  if (code === "0x") {
    throw new Error(
      `No contract is deployed at BOUNTY_CONTRACT_ADDRESS (${contractAddress})`,
    );
  }

  return new Contract(
    contractAddress,
    BOUNTY_PAYMENT_ABI,
    new Wallet(privateKey, provider),
  );
}

async function waitForSuccess(
  operation: string,
  transaction: { hash: string; wait: () => Promise<{ status: number | null } | null> },
): Promise<string> {
  const receipt = await transaction.wait();
  if (!receipt || receipt.status !== 1) {
    throw new Error(`${operation} transaction failed: ${transaction.hash}`);
  }

  return transaction.hash;
}

export function readArgument(name: string): string {
  const flag = `--${name}`;
  const index = process.argv.indexOf(flag);
  const value = index >= 0 ? process.argv[index + 1]?.trim() : undefined;
  if (!value || value.startsWith("--")) {
    throw new Error(`Missing required argument: ${flag}`);
  }
  return value;
}

export function positiveInteger(value: string, name: string): bigint {
  if (!/^[1-9]\d*$/.test(value)) {
    throw new Error(`${name} must be a positive integer`);
  }
  return BigInt(value);
}

export async function claimBounty(
  issueNumber: bigint,
  claimant: string,
): Promise<string> {
  const contract = await connect();
  const normalizedClaimant = getAddress(claimant);
  const transaction = await contract.claimBounty(
    issueNumber,
    normalizedClaimant,
  );
  return waitForSuccess("claimBounty", transaction);
}

export async function payBounty(
  issueNumber: bigint,
  prNumber: bigint,
  recipient: string,
): Promise<string> {
  const contract = await connect();
  const normalizedRecipient = getAddress(recipient);
  const transaction = await contract.payBounty(
    issueNumber,
    prNumber,
    normalizedRecipient,
  );
  return waitForSuccess("payBounty", transaction);
}
