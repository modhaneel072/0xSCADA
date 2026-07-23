import {
  payBounty,
  positiveInteger,
  readArgument,
} from "./bounty-contract";

async function main(): Promise<void> {
  const issueNumber = positiveInteger(
    readArgument("issue-number"),
    "issue-number",
  );
  const prNumber = positiveInteger(readArgument("pr-number"), "pr-number");
  const recipient = readArgument("recipient");
  const transactionHash = await payBounty(
    issueNumber,
    prNumber,
    recipient,
  );

  console.log(
    JSON.stringify({
      operation: "payBounty",
      issueNumber: issueNumber.toString(),
      prNumber: prNumber.toString(),
      recipient,
      transactionHash,
    }),
  );
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
