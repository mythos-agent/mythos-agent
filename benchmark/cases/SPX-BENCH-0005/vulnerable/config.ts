// VULNERABLE fixture for SPX-BENCH-0005.
// Do not import or execute — this file is benchmark input only.
//
// AWS access key hardcoded in source. The AKIA-prefix 20-character
// shape is the canonical AWS-docs placeholder — matches the exact
// pattern a real leaked key would take. Once committed to git, it's
// permanently in history across every mirror and fork.

export const awsConfig = {
  region: "us-east-1",
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};
