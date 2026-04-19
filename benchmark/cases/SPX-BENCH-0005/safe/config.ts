// SAFE fixture for SPX-BENCH-0005 — the intended fix shape.
//
// Credentials read from the environment at startup. Absent values
// fail loudly rather than falling through to a hardcoded fallback.
// A production setup would layer AWS Secrets Manager or an
// equivalent secret store on top — this fixture demonstrates the
// minimum: no literal credentials in source.

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const awsConfig = {
  region: process.env.AWS_REGION ?? "us-east-1",
  accessKeyId: requiredEnv("AWS_ACCESS_KEY_ID"),
  secretAccessKey: requiredEnv("AWS_SECRET_ACCESS_KEY"),
};
