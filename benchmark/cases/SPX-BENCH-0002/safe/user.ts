// SAFE fixture for SPX-BENCH-0002 — the intended fix shape.
//
// User-editable fields are explicitly allowlisted. Privilege changes
// are not accepted on this endpoint; a separate admin-only handler
// (not shown) performs those with server-side actor-identity checks.

import express from "express";

interface ProfileUpdate {
  name?: string;
  email?: string;
}

const db = {
  users: {
    updateProfile: async (_id: string, _patch: ProfileUpdate): Promise<void> => {
      // stubbed
    },
  },
};

export const router = express.Router();

router.post("/users/:id", async (req, res) => {
  const userId = req.params.id;
  const patch: ProfileUpdate = {
    name: req.body.name,
    email: req.body.email,
  };
  await db.users.updateProfile(userId, patch);
  res.json({ ok: true });
});
