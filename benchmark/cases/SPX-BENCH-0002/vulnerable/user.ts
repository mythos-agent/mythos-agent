// VULNERABLE fixture for SPX-BENCH-0002.
// Do not import or execute — this file is benchmark input only.
//
// The handler accepts a client-supplied role field and writes it
// straight to the user record. An attacker posts {"role": "admin"}
// to their own profile update endpoint and grants themselves admin.

import express from "express";

interface UserUpdate {
  name?: string;
  email?: string;
  role?: string;
  isAdmin?: boolean;
}

const db = {
  users: {
    update: async (_id: string, _patch: UserUpdate): Promise<void> => {
      // deliberately stubbed — the vuln is in the caller
    },
  },
};

export const router = express.Router();

router.post("/users/:id", async (req, res) => {
  const userId = req.params.id;
  await db.users.update(userId, {
    name: req.body.name,
    email: req.body.email,
    role: req.body.role,
  });
  res.json({ ok: true });
});
