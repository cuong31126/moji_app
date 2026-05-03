import express from "express";
import {
  acceptGroupInvite,
  approveGroupInvite,
  getGroupInvites,
  rejectGroupInvite,
} from "../controllers/conversationController.js";

const router = express.Router();

router.get("/me", getGroupInvites);
router.post("/:inviteId/accept", acceptGroupInvite);
router.post("/:inviteId/reject", rejectGroupInvite);
router.post("/:inviteId/approve", approveGroupInvite);
router.post("/:inviteId/decline", rejectGroupInvite);

export default router;
