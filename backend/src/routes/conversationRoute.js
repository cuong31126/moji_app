import express from "express";
import {
  acceptGroupInvite,
  approveGroupInvite,
  createConversation,
  deleteGroupConversation,
  getConversations,
  getGroupInvites,
  getMessages,
  inviteGroupMembers,
  leaveGroupConversation,
  markAsSeen,
  removeGroupMember,
  rejectGroupInvite,
  updateGroupAvatar,
  updateGroupInfo,
  updateGroupMemberRole,
} from "../controllers/conversationController.js";
import { checkFriendship } from "../middlewares/friendMiddleware.js";
import { upload } from "../middlewares/uploadMiddleware.js";

const router = express.Router();

router.post("/", checkFriendship, createConversation);
router.get("/", getConversations);
router.get("/group-invites", getGroupInvites);
router.post("/group-invites/:inviteId/accept", acceptGroupInvite);
router.post("/group-invites/:inviteId/reject", rejectGroupInvite);
router.post("/group-invites/:inviteId/approve", approveGroupInvite);
router.post("/group-invites/:inviteId/decline", rejectGroupInvite);
router.patch(
  "/:conversationId/group-avatar",
  upload.single("file"),
  updateGroupAvatar
);
router.patch("/:conversationId/group", updateGroupInfo);
router.post("/:conversationId/group-invites", inviteGroupMembers);
router.patch("/:conversationId/members/:memberId/role", updateGroupMemberRole);
router.delete("/:conversationId/members/:memberId", removeGroupMember);
router.post("/:conversationId/leave", leaveGroupConversation);
router.delete("/:conversationId", deleteGroupConversation);
router.get("/:conversationId/messages", getMessages);
router.patch("/:conversationId/seen", markAsSeen);

export default router;
