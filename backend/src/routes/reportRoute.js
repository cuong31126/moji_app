import express from "express";
import {
  addReportComment,
  cleanupReport,
  confirmCleanReport,
  createReport,
  getReportById,
  getReportComments,
  getReports,
  inviteReportChatMembers,
  joinReportChat,
  shareReport,
  verifyReport,
} from "../controllers/reportController.js";
import { upload } from "../middlewares/uploadMiddleware.js";

const router = express.Router();

router.get("/", getReports);
router.post("/", upload.array("images", 5), createReport);
router.get("/:id", getReportById);
router.post("/:id/verify", verifyReport);
router.post("/:id/cleanup", upload.array("images", 5), cleanupReport);
router.post("/:id/confirm-clean", confirmCleanReport);
router.get("/:id/comments", getReportComments);
router.post("/:id/comments", addReportComment);
router.post("/:id/share", shareReport);
router.post("/:id/join-chat", joinReportChat);
router.post("/:id/invite", inviteReportChatMembers);

export default router;
