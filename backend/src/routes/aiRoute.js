import express from "express";
import { summarizeChat, suggestEmojis } from "../controllers/aiController.js";

const router = express.Router();

router.post("/summarize-chat", summarizeChat);
router.post("/suggest-emojis", suggestEmojis);

export default router;
