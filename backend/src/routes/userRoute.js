import express from "express";
import {
  authMe,
  getUserById,
  searchUserByUsername,
  uploadAvatar,
} from "../controllers/userController.js";
import { upload } from "../middlewares/uploadMiddleware.js";

const router = express.Router();

router.get("/me", authMe);
router.get("/search", searchUserByUsername);
router.get("/:userId", getUserById);
router.post("/uploadAvatar", upload.single("file"), uploadAvatar);

export default router;
