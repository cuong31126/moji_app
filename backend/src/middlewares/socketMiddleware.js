import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { getAccessTokenSecret } from "../config/env.js";

export const socketAuthMiddleware = async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) {
      return next(new Error("Unauthorized - Token không tồn tại"));
    }

    const accessTokenSecret = getAccessTokenSecret();

    if (!accessTokenSecret) {
      return next(new Error("Server JWT config is missing"));
    }

    const decoded = jwt.verify(token, accessTokenSecret);
    if (!decoded) {
      return next(new Error("Unauthorized - Token không hợp lệ hoặc đã hết hạn"));
    }

    const user = await User.findById(decoded.userId).select("-hashedPassword");

    if (!user) {
      return next(new Error("User không tồn tại"));
    }

    socket.user = user;

    next();
  } catch (error) {
    console.error("Lỗi khi verify JWT trong socketMiddleware", error);
    next(new Error("Unauthorized"));
  }
};
