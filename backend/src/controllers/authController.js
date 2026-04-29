import bcrypt from "bcrypt";
import User from "../models/User.js";
import Session from "../models/Session.js";
import {
  createAccessToken,
  getClearRefreshCookieOptions,
  issueAuthSession,
  toSafeUser,
  verifyRefreshTokenIfConfigured,
} from "../utils/authHelper.js";
import { getClientUrl } from "../config/env.js";

export const signUp = async (req, res) => {
  try {
    const { username, password, email, firstName, lastName } = req.body;

    if (!username || !password || !email || !firstName || !lastName) {
      return res.status(400).json({
        message: "Không thể thiếu username, password, email, firstName, lastName",
      });
    }

    const normalizedUsername = username.trim().toLowerCase();
    const normalizedEmail = email.trim().toLowerCase();

    const duplicate = await User.findOne({
      $or: [{ username: normalizedUsername }, { email: normalizedEmail }],
    });

    if (duplicate) {
      return res
        .status(409)
        .json({ message: "Username hoặc email đã tồn tại" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      username: normalizedUsername,
      hashedPassword,
      email: normalizedEmail,
      displayName: `${firstName} ${lastName}`,
      authProviders: [{ provider: "local", providerId: normalizedUsername }],
    });

    return res.sendStatus(204);
  } catch (error) {
    console.error("Lỗi khi gọi signUp", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const signIn = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Thiếu username hoặc password" });
    }

    const user = await User.findOne({
      username: username.trim().toLowerCase(),
    });

    if (!user || !user.hashedPassword) {
      return res
        .status(401)
        .json({ message: "Username hoặc password không chính xác" });
    }

    const passwordCorrect = await bcrypt.compare(password, user.hashedPassword);

    if (!passwordCorrect) {
      return res
        .status(401)
        .json({ message: "Username hoặc password không chính xác" });
    }

    const authPayload = await issueAuthSession(res, user);

    return res.status(200).json({
      message: `User ${user.displayName} đã đăng nhập`,
      ...authPayload,
    });
  } catch (error) {
    console.error("Lỗi khi gọi signIn", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const signOut = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;

    if (token) {
      await Session.deleteOne({ refreshToken: token });
    }

    res.clearCookie("refreshToken", getClearRefreshCookieOptions());
    return res.sendStatus(204);
  } catch (error) {
    console.error("Lỗi khi gọi signOut", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const refreshToken = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;

    if (!token) {
      console.warn("[auth.refresh] Missing refresh cookie");
      return res.status(401).json({ message: "Refresh token không tồn tại" });
    }

    try {
      verifyRefreshTokenIfConfigured(token);
    } catch (error) {
      console.warn("[auth.refresh] Refresh JWT verify failed", error);
      await Session.deleteOne({ refreshToken: token });
      res.clearCookie("refreshToken", getClearRefreshCookieOptions());
      return res.status(403).json({ message: "Refresh token không hợp lệ" });
    }

    const session = await Session.findOne({ refreshToken: token }).populate({
      path: "userId",
      select: "-hashedPassword",
    });

    if (!session) {
      console.warn("[auth.refresh] Refresh token not found in Session");
      return res
        .status(403)
        .json({ message: "Refresh token không hợp lệ hoặc đã hết hạn" });
    }

    if (session.expiresAt < new Date()) {
      console.warn("[auth.refresh] Refresh token expired", {
        sessionId: session._id,
      });
      await Session.deleteOne({ _id: session._id });
      res.clearCookie("refreshToken", getClearRefreshCookieOptions());
      return res.status(403).json({ message: "Refresh token đã hết hạn" });
    }

    const user = session.userId;

    if (!user) {
      console.warn("[auth.refresh] Session user no longer exists", {
        sessionId: session._id,
      });
      await Session.deleteOne({ _id: session._id });
      res.clearCookie("refreshToken", getClearRefreshCookieOptions());
      return res.status(403).json({ message: "User không còn tồn tại" });
    }

    const accessToken = createAccessToken(user._id);

    return res.status(200).json({
      accessToken,
      user: toSafeUser(user),
    });
  } catch (error) {
    console.error("Lỗi khi gọi refreshToken", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const socialAuthCallback = async (req, res) => {
  try {
    if (!req.user) {
      return res.redirect(`${getClientUrl()}/signin?socialError=social_failed`);
    }

    await issueAuthSession(res, req.user);
    return res.redirect(`${getClientUrl()}/auth/social-callback`);
  } catch (error) {
    console.error("Lỗi khi xử lý social auth callback", error);
    return res.redirect(`${getClientUrl()}/signin?socialError=social_failed`);
  }
};
