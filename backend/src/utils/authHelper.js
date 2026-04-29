import crypto from "crypto";
import jwt from "jsonwebtoken";
import Session from "../models/Session.js";

export const ACCESS_TOKEN_TTL = "30m";
export const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000;

const isProduction = () => process.env.NODE_ENV === "production";

export const getRefreshCookieOptions = () => ({
  httpOnly: true,
  secure: isProduction(),
  sameSite: isProduction() ? "none" : "lax",
  maxAge: REFRESH_TOKEN_TTL,
  path: "/",
});

export const getClearRefreshCookieOptions = () => {
  const { maxAge, ...options } = getRefreshCookieOptions();
  return options;
};

export const createAccessToken = (userId) => {
  if (!process.env.ACCESS_TOKEN_SECRET) {
    throw new Error("Missing ACCESS_TOKEN_SECRET");
  }

  return jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
  });
};

export const createRefreshToken = (userId) => {
  const tokenId = crypto.randomBytes(32).toString("hex");

  if (!process.env.REFRESH_TOKEN_SECRET) {
    return tokenId;
  }

  return jwt.sign({ userId, tokenId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "14d",
  });
};

export const verifyRefreshTokenIfConfigured = (refreshToken) => {
  if (!process.env.REFRESH_TOKEN_SECRET) {
    return null;
  }

  return jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
};

export const toSafeUser = (user) => {
  const source = user.toObject ? user.toObject() : user;
  const { hashedPassword, ...safeUser } = source;
  return safeUser;
};

export const issueAuthSession = async (res, user) => {
  const accessToken = createAccessToken(user._id);
  const refreshToken = createRefreshToken(user._id);

  await Session.create({
    userId: user._id,
    refreshToken,
    expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
  });

  res.cookie("refreshToken", refreshToken, getRefreshCookieOptions());

  return {
    accessToken,
    user: toSafeUser(user),
  };
};
