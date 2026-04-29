import crypto from "crypto";
import jwt from "jsonwebtoken";
import Session from "../models/Session.js";
import {
  getAccessTokenSecret,
  getRefreshTokenSecret,
} from "../config/env.js";

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
  const accessTokenSecret = getAccessTokenSecret();

  if (!accessTokenSecret) {
    throw new Error("Missing JWT_ACCESS_SECRET or ACCESS_TOKEN_SECRET");
  }

  return jwt.sign({ userId }, accessTokenSecret, {
    expiresIn: ACCESS_TOKEN_TTL,
  });
};

export const createRefreshToken = (userId) => {
  const tokenId = crypto.randomBytes(32).toString("hex");

  const refreshTokenSecret = getRefreshTokenSecret();

  if (!refreshTokenSecret) {
    return tokenId;
  }

  return jwt.sign({ userId, tokenId }, refreshTokenSecret, {
    expiresIn: "14d",
  });
};

export const verifyRefreshTokenIfConfigured = (refreshToken) => {
  const refreshTokenSecret = getRefreshTokenSecret();

  if (!refreshTokenSecret) {
    return null;
  }

  return jwt.verify(refreshToken, refreshTokenSecret);
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
