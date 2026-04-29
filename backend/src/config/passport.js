import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { findOrCreateSocialUser } from "../utils/socialAuth.js";
import {
  getAccessTokenSecret,
  getOAuthCallbackUrl,
  getRefreshTokenSecret,
} from "./env.js";

const configuredProviders = new Set();

const createVerifyCallback = (provider) => {
  return async (_accessToken, _refreshToken, profile, done) => {
    try {
      const user = await findOrCreateSocialUser(provider, profile);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  };
};

export const configurePassport = () => {
  const facebookClientId =
    process.env.FACEBOOK_APP_ID || process.env.FACEBOOK_CLIENT_ID;
  const facebookClientSecret =
    process.env.FACEBOOK_APP_SECRET || process.env.FACEBOOK_CLIENT_SECRET;

  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: getOAuthCallbackUrl("google"),
        },
        createVerifyCallback("google")
      )
    );
    configuredProviders.add("google");
  }

  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    passport.use(
      new GitHubStrategy(
        {
          clientID: process.env.GITHUB_CLIENT_ID,
          clientSecret: process.env.GITHUB_CLIENT_SECRET,
          callbackURL: getOAuthCallbackUrl("github"),
          scope: ["user:email"],
        },
        createVerifyCallback("github")
      )
    );
    configuredProviders.add("github");
  }

  if (facebookClientId && facebookClientSecret) {
    passport.use(
      new FacebookStrategy(
        {
          clientID: facebookClientId,
          clientSecret: facebookClientSecret,
          callbackURL: getOAuthCallbackUrl("facebook"),
          profileFields: ["id", "displayName", "photos", "email"],
        },
        createVerifyCallback("facebook")
      )
    );
    configuredProviders.add("facebook");
  }

  if (!getAccessTokenSecret()) {
    console.warn(
      "[auth] Missing JWT_ACCESS_SECRET or ACCESS_TOKEN_SECRET. Login will fail until it is set."
    );
  }

  if (!getRefreshTokenSecret()) {
    console.warn(
      "[auth] JWT_REFRESH_SECRET or REFRESH_TOKEN_SECRET is not set. Current refresh tokens are opaque Session tokens, so this is optional for now."
    );
  }
};

export const isSocialProviderConfigured = (provider) =>
  configuredProviders.has(provider);
