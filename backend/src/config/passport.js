import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { findOrCreateSocialUser } from "../utils/socialAuth.js";

const configuredProviders = new Set();

const getServerUrl = () =>
  process.env.SERVER_URL || `http://localhost:${process.env.PORT || 5001}`;

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
  const serverUrl = getServerUrl();
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
          callbackURL:
            process.env.GOOGLE_CALLBACK_URL ||
            `${serverUrl}/api/auth/google/callback`,
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
          callbackURL:
            process.env.GITHUB_CALLBACK_URL ||
            `${serverUrl}/api/auth/github/callback`,
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
          callbackURL:
            process.env.FACEBOOK_CALLBACK_URL ||
            `${serverUrl}/api/auth/facebook/callback`,
          profileFields: ["id", "displayName", "photos", "email"],
        },
        createVerifyCallback("facebook")
      )
    );
    configuredProviders.add("facebook");
  }

  if (!process.env.ACCESS_TOKEN_SECRET) {
    console.warn("[auth] Missing ACCESS_TOKEN_SECRET. Login will fail until it is set.");
  }

  if (!process.env.REFRESH_TOKEN_SECRET) {
    console.warn(
      "[auth] REFRESH_TOKEN_SECRET is not set. Current refresh tokens are opaque Session tokens, so this is optional for now."
    );
  }
};

export const isSocialProviderConfigured = (provider) =>
  configuredProviders.has(provider);
