import "dotenv/config";

const DEFAULT_CLIENT_ORIGINS = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "https://ecomojiapp1.vercel.app",
];

export const normalizeOrigin = (value = "") => value.trim().replace(/\/+$/, "");

const splitOrigins = (value = "") =>
  value
    .split(",")
    .map(normalizeOrigin)
    .filter(Boolean);

export const getPort = () => process.env.PORT || 5001;

export const getMongoUri = () =>
  process.env.MONGODB_URI || process.env.MONGODB_CONNECTIONSTRING;

export const getAccessTokenSecret = () =>
  process.env.JWT_ACCESS_SECRET || process.env.ACCESS_TOKEN_SECRET;

export const getRefreshTokenSecret = () =>
  process.env.JWT_REFRESH_SECRET || process.env.REFRESH_TOKEN_SECRET;

export const getClientUrl = () =>
  normalizeOrigin(process.env.CLIENT_URL || "http://localhost:5173");

export const getServerUrl = () =>
  normalizeOrigin(
    process.env.SERVER_URL ||
      process.env.BACKEND_URL ||
      process.env.RENDER_EXTERNAL_URL ||
      `http://localhost:${process.env.PORT || 5001}`
  );

export const getOAuthCallbackUrl = (provider) => {
  const envKeys = {
    google: "GOOGLE_CALLBACK_URL",
    github: "GITHUB_CALLBACK_URL",
    facebook: "FACEBOOK_CALLBACK_URL",
  };
  const envKey = envKeys[provider];
  const configuredUrl = envKey ? process.env[envKey] : "";

  return normalizeOrigin(
    configuredUrl || `${getServerUrl()}/api/auth/${provider}/callback`
  );
};

export const getAllowedClientOrigins = () =>
  Array.from(
    new Set([
      ...DEFAULT_CLIENT_ORIGINS,
      ...splitOrigins(process.env.CLIENT_URLS),
      getClientUrl(),
    ])
  );

export const corsOriginDelegate = (origin, callback) => {
  if (!origin) {
    callback(null, true);
    return;
  }

  const normalizedOrigin = normalizeOrigin(origin);

  if (getAllowedClientOrigins().includes(normalizedOrigin)) {
    callback(null, true);
    return;
  }

  callback(new Error(`Origin ${origin} is not allowed by CORS`));
};
