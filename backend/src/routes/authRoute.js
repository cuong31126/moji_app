import express from "express";
import passport from "passport";
import {
  refreshToken,
  signIn,
  signOut,
  signUp,
  socialAuthCallback,
} from "../controllers/authController.js";
import { isSocialProviderConfigured } from "../config/passport.js";

const router = express.Router();

const getClientUrl = () => process.env.CLIENT_URL || "http://localhost:5173";

const socialFailureRedirect = (provider, reason = "failed") =>
  `${getClientUrl()}/signin?socialError=${provider}_${reason}`;

const ensureProviderConfigured = (provider) => (req, res, next) => {
  if (!isSocialProviderConfigured(provider)) {
    return res.redirect(socialFailureRedirect(provider, "not_configured"));
  }

  next();
};

router.post("/signup", signUp);
router.post("/signin", signIn);
router.post("/signout", signOut);
router.post("/refresh", refreshToken);

router.get(
  "/google",
  ensureProviderConfigured("google"),
  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  })
);

router.get(
  "/google/callback",
  ensureProviderConfigured("google"),
  passport.authenticate("google", {
    session: false,
    failureRedirect: socialFailureRedirect("google"),
  }),
  socialAuthCallback
);

router.get(
  "/github",
  ensureProviderConfigured("github"),
  passport.authenticate("github", {
    scope: ["user:email"],
    session: false,
  })
);

router.get(
  "/github/callback",
  ensureProviderConfigured("github"),
  passport.authenticate("github", {
    session: false,
    failureRedirect: socialFailureRedirect("github"),
  }),
  socialAuthCallback
);

router.get(
  "/facebook",
  ensureProviderConfigured("facebook"),
  passport.authenticate("facebook", {
    scope: ["email"],
    session: false,
  })
);

router.get(
  "/facebook/callback",
  ensureProviderConfigured("facebook"),
  passport.authenticate("facebook", {
    session: false,
    failureRedirect: socialFailureRedirect("facebook"),
  }),
  socialAuthCallback
);

export default router;
