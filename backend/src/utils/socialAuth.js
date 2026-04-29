import User from "../models/User.js";

const getEmailFromProfile = (provider, profile) => {
  const email = profile.emails?.[0]?.value;
  return email?.toLowerCase() || `${provider}_${profile.id}@social.moji.local`;
};

const getAvatarFromProfile = (profile) => profile.photos?.[0]?.value || "";

const getBaseUsername = (provider, profile, email) => {
  const raw =
    profile.username ||
    email.split("@")[0] ||
    profile.displayName ||
    `${provider}_${profile.id}`;

  return raw
    .toString()
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "")
    .slice(0, 24) || `${provider}${profile.id}`;
};

const createUniqueUsername = async (provider, profile, email) => {
  const base = getBaseUsername(provider, profile, email);
  let username = base;
  let suffix = 0;

  while (await User.exists({ username })) {
    suffix += 1;
    username = `${base}${suffix}`.slice(0, 30);
  }

  return username;
};

const hasProvider = (user, provider, providerId) => {
  return user.authProviders?.some(
    (item) => item.provider === provider && item.providerId === providerId
  );
};

export const findOrCreateSocialUser = async (provider, profile) => {
  const providerId = profile.id;
  const email = getEmailFromProfile(provider, profile);
  const displayName =
    profile.displayName || profile.username || email.split("@")[0] || "Moji User";
  const avatarUrl = getAvatarFromProfile(profile);

  let user = await User.findOne({
    authProviders: {
      $elemMatch: {
        provider,
        providerId,
      },
    },
  });

  if (user) {
    if (avatarUrl && !user.avatarUrl) {
      user.avatarUrl = avatarUrl;
      await user.save();
    }

    return user;
  }

  user = await User.findOne({ email });

  if (user) {
    if (!hasProvider(user, provider, providerId)) {
      user.authProviders.push({ provider, providerId });
    }

    if (avatarUrl && !user.avatarUrl) {
      user.avatarUrl = avatarUrl;
    }

    await user.save();
    return user;
  }

  const username = await createUniqueUsername(provider, profile, email);

  return User.create({
    username,
    email,
    displayName,
    avatarUrl,
    authProviders: [{ provider, providerId }],
  });
};
