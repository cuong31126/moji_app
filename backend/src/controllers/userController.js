import { uploadImageFromBuffer } from "../middlewares/uploadMiddleware.js";
import Friend from "../models/Friend.js";
import FriendRequest from "../models/FriendRequest.js";
import User from "../models/User.js";

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const toPublicUserPayload = (user, relationshipInfo = {}) => {
  if (!user) return null;

  return {
    _id: user._id,
    displayName: user.displayName,
    username: user.username,
    email: user.email,
    avatarUrl: user.avatarUrl,
    bio: user.bio,
    phone: user.phone,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    relationshipStatus: relationshipInfo.relationshipStatus ?? "none",
    friendRequestId: relationshipInfo.friendRequestId,
  };
};

const buildRelationshipMap = async (currentUserId, users) => {
  const currentId = currentUserId.toString();
  const targetIds = users
    .map((user) => user?._id)
    .filter(Boolean)
    .filter((id) => id.toString() !== currentId);

  const relationshipMap = new Map();

  users.forEach((user) => {
    if (user?._id?.toString() === currentId) {
      relationshipMap.set(currentId, { relationshipStatus: "self" });
    }
  });

  if (targetIds.length === 0) {
    return relationshipMap;
  }

  const [friendships, requests] = await Promise.all([
    Friend.find({
      $or: [
        { userA: currentUserId, userB: { $in: targetIds } },
        { userB: currentUserId, userA: { $in: targetIds } },
      ],
    }).lean(),
    FriendRequest.find({
      $or: [
        { from: currentUserId, to: { $in: targetIds } },
        { to: currentUserId, from: { $in: targetIds } },
      ],
    }).lean(),
  ]);

  friendships.forEach((friendship) => {
    const otherId =
      friendship.userA.toString() === currentId
        ? friendship.userB.toString()
        : friendship.userA.toString();

    relationshipMap.set(otherId, { relationshipStatus: "friends" });
  });

  requests.forEach((request) => {
    const isSent = request.from.toString() === currentId;
    const otherId = isSent ? request.to.toString() : request.from.toString();

    if (!relationshipMap.has(otherId)) {
      relationshipMap.set(otherId, {
        relationshipStatus: isSent ? "request_sent" : "request_received",
        friendRequestId: request._id,
      });
    }
  });

  return relationshipMap;
};

export const authMe = async (req, res) => {
  try {
    const user = req.user;

    return res.status(200).json({ user });
  } catch (error) {
    console.error("Error while calling authMe", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const searchUserByUsername = async (req, res) => {
  try {
    const { username, q } = req.query;
    const keyword = (q ?? username ?? "").trim();

    if (!keyword) {
      return res
        .status(400)
        .json({ message: "Cần cung cấp từ khóa tìm kiếm trong query." });
    }

    const safeKeyword = escapeRegex(keyword);
    const searchRegex = new RegExp(safeKeyword, "i");
    const isUsernameLookup = Boolean(username) && !q;
    const currentUserId = req.user._id;

    const users = await User.find({
      _id: { $ne: currentUserId },
      $or: [
        { displayName: searchRegex },
        { username: searchRegex },
        { email: searchRegex },
      ],
    })
      .select("_id displayName username email avatarUrl bio phone createdAt updatedAt")
      .sort({ displayName: 1, username: 1 })
      .limit(isUsernameLookup ? 1 : 8)
      .lean();

    const relationshipMap = await buildRelationshipMap(currentUserId, users);
    const payload = users.map((user) =>
      toPublicUserPayload(user, relationshipMap.get(user._id.toString()))
    );

    return res.status(200).json({ user: payload[0] ?? null, users: payload });
  } catch (error) {
    console.error("Error while searching users", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getUserById = async (req, res) => {
  try {
    const { userId } = req.params;

    if (!userId || !userId.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ message: "User không hợp lệ" });
    }

    const user = await User.findById(userId)
      .select("_id displayName username email avatarUrl bio phone createdAt updatedAt")
      .lean();

    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy người dùng" });
    }

    const relationshipMap = await buildRelationshipMap(req.user._id, [user]);

    return res.status(200).json({
      user: toPublicUserPayload(user, relationshipMap.get(user._id.toString())),
    });
  } catch (error) {
    console.error("Error while getting user detail", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const uploadAvatar = async (req, res) => {
  try {
    const file = req.file;
    const userId = req.user._id;

    if (!file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const result = await uploadImageFromBuffer(file.buffer);

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        avatarUrl: result.secure_url,
        avatarId: result.public_id,
      },
      {
        new: true,
      }
    ).select("avatarUrl");

    if (!updatedUser.avatarUrl) {
      return res.status(400).json({ message: "Avatar trả về null" });
    }

    return res.status(200).json({ avatarUrl: updatedUser.avatarUrl });
  } catch (error) {
    console.error("Error while uploading avatar", error);
    return res.status(500).json({ message: "Upload failed" });
  }
};
