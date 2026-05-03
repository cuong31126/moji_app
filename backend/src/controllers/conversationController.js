import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";
import Friend from "../models/Friend.js";
import GroupInvite, {
  GROUP_INVITE_STATUS,
} from "../models/GroupInvite.js";
import Message from "../models/Message.js";
import { uploadImageFromBuffer } from "../middlewares/uploadMiddleware.js";
import { io } from "../socket/index.js";

const conversationPopulate = [
  { path: "participants.userId", select: "displayName avatarUrl username" },
  { path: "seenBy", select: "displayName avatarUrl" },
  { path: "lastMessage.senderId", select: "displayName avatarUrl" },
];

const LEGACY_PENDING_STATUS = "pending";
const LEGACY_ACCEPTED_PENDING_ADMIN_STATUS = "accepted";

const toId = (value) => value?._id?.toString?.() || value?.toString?.();

const getFriendPair = (firstUserId, secondUserId) => {
  let userA = firstUserId.toString();
  let userB = secondUserId.toString();

  if (userA > userB) {
    [userA, userB] = [userB, userA];
  }

  return { userA, userB };
};

const isInviteExpired = (invite) =>
  invite.expiresAt && new Date(invite.expiresAt).getTime() < Date.now();

const groupInvitePopulate = [
  {
    path: "conversationId",
    populate: [
      { path: "participants.userId", select: "displayName avatarUrl username" },
      { path: "seenBy", select: "displayName avatarUrl" },
      { path: "lastMessage.senderId", select: "displayName avatarUrl" },
    ],
  },
  { path: "invitedBy", select: "_id username displayName avatarUrl" },
  { path: "invitee", select: "_id username displayName avatarUrl" },
  { path: "reportId", select: "_id title status" },
];

const formatConversation = (conversation) => {
  const obj = conversation.toObject ? conversation.toObject() : conversation;
  const participants = (obj.participants || []).map((p) => ({
    _id: p.userId?._id,
    username: p.userId?.username,
    displayName: p.userId?.displayName,
    avatarUrl: p.userId?.avatarUrl ?? null,
    joinedAt: p.joinedAt,
    role: p.role || "member",
  }));

  return {
    ...obj,
    unreadCounts: obj.unreadCounts || {},
    participants,
  };
};

const formatGroupInvite = (invite) => {
  const obj = invite.toObject ? invite.toObject() : invite;
  const conversation =
    obj.conversationId && typeof obj.conversationId === "object"
      ? formatConversation(obj.conversationId)
      : null;

  return {
    ...obj,
    conversationId: obj.conversationId?._id || obj.conversationId,
    conversation,
  };
};

const isParticipant = (conversation, userId) =>
  conversation.participants.some(
    (participant) => toId(participant.userId) === userId.toString()
  );

const isGroupAdmin = (conversation, userId) =>
  conversation.type === "group" &&
  conversation.participants.some(
    (participant) =>
      toId(participant.userId) === userId.toString() &&
      (participant.role === "admin" ||
        toId(conversation.group?.createdBy) === userId.toString())
  );

const addParticipantIfMissing = (conversation, userId, role = "member") => {
  if (isParticipant(conversation, userId)) {
    return false;
  }

  conversation.participants.push({
    userId,
    role,
    joinedAt: new Date(),
  });

  return true;
};

const ensureAtLeastOneAdmin = async (conversation, preferredAdminId = null) => {
  if (conversation.type !== "group" || conversation.participants.length === 0) {
    return;
  }

  const preferredParticipant = preferredAdminId
    ? conversation.participants.find(
        (participant) =>
          toId(participant.userId) === toId(preferredAdminId)
      )
    : null;

  if (preferredParticipant) {
    if (preferredParticipant.role === "admin") {
      return;
    }

    preferredParticipant.role = "admin";
    await conversation.save();
    return;
  }

  const hasAdmin = conversation.participants.some(
    (participant) => participant.role === "admin"
  );

  if (hasAdmin) {
    return;
  }

  const earliestMember = [...conversation.participants].sort(
    (a, b) => new Date(a.joinedAt) - new Date(b.joinedAt)
  )[0];

  earliestMember.role = "admin";
  await conversation.save();
};

const emitConversationToParticipants = async (conversation) => {
  await conversation.populate(conversationPopulate);
  const formatted = formatConversation(conversation);

  conversation.participants.forEach((participant) => {
    const participantId =
      participant.userId._id?.toString?.() || participant.userId.toString();
    io.to(participantId).emit("new-group", formatted);
  });

  return formatted;
};

const emitConversationUpdatedToParticipants = async (conversation) => {
  await conversation.populate(conversationPopulate);
  const formatted = formatConversation(conversation);

  conversation.participants.forEach((participant) => {
    const participantId = toId(participant.userId);
    io.to(participantId).emit("conversation:updated", formatted);
  });

  return formatted;
};

const emitConversationRemoved = (userIds, conversationId) => {
  userIds.forEach((userId) => {
    io.to(userId.toString()).emit("conversation:removed", {
      conversationId: conversationId.toString(),
    });
  });
};

const populateInviteById = async (inviteId) =>
  GroupInvite.findById(inviteId).populate(groupInvitePopulate);

export const createConversation = async (req, res) => {
  try {
    const { type, name, memberIds } = req.body;
    const userId = req.user._id;

    if (
      !type ||
      (type === "group" && !name) ||
      !memberIds ||
      !Array.isArray(memberIds) ||
      memberIds.length === 0
    ) {
      return res
        .status(400)
        .json({ message: "Tên nhóm và danh sách thành viên là bắt buộc" });
    }

    let conversation;

    if (type === "direct") {
      const participantId = memberIds[0];

      conversation = await Conversation.findOne({
        type: "direct",
        "participants.userId": { $all: [userId, participantId] },
      });

      if (!conversation) {
        conversation = new Conversation({
          type: "direct",
          participants: [{ userId }, { userId: participantId }],
          lastMessageAt: new Date(),
        });

        await conversation.save();
      }
    }

    if (type === "group") {
      conversation = new Conversation({
        type: "group",
        participants: [
          { userId, role: "admin" },
          ...memberIds.map((id) => ({ userId: id, role: "member" })),
        ],
        group: {
          name,
          createdBy: userId,
        },
        lastMessageAt: new Date(),
      });

      await conversation.save();
    }

    if (!conversation) {
      return res.status(400).json({ message: "Conversation type không hợp lệ" });
    }

    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);
    await conversation.populate(conversationPopulate);
    const formatted = formatConversation(conversation);

    if (type === "group") {
      memberIds.forEach((userId) => {
        io.to(userId).emit("new-group", formatted);
      });
    }

    return res.status(201).json({ conversation: formatted });
  } catch (error) {
    console.error("Lỗi khi tạo conversation", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getConversations = async (req, res) => {
  try {
    const userId = req.user._id;
    const conversations = await Conversation.find({
      "participants.userId": userId,
    })
      .sort({ lastMessageAt: -1, updatedAt: -1 })
      .populate(conversationPopulate);

    await Promise.all(
      conversations
        .filter((conversation) => conversation.type === "group")
        .map((conversation) =>
          ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy)
        )
    );

    const formatted = conversations.map((convo) => {
      const participants = (convo.participants || []).map((p) => ({
        _id: p.userId?._id,
        username: p.userId?.username,
        displayName: p.userId?.displayName,
        avatarUrl: p.userId?.avatarUrl ?? null,
        joinedAt: p.joinedAt,
        role: p.role || "member",
      }));

      return {
        ...convo.toObject(),
        unreadCounts: convo.unreadCounts || {},
        participants,
      };
    });

    return res.status(200).json({ conversations: formatted });
  } catch (error) {
    console.error("Lỗi xảy ra khi lấy conversations", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getMessages = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { limit = 50, cursor } = req.query;

    const query = { conversationId };

    if (cursor) {
      query.createdAt = { $lt: new Date(cursor) };
    }

    let messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .limit(Number(limit) + 1)
      .populate({
        path: "trashReport",
        select: "title description status type severity location images cleanedAt",
      });

    let nextCursor = null;

    if (messages.length > Number(limit)) {
      const nextMessage = messages[messages.length - 1];
      nextCursor = nextMessage.createdAt.toISOString();
      messages.pop();
    }

    messages = messages.reverse();

    return res.status(200).json({
      messages,
      nextCursor,
    });
  } catch (error) {
    console.error("Lỗi xảy ra khi lấy messages", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getUserConversationsForSocketIO = async (userId) => {
  try {
    const conversations = await Conversation.find(
      { "participants.userId": userId },
      { _id: 1 }
    );

    return conversations.map((c) => c._id.toString());
  } catch (error) {
    console.error("Lỗi khi fetch conversations: ", error);
    return [];
  }
};

export const markAsSeen = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user._id.toString();

    const conversation = await Conversation.findById(conversationId).lean();

    if (!conversation) {
      return res.status(404).json({ message: "Conversation không tồn tại" });
    }

    const last = conversation.lastMessage;

    if (!last) {
      return res.status(200).json({ message: "Không có tin nhắn để mark as seen" });
    }

    if (last.senderId.toString() === userId) {
      return res.status(200).json({ message: "Sender không cần mark as seen" });
    }

    const updated = await Conversation.findByIdAndUpdate(
      conversationId,
      {
        $addToSet: { seenBy: userId },
        $set: { [`unreadCounts.${userId}`]: 0 },
      },
      {
        new: true,
      }
    );

    io.to(conversationId).emit("read-message", {
      conversation: updated,
      lastMessage: {
        _id: updated?.lastMessage._id,
        content: updated?.lastMessage.content,
        createdAt: updated?.lastMessage.createdAt,
        sender: {
          _id: updated?.lastMessage.senderId,
        },
      },
    });

    return res.status(200).json({
      message: "Marked as seen",
      seenBy: updated?.seenBy || [],
      myUnreadCount:
        updated?.unreadCounts?.get?.(userId) ??
        updated?.unreadCounts?.[userId] ??
        0,
    });
  } catch (error) {
    console.error("Lỗi khi mark as seen", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const updateGroupAvatar = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user._id;

    if (!mongoose.isValidObjectId(conversationId)) {
      return res.status(400).json({ message: "Nhóm chat không hợp lệ" });
    }

    if (!req.file) {
      return res.status(400).json({ message: "Vui lòng chọn ảnh nhóm" });
    }

    if (!req.file.mimetype?.startsWith("image/")) {
      return res.status(400).json({ message: "File tải lên phải là ảnh" });
    }

    const conversation = await Conversation.findById(conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Không tìm thấy nhóm chat" });
    }

    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);

    if (!isParticipant(conversation, userId)) {
      return res.status(403).json({ message: "Bạn không thuộc nhóm chat này" });
    }

    if (!isGroupAdmin(conversation, userId)) {
      return res
        .status(403)
        .json({ message: "Chỉ quản trị viên mới được đổi ảnh nhóm" });
    }

    const result = await uploadImageFromBuffer(req.file.buffer, {
      folder: "moji_chat/group_avatars",
      transformation: [{ width: 512, height: 512, crop: "fill" }],
    });

    if (!conversation.group) {
      conversation.group = {};
    }

    conversation.group.avatarUrl = result.secure_url;
    await conversation.save();

    const formattedConversation =
      await emitConversationUpdatedToParticipants(conversation);

    return res.status(200).json({ conversation: formattedConversation });
  } catch (error) {
    console.error("Lỗi khi cập nhật ảnh nhóm", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const updateGroupInfo = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user._id;
    const name = req.body?.name?.trim();

    if (!mongoose.isValidObjectId(conversationId)) {
      return res.status(400).json({ message: "Nhóm chat không hợp lệ" });
    }

    if (!name) {
      return res.status(400).json({ message: "Tên nhóm không được để trống" });
    }

    if (name.length > 80) {
      return res
        .status(400)
        .json({ message: "Tên nhóm không được vượt quá 80 ký tự" });
    }

    const conversation = await Conversation.findById(conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Không tìm thấy nhóm chat" });
    }

    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);

    if (!isParticipant(conversation, userId)) {
      return res.status(403).json({ message: "Bạn không thuộc nhóm chat này" });
    }

    if (!isGroupAdmin(conversation, userId)) {
      return res
        .status(403)
        .json({ message: "Chỉ quản trị viên mới được đổi tên nhóm" });
    }

    if (!conversation.group) {
      conversation.group = {};
    }

    conversation.group.name = name;
    await conversation.save();

    const formattedConversation =
      await emitConversationUpdatedToParticipants(conversation);

    return res.status(200).json({ conversation: formattedConversation });
  } catch (error) {
    console.error("Lỗi khi cập nhật thông tin nhóm", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const inviteGroupMembers = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user._id;
    const rawFriendIds = req.body?.friendIds || req.body?.memberIds || [];

    if (!mongoose.isValidObjectId(conversationId)) {
      return res.status(400).json({ message: "Nhóm chat không hợp lệ" });
    }

    if (!Array.isArray(rawFriendIds) || rawFriendIds.length === 0) {
      return res.status(400).json({ message: "Cần chọn ít nhất một bạn bè" });
    }

    const conversation = await Conversation.findById(conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Không tìm thấy nhóm chat" });
    }

    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);

    if (!isParticipant(conversation, userId)) {
      return res.status(403).json({ message: "Bạn không thuộc nhóm chat này" });
    }

    const uniqueFriendIds = [
      ...new Set(rawFriendIds.map((id) => id?.toString?.() || id)),
    ].filter(
      (id) => mongoose.isValidObjectId(id) && id !== userId.toString()
    );

    if (uniqueFriendIds.length === 0) {
      return res.status(400).json({ message: "Danh sách mời không hợp lệ" });
    }

    const friendChecks = await Promise.all(
      uniqueFriendIds.map(async (friendId) => {
        const { userA, userB } = getFriendPair(userId, friendId);
        const friendship = await Friend.findOne({ userA, userB }).lean();
        return friendship ? friendId : null;
      })
    );
    const allowedFriendIds = friendChecks.filter(Boolean);

    if (allowedFriendIds.length === 0) {
      return res
        .status(403)
        .json({ message: "Bạn chỉ có thể mời bạn bè vào nhóm chat" });
    }

    const existingMemberIds = new Set(
      conversation.participants.map((participant) => toId(participant.userId))
    );
    const activeInvites = await GroupInvite.find({
      conversationId: conversation._id,
      invitee: { $in: allowedFriendIds },
      status: {
        $in: [
          GROUP_INVITE_STATUS.PENDING_USER,
          GROUP_INVITE_STATUS.PENDING_ADMIN,
          GROUP_INVITE_STATUS.ACCEPTED,
          LEGACY_PENDING_STATUS,
          LEGACY_ACCEPTED_PENDING_ADMIN_STATUS,
        ],
      },
      rejectedAt: null,
      $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
    }).lean();
    const activeInviteeIds = new Set(
      activeInvites.map((invite) => invite.invitee.toString())
    );
    const invitedIds = [];

    await Promise.all(
      allowedFriendIds.map(async (friendId) => {
        if (existingMemberIds.has(friendId) || activeInviteeIds.has(friendId)) {
          return;
        }

        const invite = await GroupInvite.create({
          conversationId: conversation._id,
          invitedBy: userId,
          invitee: friendId,
          message: `${req.user.displayName || "Moji"} mời bạn tham gia nhóm chat.`,
        });

        invitedIds.push(friendId);
        io.to(friendId).emit("group-invite:created", {
          inviteId: invite._id,
          conversationId: conversation._id,
        });
      })
    );

    const formattedConversation =
      await emitConversationUpdatedToParticipants(conversation);

    return res.status(200).json({
      conversation: formattedConversation,
      invitedIds,
    });
  } catch (error) {
    console.error("Lỗi khi mời thành viên vào nhóm", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const updateGroupMemberRole = async (req, res) => {
  try {
    const { conversationId, memberId } = req.params;
    const { role } = req.body;
    const userId = req.user._id;

    if (
      !mongoose.isValidObjectId(conversationId) ||
      !mongoose.isValidObjectId(memberId)
    ) {
      return res.status(400).json({ message: "Thông tin thành viên không hợp lệ" });
    }

    if (!["admin", "member"].includes(role)) {
      return res.status(400).json({ message: "Vai trò không hợp lệ" });
    }

    const conversation = await Conversation.findById(conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Không tìm thấy nhóm chat" });
    }

    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);

    if (!isGroupAdmin(conversation, userId)) {
      return res
        .status(403)
        .json({ message: "Chỉ quản trị viên mới được phân quyền" });
    }

    const targetParticipant = conversation.participants.find(
      (participant) => toId(participant.userId) === memberId
    );

    if (!targetParticipant) {
      return res.status(404).json({ message: "Không tìm thấy thành viên" });
    }

    if (
      role === "member" &&
      toId(conversation.group?.createdBy) === memberId
    ) {
      return res
        .status(400)
        .json({ message: "Không thể gỡ quyền quản trị của người tạo nhóm" });
    }

    const adminCount = conversation.participants.filter(
      (participant) => participant.role === "admin"
    ).length;

    if (
      role === "member" &&
      targetParticipant.role === "admin" &&
      adminCount <= 1
    ) {
      return res
        .status(400)
        .json({ message: "Nhóm cần có ít nhất một quản trị viên" });
    }

    targetParticipant.role = role;
    await conversation.save();

    const formattedConversation =
      await emitConversationUpdatedToParticipants(conversation);

    return res.status(200).json({ conversation: formattedConversation });
  } catch (error) {
    console.error("Lỗi khi phân quyền thành viên nhóm", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const removeGroupMember = async (req, res) => {
  try {
    const { conversationId, memberId } = req.params;
    const userId = req.user._id;

    if (
      !mongoose.isValidObjectId(conversationId) ||
      !mongoose.isValidObjectId(memberId)
    ) {
      return res.status(400).json({ message: "Thông tin thành viên không hợp lệ" });
    }

    const conversation = await Conversation.findById(conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Không tìm thấy nhóm chat" });
    }

    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);

    if (!isGroupAdmin(conversation, userId)) {
      return res
        .status(403)
        .json({ message: "Chỉ quản trị viên mới được xóa thành viên" });
    }

    if (memberId === userId.toString()) {
      return res
        .status(400)
        .json({ message: "Hãy dùng thao tác rời nhóm cho tài khoản của bạn" });
    }

    if (toId(conversation.group?.createdBy) === memberId) {
      return res
        .status(400)
        .json({ message: "Không thể xóa người tạo nhóm khỏi nhóm" });
    }

    const targetExists = conversation.participants.some(
      (participant) => toId(participant.userId) === memberId
    );

    if (!targetExists) {
      return res.status(404).json({ message: "Không tìm thấy thành viên" });
    }

    conversation.participants = conversation.participants.filter(
      (participant) => toId(participant.userId) !== memberId
    );

    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);
    await conversation.save();

    await GroupInvite.updateMany(
      {
        conversationId: conversation._id,
        invitee: memberId,
        status: {
          $in: [
            GROUP_INVITE_STATUS.PENDING_USER,
            GROUP_INVITE_STATUS.PENDING_ADMIN,
            LEGACY_PENDING_STATUS,
            LEGACY_ACCEPTED_PENDING_ADMIN_STATUS,
          ],
        },
      },
      {
        $set: {
          status: GROUP_INVITE_STATUS.REJECTED,
          rejectedBy: userId,
          rejectedAt: new Date(),
        },
      }
    );

    emitConversationRemoved([memberId], conversation._id);
    const formattedConversation =
      await emitConversationUpdatedToParticipants(conversation);

    return res.status(200).json({ conversation: formattedConversation });
  } catch (error) {
    console.error("Lỗi khi xóa thành viên khỏi nhóm", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const leaveGroupConversation = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user._id;

    if (!mongoose.isValidObjectId(conversationId)) {
      return res.status(400).json({ message: "Nhóm chat không hợp lệ" });
    }

    const conversation = await Conversation.findById(conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Không tìm thấy nhóm chat" });
    }

    if (!isParticipant(conversation, userId)) {
      return res.status(403).json({ message: "Bạn không thuộc nhóm chat này" });
    }

    const remainingParticipants = conversation.participants.filter(
      (participant) => toId(participant.userId) !== userId.toString()
    );

    if (remainingParticipants.length === 0) {
      await Promise.all([
        Message.deleteMany({ conversationId: conversation._id }),
        GroupInvite.deleteMany({ conversationId: conversation._id }),
        Conversation.deleteOne({ _id: conversation._id }),
      ]);
      emitConversationRemoved([userId], conversation._id);

      return res.status(200).json({ conversationId: conversation._id });
    }

    conversation.participants = remainingParticipants;
    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);
    await conversation.save();

    emitConversationRemoved([userId], conversation._id);
    const formattedConversation =
      await emitConversationUpdatedToParticipants(conversation);

    return res.status(200).json({
      conversation: formattedConversation,
      conversationId: conversation._id,
    });
  } catch (error) {
    console.error("Lỗi khi rời nhóm", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const deleteGroupConversation = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user._id;

    if (!mongoose.isValidObjectId(conversationId)) {
      return res.status(400).json({ message: "Nhóm chat không hợp lệ" });
    }

    const conversation = await Conversation.findById(conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Không tìm thấy nhóm chat" });
    }

    await ensureAtLeastOneAdmin(conversation, conversation.group?.createdBy);

    if (!isGroupAdmin(conversation, userId)) {
      return res
        .status(403)
        .json({ message: "Chỉ quản trị viên mới được xóa nhóm" });
    }

    const participantIds = conversation.participants.map((participant) =>
      toId(participant.userId)
    );

    await Promise.all([
      Message.deleteMany({ conversationId: conversation._id }),
      GroupInvite.deleteMany({ conversationId: conversation._id }),
      Conversation.deleteOne({ _id: conversation._id }),
    ]);

    emitConversationRemoved(participantIds, conversation._id);

    return res.status(200).json({ conversationId: conversation._id });
  } catch (error) {
    console.error("Lỗi khi xóa nhóm chat", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getGroupInvites = async (req, res) => {
  try {
    const userId = req.user._id;
    const adminConversations = await Conversation.find(
      {
        type: "group",
        $or: [
          {
            participants: {
              $elemMatch: {
                userId,
                role: "admin",
              },
            },
          },
          {
            "group.createdBy": userId,
            "participants.userId": userId,
          },
        ],
      },
      { _id: 1 }
    ).lean();
    const adminConversationIds = adminConversations.map((item) => item._id);

    const [incoming, adminApprovals] = await Promise.all([
      GroupInvite.find({
        invitee: userId,
        status: {
          $in: [GROUP_INVITE_STATUS.PENDING_USER, LEGACY_PENDING_STATUS],
        },
        $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
      })
        .sort({ createdAt: -1 })
        .populate(groupInvitePopulate),
      GroupInvite.find({
        conversationId: { $in: adminConversationIds },
        status: {
          $in: [
            GROUP_INVITE_STATUS.PENDING_ADMIN,
            LEGACY_ACCEPTED_PENDING_ADMIN_STATUS,
          ],
        },
        approvedAt: null,
        $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
      })
        .sort({ acceptedAt: 1, createdAt: 1 })
        .populate(groupInvitePopulate),
    ]);

    return res.status(200).json({
      incoming: incoming.map(formatGroupInvite),
      adminApprovals: adminApprovals.map(formatGroupInvite),
    });
  } catch (error) {
    console.error("Loi khi lay group invites", error);
    return res.status(500).json({ message: "Loi he thong" });
  }
};

export const acceptGroupInvite = async (req, res) => {
  try {
    const { inviteId } = req.params;
    const userId = req.user._id;

    if (!mongoose.isValidObjectId(inviteId)) {
      return res.status(400).json({ message: "Loi moi khong hop le" });
    }

    const invite = await GroupInvite.findById(inviteId);

    if (!invite) {
      return res.status(404).json({ message: "Khong tim thay loi moi" });
    }

    if (toId(invite.invitee) !== userId.toString()) {
      return res.status(403).json({ message: "Ban khong the xu ly loi moi nay" });
    }

    if (
      ![GROUP_INVITE_STATUS.PENDING_USER, LEGACY_PENDING_STATUS].includes(
        invite.status
      )
    ) {
      return res.status(400).json({ message: "Loi moi da duoc xu ly" });
    }

    if (isInviteExpired(invite)) {
      invite.status = GROUP_INVITE_STATUS.REJECTED;
      invite.rejectedAt = new Date();
      await invite.save();
      return res.status(410).json({ message: "Loi moi da het han" });
    }

    const conversation = await Conversation.findById(invite.conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Khong tim thay nhom chat" });
    }

    await ensureAtLeastOneAdmin(conversation);

    const inviterIsAdmin = isGroupAdmin(conversation, invite.invitedBy);
    invite.acceptedAt = new Date();

    let formattedConversation = null;

    if (inviterIsAdmin || isParticipant(conversation, userId)) {
      addParticipantIfMissing(conversation, userId, "member");
      invite.status = GROUP_INVITE_STATUS.ACCEPTED;
      invite.approvedBy = inviterIsAdmin ? invite.invitedBy : userId;
      invite.approvedAt = new Date();
      await conversation.save();
      formattedConversation = await emitConversationToParticipants(conversation);
    } else {
      invite.status = GROUP_INVITE_STATUS.PENDING_ADMIN;
      const adminIds = conversation.participants
        .filter((participant) => participant.role === "admin")
        .map((participant) => toId(participant.userId));

      adminIds.forEach((adminId) => {
        io.to(adminId).emit("group-invite:needs_approval", {
          inviteId: invite._id,
          conversationId: conversation._id,
        });
      });
    }

    await invite.save();
    const populatedInvite = await populateInviteById(invite._id);

    io.to(userId.toString()).emit("group-invite:updated", {
      invite: formatGroupInvite(populatedInvite),
    });

    return res.status(200).json({
      invite: formatGroupInvite(populatedInvite),
      conversation: formattedConversation,
    });
  } catch (error) {
    console.error("Loi khi chap nhan group invite", error);
    return res.status(500).json({ message: "Loi he thong" });
  }
};

export const rejectGroupInvite = async (req, res) => {
  try {
    const { inviteId } = req.params;
    const userId = req.user._id;

    if (!mongoose.isValidObjectId(inviteId)) {
      return res.status(400).json({ message: "Loi moi khong hop le" });
    }

    const invite = await GroupInvite.findById(inviteId);

    if (!invite) {
      return res.status(404).json({ message: "Khong tim thay loi moi" });
    }

    const conversation = await Conversation.findById(invite.conversationId);
    const isInvitee = toId(invite.invitee) === userId.toString();
    const canAdminReject =
      conversation &&
      isGroupAdmin(conversation, userId) &&
      [GROUP_INVITE_STATUS.PENDING_ADMIN, LEGACY_ACCEPTED_PENDING_ADMIN_STATUS].includes(
        invite.status
      ) &&
      !invite.approvedAt;

    if (!isInvitee && !canAdminReject) {
      return res.status(403).json({ message: "Ban khong co quyen tu choi loi moi nay" });
    }

    if (invite.status === GROUP_INVITE_STATUS.REJECTED || invite.approvedAt) {
      return res.status(400).json({ message: "Loi moi da duoc xu ly" });
    }

    if (isInviteExpired(invite)) {
      invite.status = GROUP_INVITE_STATUS.REJECTED;
      invite.rejectedAt = new Date();
      await invite.save();
      return res.status(410).json({ message: "Loi moi da het han" });
    }

    invite.status = GROUP_INVITE_STATUS.REJECTED;
    invite.rejectedBy = userId;
    invite.rejectedAt = new Date();
    await invite.save();

    const populatedInvite = await populateInviteById(invite._id);
    const formattedInvite = formatGroupInvite(populatedInvite);

    io.to(invite.invitee.toString()).emit("group-invite:updated", {
      invite: formattedInvite,
    });

    return res.status(200).json({ invite: formattedInvite });
  } catch (error) {
    console.error("Loi khi tu choi group invite", error);
    return res.status(500).json({ message: "Loi he thong" });
  }
};

export const approveGroupInvite = async (req, res) => {
  try {
    const { inviteId } = req.params;
    const userId = req.user._id;

    if (!mongoose.isValidObjectId(inviteId)) {
      return res.status(400).json({ message: "Loi moi khong hop le" });
    }

    const invite = await GroupInvite.findById(inviteId);

    if (!invite) {
      return res.status(404).json({ message: "Khong tim thay loi moi" });
    }

    const conversation = await Conversation.findById(invite.conversationId);

    if (!conversation || conversation.type !== "group") {
      return res.status(404).json({ message: "Khong tim thay nhom chat" });
    }

    await ensureAtLeastOneAdmin(conversation);

    if (!isGroupAdmin(conversation, userId)) {
      return res.status(403).json({ message: "Chi admin moi duoc duyet loi moi" });
    }

    if (
      ![
        GROUP_INVITE_STATUS.PENDING_ADMIN,
        LEGACY_ACCEPTED_PENDING_ADMIN_STATUS,
      ].includes(invite.status) ||
      invite.approvedAt ||
      invite.rejectedAt
    ) {
      return res.status(400).json({ message: "Loi moi chua san sang de duyet" });
    }

    if (isInviteExpired(invite)) {
      invite.status = GROUP_INVITE_STATUS.REJECTED;
      invite.rejectedAt = new Date();
      await invite.save();
      return res.status(410).json({ message: "Loi moi da het han" });
    }

    addParticipantIfMissing(conversation, invite.invitee, "member");
    invite.status = GROUP_INVITE_STATUS.ACCEPTED;
    invite.approvedBy = userId;
    invite.approvedAt = new Date();

    await conversation.save();
    await invite.save();

    const formattedConversation = await emitConversationToParticipants(conversation);
    const populatedInvite = await populateInviteById(invite._id);
    const formattedInvite = formatGroupInvite(populatedInvite);

    io.to(invite.invitee.toString()).emit("group-invite:approved", {
      invite: formattedInvite,
      conversation: formattedConversation,
    });

    return res.status(200).json({
      invite: formattedInvite,
      conversation: formattedConversation,
    });
  } catch (error) {
    console.error("Loi khi duyet group invite", error);
    return res.status(500).json({ message: "Loi he thong" });
  }
};
