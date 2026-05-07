export const conversationPopulate = [
  { path: "participants.userId", select: "displayName avatarUrl username" },
  { path: "seenBy", select: "displayName avatarUrl" },
  { path: "lastMessage.senderId", select: "displayName avatarUrl" },
];

export const serializeUnreadCounts = (unreadCounts) => {
  if (!unreadCounts) {
    return {};
  }

  if (unreadCounts instanceof Map) {
    return Object.fromEntries(unreadCounts);
  }

  return unreadCounts;
};

export const formatConversationForClient = (conversation) => {
  const obj = conversation.toObject ? conversation.toObject() : conversation;
  const participants = (obj.participants || []).map((participant) => ({
    _id: participant.userId?._id,
    username: participant.userId?.username,
    displayName: participant.userId?.displayName,
    avatarUrl: participant.userId?.avatarUrl ?? null,
    joinedAt: participant.joinedAt,
    role: participant.role || "member",
  }));

  return {
    ...obj,
    unreadCounts: serializeUnreadCounts(obj.unreadCounts),
    participants,
  };
};

export const updateConversationAfterCreateMessage = (
  conversation,
  message,
  senderId
) => {
  const content =
    message.messageType === "trash_report"
      ? "Đã chia sẻ một điểm rác"
      : message.messageType === "system"
      ? message.content
      : message.content || (message.imgUrl ? "Đã gửi một ảnh" : "");

  conversation.set({
    seenBy: [],
    lastMessageAt: message.createdAt,
    lastMessage: {
      _id: message._id,
      content,
      senderId,
      createdAt: message.createdAt,
    },
  });

  conversation.participants.forEach((p) => {
    const memberId = p.userId.toString();
    const isSender = memberId === senderId.toString();
    const prevCount = conversation.unreadCounts.get(memberId) || 0;
    conversation.unreadCounts.set(memberId, isSender ? 0 : prevCount + 1);
  });
};

export const emitNewMessage = (io, conversation, message) => {
  const payload = {
    message,
    conversation: {
      _id: conversation._id,
      lastMessage: conversation.lastMessage,
      lastMessageAt: conversation.lastMessageAt,
    },
    unreadCounts: serializeUnreadCounts(conversation.unreadCounts),
  };

  io.to(conversation._id.toString()).emit("new-message", payload);

  (conversation.participants || []).forEach((participant) => {
    const userId =
      participant.userId?._id?.toString?.() || participant.userId?.toString?.();

    if (userId) {
      io.to(userId).emit("new-message", payload);
    }
  });
};
