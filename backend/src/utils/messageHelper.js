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
  io.to(conversation._id.toString()).emit("new-message", {
    message,
    conversation: {
      _id: conversation._id,
      lastMessage: conversation.lastMessage,
      lastMessageAt: conversation.lastMessageAt,
    },
    unreadCounts: conversation.unreadCounts,
  });
};
