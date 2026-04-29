import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import {
  emitNewMessage,
  updateConversationAfterCreateMessage,
} from "../utils/messageHelper.js";
import { io } from "../socket/index.js";
import { uploadImageFromBuffer } from "../middlewares/uploadMiddleware.js";

const ALLOWED_REACTIONS = new Set(["👍", "❤️", "😂", "😮", "😢"]);

export const uploadMessageImage = async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ message: "Chưa chọn ảnh" });
    }

    if (!file.mimetype?.startsWith("image/")) {
      return res.status(400).json({ message: "File không phải là ảnh" });
    }

    const result = await uploadImageFromBuffer(file.buffer, {
      folder: "moji_chat/messages",
      transformation: [{ width: 1200, height: 1200, crop: "limit" }],
    });

    return res.status(200).json({ imgUrl: result.secure_url });
  } catch (error) {
    console.error("Lỗi xảy ra khi upload ảnh tin nhắn", error);
    return res.status(500).json({ message: "Upload ảnh thất bại" });
  }
};

export const revokeMessage = async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.user._id;

    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({ message: "Không tìm thấy tin nhắn" });
    }

    if (message.senderId.toString() !== userId.toString()) {
      return res.status(403).json({ message: "Bạn không thể thu hồi tin nhắn này" });
    }

    if (!message.isRevoked) {
      message.set({
        content: "",
        imgUrl: null,
        isRevoked: true,
        revokedAt: new Date(),
      });

      await message.save();
    }

    const conversation = await Conversation.findById(message.conversationId);

    if (
      conversation?.lastMessage?._id?.toString() === message._id.toString()
    ) {
      conversation.lastMessage.content = "Tin nhắn đã được thu hồi";
      await conversation.save();
    }

    const payload = {
      message,
      conversation: conversation
        ? {
            _id: conversation._id,
            lastMessage: conversation.lastMessage,
            lastMessageAt: conversation.lastMessageAt,
          }
        : null,
    };

    io.to(message.conversationId.toString()).emit("message-revoked", payload);

    return res.status(200).json(payload);
  } catch (error) {
    console.error("Lỗi xảy ra khi thu hồi tin nhắn", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const reactToMessage = async (req, res) => {
  try {
    const { messageId } = req.params;
    const { emoji } = req.body;
    const userId = req.user._id;

    if (!ALLOWED_REACTIONS.has(emoji)) {
      return res.status(400).json({ message: "Invalid reaction" });
    }

    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({ message: "Message not found" });
    }

    if (message.isRevoked) {
      return res.status(400).json({ message: "Cannot react to a revoked message" });
    }

    const conversation = await Conversation.findOne({
      _id: message.conversationId,
      "participants.userId": userId,
    });

    if (!conversation) {
      return res.status(403).json({ message: "You are not in this conversation" });
    }

    const existingReaction = message.reactions.find(
      (reaction) => reaction.user.toString() === userId.toString()
    );

    if (existingReaction) {
      existingReaction.emoji = emoji;
      existingReaction.createdAt = new Date();
    } else {
      message.reactions.push({
        user: userId,
        emoji,
        createdAt: new Date(),
      });
    }

    await message.save();

    const payload = {
      messageId: message._id,
      conversationId: message.conversationId,
      reactions: message.reactions,
    };

    io.to(message.conversationId.toString()).emit(
      "message:reaction_updated",
      payload
    );

    return res.status(200).json(payload);
  } catch (error) {
    console.error("Error reacting to message", error);
    return res.status(500).json({ message: "System error" });
  }
};

export const sendDirectMessage = async (req, res) => {
  try {
    const { recipientId, content = "", imgUrl, conversationId } = req.body;
    const senderId = req.user._id;

    let conversation;

    if (!content.trim() && !imgUrl) {
      return res.status(400).json({ message: "Thiếu nội dung" });
    }

    if (conversationId) {
      conversation = await Conversation.findById(conversationId);
    }

    if (!conversation) {
      conversation = await Conversation.create({
        type: "direct",
        participants: [
          { userId: senderId, joinedAt: new Date() },
          { userId: recipientId, joinedAt: new Date() },
        ],
        lastMessageAt: new Date(),
        unreadCounts: new Map(),
      });
    }

    const message = await Message.create({
      conversationId: conversation._id,
      senderId,
      content: content.trim(),
      imgUrl,
    });

    updateConversationAfterCreateMessage(conversation, message, senderId);

    await conversation.save();

    emitNewMessage(io, conversation, message);

    return res.status(201).json({ message });
  } catch (error) {
    console.error("Lỗi xảy ra khi gửi tin nhắn trực tiếp", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const sendGroupMessage = async (req, res) => {
  try {
    const { conversationId, content = "", imgUrl } = req.body;
    const senderId = req.user._id;
    const conversation = req.conversation;

    if (!content.trim() && !imgUrl) {
      return res.status(400).json({ message: "Thiếu nội dung" });
    }

    const message = await Message.create({
      conversationId,
      senderId,
      content: content.trim(),
      imgUrl,
    });

    updateConversationAfterCreateMessage(conversation, message, senderId);

    await conversation.save();
    emitNewMessage(io, conversation, message);

    return res.status(201).json({ message });
  } catch (error) {
    console.error("Lỗi xảy ra khi gửi tin nhắn nhóm", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};
