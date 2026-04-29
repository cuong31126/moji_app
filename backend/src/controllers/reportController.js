import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";
import Friend from "../models/Friend.js";
import Message from "../models/Message.js";
import TrashComment from "../models/TrashComment.js";
import TrashReport, {
  TRASH_REPORT_STATUS,
} from "../models/TrashReport.js";
import { uploadImageFromBuffer } from "../middlewares/uploadMiddleware.js";
import {
  emitNewMessage,
  updateConversationAfterCreateMessage,
} from "../utils/messageHelper.js";
import { io } from "../socket/index.js";

const REQUIRED_VERIFICATIONS = 2;
const REQUIRED_CLEAN_CONFIRMATIONS = 2;

const reportPopulate = [
  { path: "createdBy", select: "_id username displayName avatarUrl" },
  { path: "cleanup.cleanedBy", select: "_id username displayName avatarUrl" },
];

const conversationPopulate = [
  { path: "participants.userId", select: "displayName avatarUrl username" },
  { path: "seenBy", select: "displayName avatarUrl" },
  { path: "lastMessage.senderId", select: "displayName avatarUrl" },
];

const getFriendPair = (firstUserId, secondUserId) => {
  let userA = firstUserId.toString();
  let userB = secondUserId.toString();

  if (userA > userB) {
    [userA, userB] = [userB, userA];
  }

  return { userA, userB };
};

const buildLocation = ({ lat, lng, address = "" }) => ({
  type: "Point",
  coordinates: [lng, lat],
  lat,
  lng,
  address,
});

const getReportPosition = (report) => {
  const lat = report.location?.lat;
  const lng = report.location?.lng;

  if (Number.isFinite(lat) && Number.isFinite(lng)) {
    return { lat, lng };
  }

  const [geoLng, geoLat] = report.location?.coordinates || [];

  if (Number.isFinite(geoLat) && Number.isFinite(geoLng)) {
    return { lat: geoLat, lng: geoLng };
  }

  return null;
};

const getDistanceMeters = (from, to) => {
  const earthRadius = 6371000;
  const toRad = (value) => (value * Math.PI) / 180;
  const dLat = toRad(to.lat - from.lat);
  const dLng = toRad(to.lng - from.lng);
  const lat1 = toRad(from.lat);
  const lat2 = toRad(to.lat);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1) *
      Math.cos(lat2) *
      Math.sin(dLng / 2) *
      Math.sin(dLng / 2);

  return earthRadius * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
};

const isMissingGeoIndexError = (error) =>
  error?.message?.includes("unable to find index for $geoNear query") ||
  error?.codeName === "IndexNotFound";

const formatConversation = (conversation) => {
  const obj = conversation.toObject ? conversation.toObject() : conversation;
  const participants = (obj.participants || []).map((p) => ({
    _id: p.userId?._id,
    username: p.userId?.username,
    displayName: p.userId?.displayName,
    avatarUrl: p.userId?.avatarUrl ?? null,
    joinedAt: p.joinedAt,
  }));

  return {
    ...obj,
    unreadCounts: obj.unreadCounts || {},
    participants,
  };
};

const uploadFiles = async (files = [], folder = "moji_eco/reports") => {
  if (!files.length) {
    return [];
  }

  const uploads = files.map((file) =>
    uploadImageFromBuffer(file.buffer, {
      folder,
      transformation: [{ width: 1400, height: 1400, crop: "limit" }],
    })
  );

  const results = await Promise.all(uploads);
  return results.map((result) => result.secure_url);
};

const ensureReport = async (reportId) => {
  if (!mongoose.isValidObjectId(reportId)) {
    return null;
  }

  return TrashReport.findById(reportId);
};

const emitReportUpdated = (report) => {
  io.emit("trash-report-updated", { report });
};

const ensureReportConversation = async (report, userId) => {
  let conversation = report.conversationId
    ? await Conversation.findById(report.conversationId)
    : null;

  if (!conversation) {
    const shortTitle = report.title.slice(0, 42);
    conversation = await Conversation.create({
      type: "group",
      participants: [{ userId }],
      group: {
        name: `Cleanup: ${shortTitle}`,
        createdBy: userId,
      },
      lastMessageAt: new Date(),
      unreadCounts: new Map(),
    });

    report.conversationId = conversation._id;
    await report.save();
  } else {
    const isMember = conversation.participants.some(
      (p) => p.userId.toString() === userId.toString()
    );

    if (!isMember) {
      conversation.participants.push({ userId });
      await conversation.save();
    }
  }

  return conversation;
};

const sendReportSystemMessage = async (report, actorId, content) => {
  if (!report.conversationId) {
    return null;
  }

  const conversation = await Conversation.findById(report.conversationId);

  if (!conversation) {
    return null;
  }

  const message = await Message.create({
    conversationId: conversation._id,
    senderId: actorId,
    content,
    messageType: "system",
  });

  updateConversationAfterCreateMessage(conversation, message, actorId);
  await conversation.save();
  emitNewMessage(io, conversation, message);

  return message;
};

const emitConversationToParticipants = async (conversation) => {
  await conversation.populate(conversationPopulate);
  const formatted = formatConversation(conversation);

  conversation.participants.forEach((participant) => {
    io.to(participant.userId._id?.toString?.() || participant.userId.toString()).emit(
      "new-group",
      formatted
    );
  });

  return formatted;
};

export const getReports = async (req, res) => {
  try {
    const { status, lat, lng, limit = 100, maxDistance = 50000 } = req.query;
    const query = {};
    const userLat = Number(lat);
    const userLng = Number(lng);
    const hasUserLocation = Number.isFinite(userLat) && Number.isFinite(userLng);
    const limitNumber = Math.min(Number(limit) || 100, 200);
    const maxDistanceMeters = Math.min(Number(maxDistance) || 50000, 200000);

    if (status && status !== "ALL") {
      query.status = status;
    }

    if (hasUserLocation) {
      query.location = {
        $near: {
          $geometry: {
            type: "Point",
            coordinates: [userLng, userLat],
          },
          $maxDistance: maxDistanceMeters,
        },
      };
    }

    let reportQuery = TrashReport.find(query).limit(limitNumber);

    if (!hasUserLocation) {
      reportQuery = reportQuery.sort({ createdAt: -1 });
    }

    let reports;

    try {
      reports = await reportQuery.populate(reportPopulate).lean();
    } catch (error) {
      if (!hasUserLocation || !isMissingGeoIndexError(error)) {
        throw error;
      }

      console.warn(
        "[trash-reports] Missing 2dsphere index on location; falling back to in-memory distance sort. Run TrashReport.syncIndexes() or createIndex({ location: '2dsphere' }).",
        error.message
      );

      const fallbackQuery = { ...query };
      delete fallbackQuery.location;

      reports = await TrashReport.find(fallbackQuery)
        .sort({ createdAt: -1 })
        .limit(1000)
        .populate(reportPopulate)
        .lean();
    }

    if (hasUserLocation) {
      const from = { lat: userLat, lng: userLng };
      reports = reports
        .map((report) => ({
          ...report,
          distanceMeters: Math.round(
            getDistanceMeters(from, getReportPosition(report) || from)
          ),
        }))
        .filter((report) => report.distanceMeters <= maxDistanceMeters)
        .sort((a, b) => a.distanceMeters - b.distanceMeters);

      reports = reports.slice(0, limitNumber);
    }

    return res.status(200).json({ reports });
  } catch (error) {
    console.error("Lỗi khi lấy danh sách điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getReportById = async (req, res) => {
  try {
    const report = await TrashReport.findById(req.params.id)
      .populate(reportPopulate)
      .lean();

    if (!report) {
      return res.status(404).json({ message: "Không tìm thấy điểm rác" });
    }

    return res.status(200).json({ report });
  } catch (error) {
    console.error("Lỗi khi lấy chi tiết điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const createReport = async (req, res) => {
  try {
    const { description, type, severity, lat, lng, address = "", title } = req.body;
    const parsedLat = Number(lat);
    const parsedLng = Number(lng);

    if (!description?.trim()) {
      return res.status(400).json({ message: "Mô tả điểm rác là bắt buộc" });
    }

    if (!Number.isFinite(parsedLat) || !Number.isFinite(parsedLng)) {
      return res.status(400).json({ message: "Tọa độ không hợp lệ" });
    }

    const images = await uploadFiles(req.files);
    const cleanDescription = description.trim();
    const reportTitle =
      title?.trim() || cleanDescription.slice(0, 80) || "Điểm rác mới";

    let report = await TrashReport.create({
      title: reportTitle,
      description: cleanDescription,
      type,
      severity,
      location: buildLocation({
        lat: parsedLat,
        lng: parsedLng,
        address,
      }),
      images,
      createdBy: req.user._id,
    });

    report = await report.populate(reportPopulate);

    io.emit("new-trash-report", { report });

    return res.status(201).json({ report });
  } catch (error) {
    console.error("Lỗi khi tạo điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const verifyReport = async (req, res) => {
  try {
    const report = await ensureReport(req.params.id);
    const userId = req.user._id.toString();
    const previousStatus = report?.status;

    if (!report) {
      return res.status(404).json({ message: "Không tìm thấy điểm rác" });
    }

    if (report.status === TRASH_REPORT_STATUS.CLEANED) {
      return res.status(400).json({ message: "Điểm rác này đã được dọn sạch" });
    }

    const alreadyVerified = report.verifications.some(
      (item) => item.userId.toString() === userId
    );

    if (alreadyVerified) {
      return res.status(400).json({ message: "Bạn đã xác nhận điểm rác này" });
    }

    report.verifications.push({ userId: req.user._id });

    if (
      report.status === TRASH_REPORT_STATUS.ACTIVE &&
      report.verifications.length >= REQUIRED_VERIFICATIONS
    ) {
      report.status = TRASH_REPORT_STATUS.VERIFIED;
    }

    await report.save();
    await report.populate(reportPopulate);
    emitReportUpdated(report);
    await sendReportSystemMessage(
      report,
      req.user._id,
      previousStatus === TRASH_REPORT_STATUS.ACTIVE &&
        report.status === TRASH_REPORT_STATUS.VERIFIED
        ? `${req.user.displayName} đã xác nhận điểm rác. Report đã đủ xác nhận.`
        : `${req.user.displayName} đã xác nhận điểm rác.`
    );

    return res.status(200).json({ report });
  } catch (error) {
    console.error("Lỗi khi xác nhận điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const cleanupReport = async (req, res) => {
  try {
    const report = await ensureReport(req.params.id);

    if (!report) {
      return res.status(404).json({ message: "Không tìm thấy điểm rác" });
    }

    if (report.status === TRASH_REPORT_STATUS.CLEANED) {
      return res.status(400).json({ message: "Điểm rác này đã được dọn sạch" });
    }

    const afterImages = await uploadFiles(req.files, "moji_eco/cleanups");

    report.cleanup = {
      cleanedBy: req.user._id,
      beforeImages: report.images,
      afterImages,
      description: req.body.description?.trim() || "",
      createdAt: new Date(),
    };
    report.cleanupConfirmations = [];
    report.status = TRASH_REPORT_STATUS.CLEANUP_PENDING;

    await report.save();
    await report.populate(reportPopulate);
    emitReportUpdated(report);
    await sendReportSystemMessage(
      report,
      req.user._id,
      `${req.user.displayName} đã báo điểm rác được dọn và chờ cộng đồng xác nhận.`
    );

    return res.status(200).json({ report });
  } catch (error) {
    console.error("Lỗi khi báo đã dọn điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const confirmCleanReport = async (req, res) => {
  try {
    const report = await ensureReport(req.params.id);
    const userId = req.user._id.toString();

    if (!report) {
      return res.status(404).json({ message: "Không tìm thấy điểm rác" });
    }

    if (report.status !== TRASH_REPORT_STATUS.CLEANUP_PENDING) {
      return res
        .status(400)
        .json({ message: "Điểm rác chưa ở trạng thái chờ xác nhận sạch" });
    }

    const alreadyConfirmed = report.cleanupConfirmations.some(
      (item) => item.userId.toString() === userId
    );

    if (alreadyConfirmed) {
      return res.status(400).json({ message: "Bạn đã xác nhận sạch điểm này" });
    }

    let becameCleaned = false;
    report.cleanupConfirmations.push({ userId: req.user._id });

    if (report.cleanupConfirmations.length >= REQUIRED_CLEAN_CONFIRMATIONS) {
      report.status = TRASH_REPORT_STATUS.CLEANED;
      becameCleaned = true;
    }

    await report.save();
    await report.populate(reportPopulate);
    emitReportUpdated(report);
    if (becameCleaned) {
      io.emit("trash-report-cleaned", { report });
    }
    await sendReportSystemMessage(
      report,
      req.user._id,
      report.status === TRASH_REPORT_STATUS.CLEANED
        ? `${req.user.displayName} đã xác nhận sạch. Report đã được dọn sạch.`
        : `${req.user.displayName} đã xác nhận điểm rác đã sạch.`
    );

    return res.status(200).json({ report });
  } catch (error) {
    console.error("Lỗi khi xác nhận đã sạch", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const getReportComments = async (req, res) => {
  try {
    const comments = await TrashComment.find({ reportId: req.params.id })
      .sort({ createdAt: 1 })
      .populate("userId", "_id username displayName avatarUrl")
      .lean();

    return res.status(200).json({ comments });
  } catch (error) {
    console.error("Lỗi khi lấy bình luận điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const addReportComment = async (req, res) => {
  try {
    const { content } = req.body;
    const report = await ensureReport(req.params.id);

    if (!report) {
      return res.status(404).json({ message: "Không tìm thấy điểm rác" });
    }

    if (!content?.trim()) {
      return res.status(400).json({ message: "Nội dung bình luận là bắt buộc" });
    }

    let comment = await TrashComment.create({
      reportId: report._id,
      userId: req.user._id,
      content: content.trim(),
    });

    comment = await comment.populate("userId", "_id username displayName avatarUrl");

    io.emit("trash-report-commented", {
      reportId: report._id,
      comment,
    });

    return res.status(201).json({ comment });
  } catch (error) {
    console.error("Lỗi khi thêm bình luận điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const shareReport = async (req, res) => {
  try {
    const { conversationId, targetUserId } = req.body;
    const report = await TrashReport.findById(req.params.id);
    const senderId = req.user._id;

    if (!report) {
      return res.status(404).json({ message: "Không tìm thấy điểm rác" });
    }

    let conversation = null;
    let createdConversation = false;

    if (conversationId) {
      conversation = await Conversation.findById(conversationId);

      const isMember = conversation?.participants.some(
        (p) => p.userId.toString() === senderId.toString()
      );

      if (!conversation || !isMember) {
        return res
          .status(403)
          .json({ message: "Bạn không ở trong cuộc trò chuyện này" });
      }
    }

    if (!conversation && targetUserId) {
      if (!mongoose.isValidObjectId(targetUserId)) {
        return res.status(400).json({ message: "Người nhận không hợp lệ" });
      }

      const { userA, userB } = getFriendPair(senderId, targetUserId);
      const friendship = await Friend.findOne({ userA, userB });

      if (!friendship) {
        return res
          .status(403)
          .json({ message: "Bạn chỉ có thể chia sẻ trực tiếp cho bạn bè" });
      }

      conversation = await Conversation.findOne({
        type: "direct",
        "participants.userId": { $all: [senderId, targetUserId] },
      });

      if (!conversation) {
        conversation = await Conversation.create({
          type: "direct",
          participants: [{ userId: senderId }, { userId: targetUserId }],
          lastMessageAt: new Date(),
          unreadCounts: new Map(),
        });
        createdConversation = true;
      }
    }

    if (!conversation) {
      return res
        .status(400)
        .json({ message: "Cần conversationId hoặc targetUserId để chia sẻ" });
    }

    const message = await Message.create({
      conversationId: conversation._id,
      senderId,
      content: "Đã chia sẻ một điểm rác",
      messageType: "trash_report",
      trashReport: report._id,
    });

    await message.populate({
      path: "trashReport",
      select: "title description status type severity location images",
    });

    updateConversationAfterCreateMessage(conversation, message, senderId);
    await conversation.save();
    emitNewMessage(io, conversation, message);

    const formattedConversation = createdConversation
      ? await emitConversationToParticipants(conversation)
      : null;

    io.emit("trash-report-shared", {
      reportId: report._id,
      conversationId: conversation._id,
    });

    return res.status(201).json({ message, conversation: formattedConversation });
  } catch (error) {
    console.error("Lỗi khi chia sẻ điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const joinReportChat = async (req, res) => {
  try {
    const report = await TrashReport.findById(req.params.id);
    const userId = req.user._id;

    if (!report) {
      return res.status(404).json({ message: "Không tìm thấy điểm rác" });
    }

    const conversation = await ensureReportConversation(report, userId);
    const formatted = await emitConversationToParticipants(conversation);

    return res.status(200).json({ conversation: formatted });
  } catch (error) {
    console.error("Lỗi khi vào nhóm xử lý điểm rác", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};

export const inviteReportChatMembers = async (req, res) => {
  try {
    const { friendIds = [] } = req.body;
    const report = await TrashReport.findById(req.params.id);
    const userId = req.user._id;

    if (!report) {
      return res.status(404).json({ message: "Không tìm thấy điểm rác" });
    }

    if (!Array.isArray(friendIds) || friendIds.length === 0) {
      return res.status(400).json({ message: "Cần chọn ít nhất một bạn bè" });
    }

    const uniqueFriendIds = [...new Set(friendIds.map((id) => id.toString()))].filter(
      (id) => mongoose.isValidObjectId(id) && id !== userId.toString()
    );

    if (uniqueFriendIds.length === 0) {
      return res.status(400).json({ message: "Danh sách mời không hợp lệ" });
    }

    const friendChecks = await Promise.all(
      uniqueFriendIds.map(async (friendId) => {
        const { userA, userB } = getFriendPair(userId, friendId);
        const friendship = await Friend.findOne({ userA, userB });
        return friendship ? friendId : null;
      })
    );
    const allowedFriendIds = friendChecks.filter(Boolean);

    if (allowedFriendIds.length === 0) {
      return res
        .status(403)
        .json({ message: "Bạn chỉ có thể mời bạn bè vào nhóm xử lý" });
    }

    const conversation = await ensureReportConversation(report, userId);
    const existingIds = new Set(
      conversation.participants.map((p) => p.userId.toString())
    );
    const invitedIds = [];

    allowedFriendIds.forEach((friendId) => {
      if (!existingIds.has(friendId)) {
        conversation.participants.push({ userId: friendId });
        invitedIds.push(friendId);
      }
    });

    if (invitedIds.length > 0) {
      await conversation.save();
      await sendReportSystemMessage(
        report,
        userId,
        `${req.user.displayName} đã mời ${invitedIds.length} bạn bè vào nhóm xử lý.`
      );
    }

    const formatted = await emitConversationToParticipants(conversation);

    return res.status(200).json({ conversation: formatted, invitedIds });
  } catch (error) {
    console.error("Lỗi khi mời bạn bè vào nhóm xử lý", error);
    return res.status(500).json({ message: "Lỗi hệ thống" });
  }
};
