import mongoose from "mongoose";

export const GROUP_INVITE_STATUS = {
  PENDING_USER: "pending_user",
  PENDING_ADMIN: "pending_admin",
  ACCEPTED: "accepted",
  REJECTED: "rejected",
};

const groupInviteSchema = new mongoose.Schema(
  {
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Conversation",
      required: true,
      index: true,
    },
    reportId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "TrashReport",
      default: null,
    },
    invitedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    invitee: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: Object.values(GROUP_INVITE_STATUS),
      default: GROUP_INVITE_STATUS.PENDING_USER,
      index: true,
    },
    acceptedAt: {
      type: Date,
      default: null,
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    approvedAt: {
      type: Date,
      default: null,
    },
    rejectedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    rejectedAt: {
      type: Date,
      default: null,
    },
    message: {
      type: String,
      trim: true,
      default: "",
    },
    expiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 14 * 24 * 60 * 60 * 1000),
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

groupInviteSchema.index({
  conversationId: 1,
  invitee: 1,
  status: 1,
});

const GroupInvite = mongoose.model("GroupInvite", groupInviteSchema);

export default GroupInvite;
