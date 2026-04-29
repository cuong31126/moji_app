import mongoose from "mongoose";

const trashCommentSchema = new mongoose.Schema(
  {
    reportId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "TrashReport",
      required: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    content: {
      type: String,
      trim: true,
      required: true,
      maxlength: 1000,
    },
  },
  {
    timestamps: true,
  }
);

trashCommentSchema.index({ reportId: 1, createdAt: -1 });

const TrashComment = mongoose.model("TrashComment", trashCommentSchema);

export default TrashComment;
