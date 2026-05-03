import mongoose from "mongoose";

export const TRASH_REPORT_STATUS = {
  ACTIVE: "ACTIVE",
  VERIFIED: "VERIFIED",
  CLEANUP_PENDING: "CLEANUP_PENDING",
  CLEANED: "CLEANED",
};

const userActionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    _id: false,
  }
);

const cleanupSchema = new mongoose.Schema(
  {
    cleanedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    beforeImages: {
      type: [String],
      default: [],
    },
    afterImages: {
      type: [String],
      default: [],
    },
    description: {
      type: String,
      trim: true,
      default: "",
    },
    createdAt: {
      type: Date,
      default: null,
    },
  },
  {
    _id: false,
  }
);

const trashReportSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      trim: true,
      maxlength: 120,
      required: true,
    },
    description: {
      type: String,
      trim: true,
      required: true,
    },
    type: {
      type: String,
      enum: ["plastic", "organic", "metal", "glass", "other"],
      default: "other",
    },
    severity: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "medium",
    },
    status: {
      type: String,
      enum: Object.values(TRASH_REPORT_STATUS),
      default: TRASH_REPORT_STATUS.ACTIVE,
      index: true,
    },
    location: {
      type: {
        type: String,
        enum: ["Point"],
        default: "Point",
      },
      coordinates: {
        type: [Number],
        required: true,
        validate: {
          validator: (coordinates) =>
            Array.isArray(coordinates) &&
            coordinates.length === 2 &&
            coordinates.every(Number.isFinite),
          message: "Location coordinates must be [longitude, latitude]",
        },
      },
      lat: {
        type: Number,
        required: true,
      },
      lng: {
        type: Number,
        required: true,
      },
      address: {
        type: String,
        trim: true,
        default: "",
      },
    },
    images: {
      type: [String],
      default: [],
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    verifications: {
      type: [userActionSchema],
      default: [],
    },
    cleanup: {
      type: cleanupSchema,
      default: () => ({}),
    },
    cleanupConfirmations: {
      type: [userActionSchema],
      default: [],
    },
    cleanedAt: {
      type: Date,
      default: null,
      index: true,
    },
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Conversation",
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

trashReportSchema.index({ location: "2dsphere" });
trashReportSchema.index({ status: 1, createdAt: -1 });

const TrashReport = mongoose.model("TrashReport", trashReportSchema);

export default TrashReport;
