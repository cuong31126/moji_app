import mongoose from "mongoose";
import { getMongoUri } from "../config/env.js";

export const connectDB = async () => {
  try {
    const mongoUri = getMongoUri();

    if (!mongoUri) {
      throw new Error("Missing MONGODB_URI or MONGODB_CONNECTIONSTRING");
    }

    await mongoose.connect(mongoUri);
    console.log("Connected to MongoDB successfully");
  } catch (error) {
    console.log("MongoDB connection failed:", error);
    process.exit(1);
  }
};
