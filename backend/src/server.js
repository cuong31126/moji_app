import express from "express";
import { connectDB } from "./libs/db.js";
import authRoute from "./routes/authRoute.js";
import userRoute from "./routes/userRoute.js";
import friendRoute from "./routes/friendRoute.js";
import messageRoute from "./routes/messageRoute.js";
import conversationRoute from "./routes/conversationRoute.js";
import reportRoute from "./routes/reportRoute.js";
import aiRoute from "./routes/aiRoute.js";
import cookieParser from "cookie-parser";
import { protectedRoute } from "./middlewares/authMiddleware.js";
import cors from "cors";
import swaggerUi from "swagger-ui-express";
import fs from "fs";
import { app, server } from "./socket/index.js";
import { v2 as cloudinary } from "cloudinary";
import passport from "passport";
import { configurePassport } from "./config/passport.js";
import { corsOriginDelegate, getPort } from "./config/env.js";

const PORT = getPort();

// middlewares
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: corsOriginDelegate, credentials: true }));
configurePassport();
app.use(passport.initialize());

// CLOUDINARY Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// swagger
const swaggerDocument = JSON.parse(fs.readFileSync("./src/swagger.json", "utf8"));

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// public routes
app.use("/api/auth", authRoute);

// private routes
app.use(protectedRoute);
app.use("/api/users", userRoute);
app.use("/api/friends", friendRoute);
app.use("/api/messages", messageRoute);
app.use("/api/conversations", conversationRoute);
app.use("/api/reports", reportRoute);
app.use("/api/ai", aiRoute);

server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use`);
    console.error("Please stop the old backend process or change PORT in .env");
    console.error("Windows: netstat -ano | findstr :5001");
    console.error("Windows: taskkill /PID <PID> /F");
    process.exit(1);
  }

  console.error("Server failed to start", error);
  process.exit(1);
});

connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});
