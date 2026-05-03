import { Server } from "socket.io";
import http from "http";
import express from "express";
import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import { socketAuthMiddleware } from "../middlewares/socketMiddleware.js";
import { getUserConversationsForSocketIO } from "../controllers/conversationController.js";
import { getAllowedClientOrigins } from "../config/env.js";
import {
    emitNewMessage,
    updateConversationAfterCreateMessage,
} from "../utils/messageHelper.js";

const app = express();

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: getAllowedClientOrigins(),
        credentials: true,
    },
});

io.use(socketAuthMiddleware);

const onlineUsers = new Map(); // {userId: socketId}

io.on("connection", async (socket) => {
    const user = socket.user;

    // console.log(`${user.displayName} online với socket ${socket.id}`);

    onlineUsers.set(user._id, socket.id);

    io.emit("online-users", Array.from(onlineUsers.keys()));

    const conversationIds = await getUserConversationsForSocketIO(user._id);
    conversationIds.forEach((id) => {
        socket.join(id);
    });

    socket.on("join-conversation", (conversationId) => {
        socket.join(conversationId);
    });

    socket.join(user._id.toString());

    socket.on("message:send", async (payload = {}, ack) => {
        const reply = (response) => {
            if (typeof ack === "function") {
                ack(response);
            }
        };

        try {
            const { conversationId, content = "", imgUrl, clientId } = payload;
            const trimmedContent = content.trim();

            if (!mongoose.isValidObjectId(conversationId)) {
                return reply({ ok: false, error: "Conversation khong hop le" });
            }

            if (!trimmedContent && !imgUrl) {
                return reply({ ok: false, error: "Thieu noi dung tin nhan" });
            }

            if (!clientId || typeof clientId !== "string") {
                return reply({ ok: false, error: "Missing clientId" });
            }

            const conversation = await Conversation.findOne({
                _id: conversationId,
                "participants.userId": user._id,
            });

            if (!conversation) {
                return reply({
                    ok: false,
                    error: "Ban khong o trong cuoc tro chuyen nay",
                });
            }

            let message = await Message.findOne({
                conversationId,
                senderId: user._id,
                clientId,
            });

            if (!message) {
                message = await Message.create({
                    conversationId,
                    senderId: user._id,
                    clientId,
                    content: trimmedContent,
                    imgUrl,
                    messageType: imgUrl && !trimmedContent ? "image" : "text",
                });

                updateConversationAfterCreateMessage(conversation, message, user._id);
                await conversation.save();
                emitNewMessage(io, conversation, message);
            }

            return reply({ ok: true, message });
        } catch (error) {
            console.error("Loi khi gui tin nhan qua socket", error);
            return reply({ ok: false, error: "Loi he thong" });
        }
    });

    socket.on("disconnect", () => {
        onlineUsers.delete(user._id);
        io.emit("online-users", Array.from(onlineUsers.keys()));
        /* console.log(`socket disconnected: ${socket.id}`); */
    });
});

export { io, app, server };
