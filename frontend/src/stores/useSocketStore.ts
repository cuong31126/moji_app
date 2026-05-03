import { create } from "zustand";
import { io, type Socket } from "socket.io-client";
import type { SocketState } from "@/types/store";
import { toast } from "sonner";
import type { Message, SendSocketMessageInput } from "@/types/chat";

const baseURL = import.meta.env.VITE_SOCKET_URL;

const getAuthState = async () => {
  const { useAuthStore } = await import("./useAuthStore");
  return useAuthStore.getState();
};

const getChatState = async () => {
  const { useChatStore } = await import("./useChatStore");
  return useChatStore.getState();
};

export const useSocketStore = create<SocketState>((set, get) => ({
  socket: null,
  onlineUsers: [],
  sendChatMessage: (input: SendSocketMessageInput) => {
    const socket = get().socket;

    if (!socket?.connected) {
      return Promise.reject(new Error("Socket is not connected"));
    }

    return new Promise<Message>((resolve, reject) => {
      socket.timeout(12000).emit(
        "message:send",
        input,
        (
          error: Error | null,
          ack?: { ok: boolean; message?: Message; error?: string }
        ) => {
          if (error) {
            reject(error);
            return;
          }

          if (!ack?.ok || !ack.message) {
            reject(new Error(ack?.error || "Send message failed"));
            return;
          }

          resolve(ack.message);
        }
      );
    });
  },
  connectSocket: () => {
    void (async () => {
      const accessToken = (await getAuthState()).accessToken;
      const existingSocket = get().socket;

      if (existingSocket) return;

      const socket: Socket = io(baseURL, {
        auth: { token: accessToken },
        transports: ["websocket"],
      });

      set({ socket });

      socket.on("connect", () => {
        console.log("Da ket noi voi socket");
      });

      socket.on("online-users", (userIds) => {
        set({ onlineUsers: userIds });
      });

      socket.on("new-message", ({ message, conversation, unreadCounts }) => {
        void (async () => {
          const chatState = await getChatState();
          await chatState.addMessage(message);

          const lastMessage = {
            _id: conversation.lastMessage._id,
            content: conversation.lastMessage.content,
            createdAt: conversation.lastMessage.createdAt,
            sender: {
              _id: conversation.lastMessage.senderId,
              displayName: "",
              avatarUrl: null,
            },
          };

          const updatedConversation = {
            ...conversation,
            lastMessage,
            unreadCounts,
          };

          const latestChatState = await getChatState();

          if (latestChatState.activeConversationId === message.conversationId) {
            latestChatState.markAsSeen();
          }

          latestChatState.updateConversation(updatedConversation);
        })();
      });

      socket.on("read-message", ({ conversation, lastMessage }) => {
        void (async () => {
          const updated = {
            _id: conversation._id,
            lastMessage,
            lastMessageAt: conversation.lastMessageAt,
            unreadCounts: conversation.unreadCounts,
            seenBy: conversation.seenBy,
          };

          (await getChatState()).updateConversation(updated);
        })();
      });

      socket.on("message-revoked", ({ message, conversation }) => {
        void (async () => {
          const chatState = await getChatState();
          chatState.updateMessage(message);

          if (conversation) {
            chatState.updateConversation(conversation);
          }
        })();
      });

      socket.on("message:reaction_updated", ({ conversationId, messageId, reactions }) => {
        void (async () => {
          (await getChatState()).updateMessageReactions(
            conversationId,
            messageId,
            reactions
          );
        })();
      });

      socket.on("group-invite:created", () => {
        void (async () => {
          toast.info("Có lời mời vào nhóm chat");
          (await getChatState()).fetchGroupInvites();
        })();
      });

      socket.on("group-invite:needs_approval", () => {
        void (async () => {
          toast.info("Có lời mời nhóm đang chờ admin duyệt");
          (await getChatState()).fetchGroupInvites();
        })();
      });

      socket.on("group-invite:updated", ({ invite } = {}) => {
        void (async () => {
          const chatState = await getChatState();
          if (invite) {
            chatState.applyGroupInviteUpdate(invite);
            return;
          }

          chatState.fetchGroupInvites();
        })();
      });

      socket.on("group-invite:approved", ({ invite, conversation }) => {
        void (async () => {
          const chatState = await getChatState();
          if (conversation) {
            chatState.addConvo(conversation);
            socket.emit("join-conversation", conversation._id);
          }
          if (invite) {
            chatState.applyGroupInviteUpdate(invite);
          } else {
            chatState.fetchGroupInvites();
          }
          toast.success("Lời mời nhóm đã được duyệt");
        })();
      });

      socket.on("conversation:updated", (conversation) => {
        void (async () => {
          (await getChatState()).updateConversation(conversation);
        })();
      });

      socket.on("conversation:removed", ({ conversationId }) => {
        void (async () => {
          (await getChatState()).removeConversation(conversationId);
        })();
      });

      socket.on("new-group", (conversation) => {
        void (async () => {
          (await getChatState()).addConvo(conversation);
          socket.emit("join-conversation", conversation._id);
        })();
      });
    })();
  },
  disconnectSocket: () => {
    const socket = get().socket;
    if (socket) {
      socket.disconnect();
      set({ socket: null });
    }
  },
}));
