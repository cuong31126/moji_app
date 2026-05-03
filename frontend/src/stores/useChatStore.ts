import { chatService } from "@/services/chatService";
import type { ChatState } from "@/types/store";
import { create } from "zustand";
import { persist } from "zustand/middleware";

const getAuthState = async () => {
  const { useAuthStore } = await import("./useAuthStore");
  return useAuthStore.getState();
};

export const useChatStore = create<ChatState>()(
  persist(
    (set, get) => ({
      conversations: [],
      messages: {},
      activeConversationId: null,
      convoLoading: false, // convo loading
      messageLoading: false,
      loading: false,
      groupInvites: [],
      adminGroupInvites: [],

      setActiveConversation: (id) => set({ activeConversationId: id }),
      reset: () => {
        set({
          conversations: [],
          messages: {},
          activeConversationId: null,
          convoLoading: false,
          messageLoading: false,
          groupInvites: [],
          adminGroupInvites: [],
        });
      },
      fetchConversations: async () => {
        try {
          set({ convoLoading: true });
          const { conversations } = await chatService.fetchConversations();

          set({ conversations, convoLoading: false });
        } catch (error) {
          console.error("Lỗi xảy ra khi fetchConversations:", error);
          set({ convoLoading: false });
        }
      },// }, Xử lý tin nhắn cũ - Phân trang
      fetchMessages: async (conversationId) => {
        const { activeConversationId, messages } = get();
        const { user } = await getAuthState();

        const convoId = conversationId ?? activeConversationId;

        if (!convoId) return;

        const current = messages?.[convoId];
        const nextCursor =
          current?.nextCursor === undefined ? "" : current?.nextCursor;

        if (nextCursor === null) return;

        set({ messageLoading: true });

        try {
          const { messages: fetched, cursor } = await chatService.fetchMessages(
            convoId,
            nextCursor
          );

          const processed = fetched.map((m) => ({
            ...m,
            isOwn: m.senderId === user?._id,
          }));

          set((state) => {
            const prev = state.messages[convoId]?.items ?? [];
            const merged = prev.length > 0 ? [...processed, ...prev] : processed;

            return {
              messages: {
                ...state.messages,
                [convoId]: {
                  items: merged,
                  hasMore: !!cursor,
                  nextCursor: cursor ?? null,
                },
              },
            };
          });
        } catch (error) {
          console.error("Lỗi xảy ra khi fetchMessages:", error);
        } finally {
          set({ messageLoading: false });
        }
      },
      sendDirectMessage: async (recipientId, content, imgUrl) => {
        try {
          const { activeConversationId } = get();
          await chatService.sendDirectMessage(
            recipientId,
            content,
            imgUrl,
            activeConversationId || undefined
          );
          set((state) => ({
            conversations: state.conversations.map((c) =>
              c._id === activeConversationId ? { ...c, seenBy: [] } : c
            ),
          }));
        } catch (error) {
          console.error("Lỗi xảy ra khi gửi direct message", error);
          throw error;
        }
      },
      sendGroupMessage: async (conversationId, content, imgUrl) => {
        try {
          await chatService.sendGroupMessage(conversationId, content, imgUrl);
          set((state) => ({
            conversations: state.conversations.map((c) =>
              c._id === get().activeConversationId ? { ...c, seenBy: [] } : c
            ),
          }));
        } catch (error) {
          console.error("Lỗi xảy ra gửi group message", error);
          throw error;
        }
      },
      addMessage: async (message) => {
        try {
          const { user } = await getAuthState();
          const { fetchMessages } = get();

          message.isOwn = message.senderId === user?._id;

          const convoId = message.conversationId;

          let prevItems = get().messages[convoId]?.items ?? [];

          if (prevItems.length === 0) {
            await fetchMessages(message.conversationId);
            prevItems = get().messages[convoId]?.items ?? [];
          }

          set((state) => {
            if (prevItems.some((m) => m._id === message._id)) {
              return state;
            }

            return {
              messages: {
                ...state.messages,
                [convoId]: {
                  items: [...prevItems, message],
                  hasMore: state.messages[convoId].hasMore,
                  nextCursor: state.messages[convoId].nextCursor ?? undefined,
                },
              },
            };
          });
        } catch (error) {
          console.error("Lỗi xảy khi ra add message:", error);
        }
      },
      updateMessage: (message) => {
        const convoId = message.conversationId;

        set((state) => {
          const current = state.messages[convoId];

          if (!current) {
            return state;
          }

          return {
            messages: {
              ...state.messages,
              [convoId]: {
                ...current,
                items: current.items.map((item) =>
                  item._id === message._id
                    ? { ...item, ...message, isOwn: item.isOwn }
                    : item
                ),
              },
            },
          };
        });
      },
      updateMessageReactions: (conversationId, messageId, reactions) => {
        set((state) => {
          const current = state.messages[conversationId];

          if (!current) {
            return state;
          }

          return {
            messages: {
              ...state.messages,
              [conversationId]: {
                ...current,
                items: current.items.map((item) =>
                  item._id === messageId ? { ...item, reactions } : item
                ),
              },
            },
          };
        });
      },
      reactToMessage: async (messageId, emoji) => {
        try {
          const result = await chatService.reactToMessage(messageId, emoji);
          get().updateMessageReactions(
            result.conversationId,
            result.messageId,
            result.reactions
          );
        } catch (error) {
          console.error("Error reacting to message", error);
          throw error;
        }
      },
      revokeMessage: async (messageId) => {
        try {
          const result = await chatService.revokeMessage(messageId);
          get().updateMessage(result.message);

          if (result.conversation) {
            get().updateConversation(result.conversation);
          }
        } catch (error) {
          console.error("Lỗi xảy ra khi thu hồi tin nhắn", error);
          throw error;
        }
      },
      updateConversation: (conversation) => {
        set((state) => ({
          conversations: state.conversations.map((c) =>
            c._id === conversation._id ? { ...c, ...conversation } : c
          ),
        }));
      },
      removeConversation: (conversationId) => {
        set((state) => {
          const nextMessages = { ...state.messages };
          delete nextMessages[conversationId];

          return {
            conversations: state.conversations.filter(
              (conversation) => conversation._id !== conversationId
            ),
            messages: nextMessages,
            activeConversationId:
              state.activeConversationId === conversationId
                ? null
                : state.activeConversationId,
          };
        });
      },
      uploadGroupAvatar: async (conversationId, file) => {
        try {
          set({ loading: true });
          const formData = new FormData();
          formData.append("file", file);

          const result = await chatService.uploadGroupAvatar(
            conversationId,
            formData
          );

          get().updateConversation(result.conversation);
        } catch (error) {
          console.error("Lỗi xảy ra khi cập nhật ảnh nhóm", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      updateGroupInfo: async (conversationId, name) => {
        try {
          set({ loading: true });
          const result = await chatService.updateGroupInfo(conversationId, name);
          get().updateConversation(result.conversation);
        } catch (error) {
          console.error("Lỗi xảy ra khi cập nhật thông tin nhóm", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      inviteGroupMembers: async (conversationId, friendIds) => {
        try {
          set({ loading: true });
          const result = await chatService.inviteGroupMembers(
            conversationId,
            friendIds
          );

          get().updateConversation(result.conversation);
          await get().fetchGroupInvites();

          return result.invitedIds;
        } catch (error) {
          console.error("Lỗi xảy ra khi mời thành viên vào nhóm", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      updateGroupMemberRole: async (conversationId, memberId, role) => {
        try {
          set({ loading: true });
          const result = await chatService.updateGroupMemberRole(
            conversationId,
            memberId,
            role
          );
          get().updateConversation(result.conversation);
        } catch (error) {
          console.error("Lỗi xảy ra khi phân quyền thành viên nhóm", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      removeGroupMember: async (conversationId, memberId) => {
        try {
          set({ loading: true });
          const result = await chatService.removeGroupMember(
            conversationId,
            memberId
          );
          get().updateConversation(result.conversation);
          await get().fetchGroupInvites();
        } catch (error) {
          console.error("Lỗi xảy ra khi xóa thành viên khỏi nhóm", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      leaveGroupConversation: async (conversationId) => {
        try {
          set({ loading: true });
          const result = await chatService.leaveGroupConversation(conversationId);

          get().removeConversation(conversationId);

          if (result.conversation) {
            get().updateConversation(result.conversation);
          }
        } catch (error) {
          console.error("Lỗi xảy ra khi rời nhóm", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      deleteGroupConversation: async (conversationId) => {
        try {
          set({ loading: true });
          await chatService.deleteGroupConversation(conversationId);
          get().removeConversation(conversationId);
        } catch (error) {
          console.error("Lỗi xảy ra khi xóa nhóm", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      markAsSeen: async () => {
        try {
          const { user } = await getAuthState();
          const { activeConversationId, conversations } = get();

          if (!activeConversationId || !user) {
            return;
          }

          const convo = conversations.find((c) => c._id === activeConversationId);

          if (!convo) {
            return;
          }

          if ((convo.unreadCounts?.[user._id] ?? 0) === 0) {
            return;
          }

          await chatService.markAsSeen(activeConversationId);

          set((state) => ({
            conversations: state.conversations.map((c) =>
              c._id === activeConversationId && c.lastMessage
                ? {
                    ...c,
                    unreadCounts: {
                      ...c.unreadCounts,
                      [user._id]: 0,
                    },
                  }
                : c
            ),
          }));
        } catch (error) {
          console.error("Lỗi xảy ra khi gọi markAsSeen trong store", error);
        }
      },
      addConvo: (convo) => {
        set((state) => {
          const exists = state.conversations.some(
            (c) => c._id.toString() === convo._id.toString()
          );

          return {
            conversations: exists
              ? state.conversations
              : [convo, ...state.conversations],
            activeConversationId: convo._id,
          };
        });
      },
      createConversation: async (type, name, memberIds) => {
        try {
          set({ loading: true });
          const conversation = await chatService.createConversation(
            type,
            name,
            memberIds
          );

          get().addConvo(conversation);

          const { useSocketStore } = await import("./useSocketStore");
          useSocketStore.getState().socket?.emit("join-conversation", conversation._id);
        } catch (error) {
          console.error("Lỗi xảy ra khi gọi createConversation trong store", error);
        } finally {
          set({ loading: false });
        }
      },
      fetchGroupInvites: async () => {
        try {
          const { incoming, adminApprovals } =
            await chatService.fetchGroupInvites();
          set({ groupInvites: incoming, adminGroupInvites: adminApprovals });
        } catch (error) {
          console.error("Loi xay ra khi fetch group invites", error);
        }
      },
      acceptGroupInvite: async (inviteId) => {
        try {
          set({ loading: true });
          const result = await chatService.acceptGroupInvite(inviteId);

          if (result.conversation) {
            get().addConvo(result.conversation);
            const { useSocketStore } = await import("./useSocketStore");
            useSocketStore
              .getState()
              .socket?.emit("join-conversation", result.conversation._id);
          }

          await get().fetchGroupInvites();
        } catch (error) {
          console.error("Loi xay ra khi accept group invite", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      rejectGroupInvite: async (inviteId) => {
        try {
          set({ loading: true });
          await chatService.rejectGroupInvite(inviteId);
          await get().fetchGroupInvites();
        } catch (error) {
          console.error("Loi xay ra khi reject group invite", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      approveGroupInvite: async (inviteId) => {
        try {
          set({ loading: true });
          const result = await chatService.approveGroupInvite(inviteId);

          if (result.conversation) {
            get().updateConversation(result.conversation);
          }

          await get().fetchGroupInvites();
        } catch (error) {
          console.error("Loi xay ra khi approve group invite", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      declineGroupInvite: async (inviteId) => {
        try {
          set({ loading: true });
          await chatService.declineGroupInvite(inviteId);
          await get().fetchGroupInvites();
        } catch (error) {
          console.error("Loi xay ra khi decline group invite", error);
          throw error;
        } finally {
          set({ loading: false });
        }
      },
    }),
    {
      name: "chat-storage",
      partialize: (state) => ({ conversations: state.conversations }),
    }
  )
);
