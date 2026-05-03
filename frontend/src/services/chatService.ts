import api from "@/lib/axios";
import type {
  Conversation,
  ConversationResponse,
  GroupInvite,
  GroupInviteResponse,
  Message,
} from "@/types/chat";

interface FetchMessageProps {
  messages: Message[];
  cursor?: string;
}

const pageLimit = 50;

export const chatService = {
  async fetchConversations(): Promise<ConversationResponse> {
    const res = await api.get("/conversations");
    return res.data;
  },

  async fetchMessages(id: string, cursor?: string): Promise<FetchMessageProps> {
    const res = await api.get(
      `/conversations/${id}/messages?limit=${pageLimit}&cursor=${cursor}`
    );

    return { messages: res.data.messages, cursor: res.data.nextCursor };
  },

  async sendDirectMessage(
    recipientId: string,
    content: string = "",
    imgUrl?: string,
    conversationId?: string
  ) {
    const res = await api.post("/messages/direct", {
      recipientId,
      content,
      imgUrl,
      conversationId,
    });

    return res.data.message;
  },

  async sendGroupMessage(
    conversationId: string,
    content: string = "",
    imgUrl?: string
  ) {
    const res = await api.post("/messages/group", {
      conversationId,
      content,
      imgUrl,
    });
    return res.data.message;
  },

  async uploadMessageImage(formData: FormData) {
    const res = await api.post("/messages/upload-image", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    return res.data.imgUrl as string;
  },

  async uploadGroupAvatar(
    conversationId: string,
    formData: FormData
  ): Promise<{ conversation: Conversation }> {
    const res = await api.patch(
      `/conversations/${conversationId}/group-avatar`,
      formData,
      {
        headers: { "Content-Type": "multipart/form-data" },
      }
    );

    return res.data;
  },

  async updateGroupInfo(
    conversationId: string,
    name: string
  ): Promise<{ conversation: Conversation }> {
    const res = await api.patch(`/conversations/${conversationId}/group`, {
      name,
    });

    return res.data;
  },

  async inviteGroupMembers(
    conversationId: string,
    friendIds: string[]
  ): Promise<{ conversation: Conversation; invitedIds: string[] }> {
    const res = await api.post(
      `/conversations/${conversationId}/group-invites`,
      { friendIds }
    );

    return res.data;
  },

  async updateGroupMemberRole(
    conversationId: string,
    memberId: string,
    role: "admin" | "member"
  ): Promise<{ conversation: Conversation }> {
    const res = await api.patch(
      `/conversations/${conversationId}/members/${memberId}/role`,
      { role }
    );

    return res.data;
  },

  async removeGroupMember(
    conversationId: string,
    memberId: string
  ): Promise<{ conversation: Conversation }> {
    const res = await api.delete(
      `/conversations/${conversationId}/members/${memberId}`
    );

    return res.data;
  },

  async leaveGroupConversation(
    conversationId: string
  ): Promise<{ conversation?: Conversation; conversationId: string }> {
    const res = await api.post(`/conversations/${conversationId}/leave`);
    return res.data;
  },

  async deleteGroupConversation(
    conversationId: string
  ): Promise<{ conversationId: string }> {
    const res = await api.delete(`/conversations/${conversationId}`);
    return res.data;
  },

  async revokeMessage(messageId: string) {
    const res = await api.patch(`/messages/${messageId}/revoke`);
    return res.data;
  },

  async reactToMessage(messageId: string, emoji: string) {
    const res = await api.patch(`/messages/${messageId}/reaction`, { emoji });
    return res.data;
  },

  async markAsSeen(conversationId: string) {
    const res = await api.patch(`/conversations/${conversationId}/seen`);
    return res.data;
  },

  async createConversation(
    type: "direct" | "group",
    name: string,
    memberIds: string[]
  ) {
    const res = await api.post("/conversations", { type, name, memberIds });
    return res.data.conversation;
  },

  async fetchGroupInvites(): Promise<GroupInviteResponse> {
    const res = await api.get<GroupInviteResponse>("/group-invites/me");
    return res.data;
  },

  async acceptGroupInvite(inviteId: string): Promise<{
    invite: GroupInvite;
    conversation?: Conversation | null;
  }> {
    const res = await api.post(`/group-invites/${inviteId}/accept`);
    return res.data;
  },

  async rejectGroupInvite(inviteId: string): Promise<{ invite: GroupInvite }> {
    const res = await api.post(`/group-invites/${inviteId}/reject`);
    return res.data;
  },

  async approveGroupInvite(inviteId: string): Promise<{
    invite: GroupInvite;
    conversation?: Conversation | null;
  }> {
    const res = await api.post(`/group-invites/${inviteId}/approve`);
    return res.data;
  },

  async declineGroupInvite(inviteId: string): Promise<{ invite: GroupInvite }> {
    const res = await api.post(`/group-invites/${inviteId}/decline`);
    return res.data;
  },
};
