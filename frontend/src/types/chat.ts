import type { TrashReport } from "./report";
import type { User } from "./user";

export interface Participant {
  _id: string;
  username?: string;
  displayName: string;
  avatarUrl?: string | null;
  joinedAt: string;
  role?: "admin" | "member";
}

export interface SeenUser {
  _id: string;
  displayName?: string;
  avatarUrl?: string | null;
}

export interface Group {
  name: string;
  createdBy: string;
  avatarUrl?: string | null;
}

export interface LastMessage {
  _id: string;
  content: string;
  createdAt: string;
  sender: {
    _id: string;
    displayName: string;
    avatarUrl?: string | null;
  };
}

export interface MessageReaction {
  _id?: string;
  user: string | { _id: string };
  emoji: string;
  createdAt: string;
}

export type MessageStatus = "sending" | "sent" | "error";

export interface Conversation {
  _id: string;
  type: "direct" | "group";
  group: Group;
  participants: Participant[];
  lastMessageAt: string;
  seenBy: SeenUser[];
  lastMessage: LastMessage | null;
  unreadCounts: Record<string, number>; // key = userId, value = unread count
  createdAt: string;
  updatedAt: string;
}

export interface ConversationResponse {
  conversations: Conversation[];
}

export interface GroupInvite {
  _id: string;
  conversationId: string;
  conversation?: Conversation | null;
  reportId?: {
    _id: string;
    title: string;
    status: string;
  } | string | null;
  invitedBy: User;
  invitee: User;
  status: "pending_user" | "pending_admin" | "accepted" | "rejected" | "pending";
  acceptedAt?: string | null;
  approvedAt?: string | null;
  rejectedAt?: string | null;
  message?: string;
  createdAt: string;
  updatedAt: string;
}

export interface GroupInviteResponse {
  incoming: GroupInvite[];
  adminApprovals: GroupInvite[];
}

export interface Message {
  _id: string;
  clientId?: string;
  conversationId: string;
  senderId: string;
  content: string | null;
  imgUrl?: string | null;
  messageType?: "text" | "image" | "trash_report" | "system";
  trashReport?: TrashReport | string | null;
  isRevoked?: boolean;
  reactions?: MessageReaction[];
  revokedAt?: string | null;
  updatedAt?: string | null;
  createdAt: string;
  isOwn?: boolean;
  status?: MessageStatus;
}

export interface SendSocketMessageInput {
  conversationId: string;
  content?: string;
  imgUrl?: string;
  clientId: string;
}
