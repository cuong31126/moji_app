import type { Socket } from "socket.io-client";
import type {
  Conversation,
  GroupInvite,
  Message,
  MessageReaction,
  MessageStatus,
  SendSocketMessageInput,
} from "./chat";
import type { Friend, FriendRequest, User } from "./user";

export type ConversationUpdate = Partial<Conversation> & Pick<Conversation, "_id">;

export interface AuthState {
  accessToken: string | null;
  user: User | null;
  loading: boolean;

  setAccessToken: (accessToken: string) => void;
  setUser: (user: User) => void;
  clearState: () => void;
  signUp: (
    username: string,
    password: string,
    email: string,
    firstName: string,
    lastName: string
  ) => Promise<void>;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  fetchMe: () => Promise<void>;
  refresh: (options?: { silent?: boolean }) => Promise<void>;
}

export interface ThemeState {
  isDark: boolean;
  toggleTheme: () => void;
  setTheme: (dark: boolean) => void;
}

export interface ChatState {
  conversations: Conversation[];
  messages: Record<
    string,
    {
      items: Message[];
      hasMore: boolean; // infinite-scroll
      nextCursor?: string | null; // phân trang
    }
  >;
  activeConversationId: string | null;
  convoLoading: boolean;
  messageLoading: boolean;
  loading: boolean;
  groupInvites: GroupInvite[];
  adminGroupInvites: GroupInvite[];
  inviteActionLoadingById: Record<string, boolean>;
  reset: () => void;

  setActiveConversation: (id: string | null) => void;
  fetchConversations: () => Promise<void>;
  fetchMessages: (conversationId?: string) => Promise<void>;
  sendDirectMessage: (
    recipientId: string,
    content: string,
    imgUrl?: string
  ) => Promise<void>;
  sendGroupMessage: (
    conversationId: string,
    content: string,
    imgUrl?: string
  ) => Promise<void>;
  // add message
  addMessage: (message: Message) => Promise<void>;
  addOptimisticMessage: (message: Message) => void;
  confirmOptimisticMessage: (clientId: string, message: Message) => void;
  setMessageStatus: (
    conversationId: string,
    clientId: string,
    status: MessageStatus
  ) => void;
  updateMessage: (message: Message) => void;
  updateMessageReactions: (
    conversationId: string,
    messageId: string,
    reactions: MessageReaction[]
  ) => void;
  reactToMessage: (messageId: string, emoji: string) => Promise<void>;
  revokeMessage: (messageId: string) => Promise<void>;
  // update convo
  updateConversation: (conversation: ConversationUpdate) => void;
  removeConversation: (conversationId: string) => void;
  uploadGroupAvatar: (conversationId: string, file: File) => Promise<void>;
  updateGroupInfo: (conversationId: string, name: string) => Promise<void>;
  inviteGroupMembers: (
    conversationId: string,
    friendIds: string[]
  ) => Promise<string[]>;
  updateGroupMemberRole: (
    conversationId: string,
    memberId: string,
    role: "admin" | "member"
  ) => Promise<void>;
  removeGroupMember: (conversationId: string, memberId: string) => Promise<void>;
  leaveGroupConversation: (conversationId: string) => Promise<void>;
  deleteGroupConversation: (conversationId: string) => Promise<void>;
  markAsSeen: () => Promise<void>;
  addConvo: (convo: Conversation) => void;
  createConversation: (
    type: "group" | "direct",
    name: string,
    memberIds: string[]
  ) => Promise<void>;
  fetchGroupInvites: () => Promise<void>;
  applyGroupInviteUpdate: (invite: GroupInvite) => void;
  acceptGroupInvite: (inviteId: string) => Promise<void>;
  rejectGroupInvite: (inviteId: string) => Promise<void>;
  approveGroupInvite: (inviteId: string) => Promise<void>;
  declineGroupInvite: (inviteId: string) => Promise<void>;
}

export interface SocketState {
  socket: Socket | null;
  onlineUsers: string[];
  connectSocket: () => void;
  disconnectSocket: () => void;
  sendChatMessage: (input: SendSocketMessageInput) => Promise<Message>;
}

export interface FriendState {
  friends: Friend[];
  loading: boolean;
  receivedList: FriendRequest[];
  sentList: FriendRequest[];
  searchByUsername: (username: string) => Promise<User | null>;
  searchUsers: (keyword: string) => Promise<User[]>;
  addFriend: (to: string, message?: string) => Promise<string>;
  getAllFriendRequests: () => Promise<void>;
  acceptRequest: (requestId: string) => Promise<void>;
  declineRequest: (requestId: string) => Promise<void>;
  withdrawRequest: (requestId: string) => Promise<void>;
  getFriends: () => Promise<void>;
}

export interface UserState {
  updateAvatarUrl: (formData: FormData) => Promise<void>;
}
