export type RelationshipStatus =
  | "self"
  | "friends"
  | "request_sent"
  | "request_received"
  | "none";

export interface User {
  _id: string;
  username: string;
  email?: string;
  displayName: string;
  avatarUrl?: string;
  bio?: string;
  phone?: string;
  relationshipStatus?: RelationshipStatus;
  friendRequestId?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface Friend {
  _id: string;
  username: string;
  displayName: string;
  avatarUrl?: string;
}

export interface FriendRequest {
  _id: string;
  from?: {
    _id: string;
    username: string;
    displayName: string;
    avatarUrl?: string;
  };
  to?: {
    _id: string;
    username: string;
    displayName: string;
    avatarUrl?: string;
  };
  message: string;
  createdAt: string;
  updatedAt: string;
}
