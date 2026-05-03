import type { User } from "./user";

export type TrashReportStatus =
  | "ACTIVE"
  | "VERIFIED"
  | "CLEANUP_PENDING"
  | "CLEANED";

export type TrashType = "plastic" | "organic" | "metal" | "glass" | "other";
export type TrashSeverity = "low" | "medium" | "high";

export interface TrashLocation {
  type?: "Point";
  coordinates?: [number, number];
  lat: number;
  lng: number;
  address?: string;
}

export interface TrashUserAction {
  userId: string;
  createdAt: string;
}

export interface TrashCleanup {
  cleanedBy?: User | string | null;
  beforeImages?: string[];
  afterImages?: string[];
  description?: string;
  createdAt?: string | null;
}

export interface TrashReport {
  _id: string;
  title: string;
  description: string;
  type: TrashType;
  severity: TrashSeverity;
  status: TrashReportStatus;
  location: TrashLocation;
  images: string[];
  createdBy: User;
  verifications: TrashUserAction[];
  cleanup?: TrashCleanup;
  cleanupConfirmations: TrashUserAction[];
  cleanedAt?: string | null;
  conversationId?: string | null;
  distanceMeters?: number;
  createdAt: string;
  updatedAt: string;
}

export interface TrashComment {
  _id: string;
  reportId: string;
  userId: User;
  content: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateReportInput {
  description: string;
  type: TrashType;
  severity: TrashSeverity;
  lat: number;
  lng: number;
  address?: string;
}

export interface CleanupReportInput {
  description?: string;
  images?: File[];
}
