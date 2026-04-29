import api from "@/lib/axios";
import type {
  CleanupReportInput,
  CreateReportInput,
  TrashComment,
  TrashReport,
  TrashReportStatus,
} from "@/types/report";
import type { Conversation, Message } from "@/types/chat";

interface FetchReportsParams {
  status?: TrashReportStatus | "ALL";
  lat?: number;
  lng?: number;
}

const appendImages = (formData: FormData, files?: File[]) => {
  files?.forEach((file) => formData.append("images", file));
};

export const reportService = {
  async fetchReports(params: FetchReportsParams = {}) {
    const res = await api.get<{ reports: TrashReport[] }>("/reports", {
      params,
    });
    return res.data.reports;
  },

  async fetchReport(id: string) {
    const res = await api.get<{ report: TrashReport }>(`/reports/${id}`);
    return res.data.report;
  },

  async createReport(input: CreateReportInput, images: File[] = []) {
    const formData = new FormData();
    formData.append("description", input.description);
    formData.append("type", input.type);
    formData.append("severity", input.severity);
    formData.append("lat", String(input.lat));
    formData.append("lng", String(input.lng));

    if (input.address) {
      formData.append("address", input.address);
    }

    appendImages(formData, images);

    const res = await api.post<{ report: TrashReport }>("/reports", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return res.data.report;
  },

  async verifyReport(id: string) {
    const res = await api.post<{ report: TrashReport }>(`/reports/${id}/verify`);
    return res.data.report;
  },

  async cleanupReport(id: string, input: CleanupReportInput) {
    const formData = new FormData();

    if (input.description) {
      formData.append("description", input.description);
    }

    appendImages(formData, input.images);

    const res = await api.post<{ report: TrashReport }>(
      `/reports/${id}/cleanup`,
      formData,
      {
        headers: { "Content-Type": "multipart/form-data" },
      }
    );
    return res.data.report;
  },

  async confirmClean(id: string) {
    const res = await api.post<{ report: TrashReport }>(
      `/reports/${id}/confirm-clean`
    );
    return res.data.report;
  },

  async fetchComments(reportId: string) {
    const res = await api.get<{ comments: TrashComment[] }>(
      `/reports/${reportId}/comments`
    );
    return res.data.comments;
  },

  async addComment(reportId: string, content: string) {
    const res = await api.post<{ comment: TrashComment }>(
      `/reports/${reportId}/comments`,
      { content }
    );
    return res.data.comment;
  },

  async shareReport(
    reportId: string,
    target: { conversationId?: string; targetUserId?: string }
  ) {
    const res = await api.post<{
      message: Message;
      conversation?: Conversation | null;
    }>(`/reports/${reportId}/share`, target);
    return res.data;
  },

  async joinReportChat(reportId: string) {
    const res = await api.post<{ conversation: Conversation }>(
      `/reports/${reportId}/join-chat`
    );
    return res.data;
  },

  async inviteReportChatMembers(reportId: string, friendIds: string[]) {
    const res = await api.post<{
      conversation: Conversation;
      invitedIds: string[];
    }>(`/reports/${reportId}/invite`, { friendIds });
    return res.data;
  },
};
