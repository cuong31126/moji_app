import api from "@/lib/axios";

export interface ChatSummaryMessage {
  senderName: string;
  content: string;
}

export const aiService = {
  async summarizeChat(messages: ChatSummaryMessage[]) {
    const res = await api.post<{ summary: string; fallback?: boolean }>(
      "/ai/summarize-chat",
      { messages }
    );

    return res.data;
  },

  async suggestEmojis(text: string) {
    const res = await api.post<{ emojis: string[]; fallback?: boolean }>(
      "/ai/suggest-emojis",
      { text }
    );

    return res.data;
  },
};
