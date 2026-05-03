import { useEffect, useMemo, useState } from "react";
import { AlertCircle, Loader2, Sparkles, X } from "lucide-react";
import { toast } from "sonner";

import { aiService } from "@/services/aiService";
import { useChatStore } from "@/stores/useChatStore";
import type { Message } from "@/types/chat";
import ChatWelcomeScreen from "./ChatWelcomeScreen";
import { SidebarInset } from "../ui/sidebar";
import ChatWindowHeader from "./ChatWindowHeader";
import ChatWindowBody from "./ChatWindowBody";
import MessageInput from "./MessageInput";
import ChatDetailsPanel from "./ChatDetailsPanel";
import ChatWindowSkeleton from "../skeleton/ChatWindowSkeleton";
import { Button } from "../ui/button";

const ChatWindowLayout = () => {
  const {
    activeConversationId,
    conversations,
    messages,
    messageLoading: loading,
    markAsSeen,
  } = useChatStore();
  const [summary, setSummary] = useState("");
  const [summaryOpen, setSummaryOpen] = useState(false);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState("");
  const [detailsOpen, setDetailsOpen] = useState(false);

  const selectedConvo =
    conversations.find((c) => c._id === activeConversationId) ?? null;
  const currentMessages: Message[] = useMemo(
    () => (activeConversationId ? messages[activeConversationId]?.items ?? [] : []),
    [activeConversationId, messages]
  );
  const summarizableMessages = useMemo(
    () =>
      currentMessages
        .filter((message) => !message.isRevoked && message.content?.trim())
        .slice(-30),
    [currentMessages]
  );
  const summarizableCount = summarizableMessages.length;
  const canSummarize = summarizableCount >= 10;

  const participantNameMap = useMemo(() => {
    const map = new Map<string, string>();

    selectedConvo?.participants.forEach((participant) => {
      map.set(participant._id, participant.displayName || "Moji user");
    });

    return map;
  }, [selectedConvo]);

  useEffect(() => {
    if (!selectedConvo) {
      return;
    }

    const markSeen = async () => {
      try {
        await markAsSeen();
      } catch (error) {
        console.error("Loi khi markSeen", error);
      }
    };

    markSeen();
  }, [markAsSeen, selectedConvo]);

  useEffect(() => {
    setSummary("");
    setSummaryError("");
    setSummaryOpen(false);
    setDetailsOpen(false);
  }, [activeConversationId]);

  const handleSummarizeChat = async () => {
    if (!canSummarize) {
      return;
    }

    const payload = summarizableMessages.map((message) => ({
      senderName: participantNameMap.get(message.senderId) || "Moji user",
      content: message.content || "",
    }));

    if (payload.length === 0) {
      toast.error("Không có nội dung để tóm tắt");
      return;
    }

    try {
      setSummaryLoading(true);
      setSummaryError("");
      setSummaryOpen(true);
      const result = await aiService.summarizeChat(payload);
      setSummary(result.summary);

      if (result.fallback) {
        setSummaryError("AI đang bận, thử lại sau.");
      }
    } catch (error) {
      console.error(error);
      setSummary("");
      setSummaryError("AI đang bận, thử lại sau.");
    } finally {
      setSummaryLoading(false);
    }
  };

  if (!selectedConvo) {
    return <ChatWelcomeScreen />;
  }

  if (loading) {
    return <ChatWindowSkeleton />;
  }

  return (
    <SidebarInset className="h-full flex-1 overflow-hidden rounded-sm shadow-md">
      <div className="flex min-h-0 flex-1">
        <section className="flex min-w-0 flex-1 flex-col">
          <ChatWindowHeader
            chat={selectedConvo}
            onOpenDetails={() => setDetailsOpen((current) => !current)}
          />

          <div className="border-b border-border/60 bg-background px-4 py-2">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-8 rounded-full"
                  onClick={handleSummarizeChat}
                  disabled={summaryLoading || !canSummarize}
                >
                  {summaryLoading ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <Sparkles className="size-4" />
                  )}
                  {summaryLoading ? "Đang tóm tắt..." : "Tóm tắt chat"}
                </Button>
                <span className="text-xs text-muted-foreground">
                  {canSummarize
                    ? `AI sẽ đọc ${Math.min(summarizableCount, 30)} tin gần nhất`
                    : `Cần thêm ${Math.max(
                        10 - summarizableCount,
                        0
                      )} tin nhắn chữ`}
                </span>
              </div>

              {summaryOpen && (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-8 rounded-full"
                  onClick={() => setSummaryOpen(false)}
                >
                  <X className="size-4" />
                </Button>
              )}
            </div>

            {summaryOpen && (
              <div className="mt-2 rounded-xl border border-primary/20 bg-primary/5 p-3 text-sm leading-6">
                {summaryError && (
                  <div className="mb-2 flex items-center gap-2 text-warning">
                    <AlertCircle className="size-4" />
                    {summaryError}
                  </div>
                )}
                {summaryLoading ? (
                  <p className="text-muted-foreground">Đang tóm tắt...</p>
                ) : (
                  <p className="whitespace-pre-line">{summary}</p>
                )}
              </div>
            )}
          </div>

          <div className="flex-1 overflow-y-auto bg-primary-foreground">
            <ChatWindowBody />
          </div>

          <MessageInput selectedConvo={selectedConvo} />
        </section>

        <ChatDetailsPanel
          chat={selectedConvo}
          open={detailsOpen}
          onOpenChange={setDetailsOpen}
        />
      </div>
    </SidebarInset>
  );
};

export default ChatWindowLayout;
