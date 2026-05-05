import { useChatStore } from "@/stores/useChatStore";
import ChatWelcomeScreen from "./ChatWelcomeScreen";
import MessageItem from "./MessageItem";
import { useLayoutEffect, useRef } from "react";
import InfiniteScroll from "react-infinite-scroll-component";
import type { Message } from "@/types/chat";

const ChatWindowBody = ({ onReply }: { onReply: (message: Message) => void }) => {
  const {
    activeConversationId,
    conversations,
    messages: allMessages,
    fetchMessages,
    revokeMessage,
  } = useChatStore();
  const messages = allMessages[activeConversationId!]?.items ?? [];
  const reversedMessages = [...messages].reverse();
  const hasMore = allMessages[activeConversationId!]?.hasMore ?? false;
  const selectedConvo = conversations.find((c) => c._id === activeConversationId);
  const lastMessageStatus: "delivered" | "seen" =
    selectedConvo?.lastMessage && (selectedConvo.seenBy ?? []).length > 0
      ? "seen"
      : "delivered";
  const key = `chat-scroll-${activeConversationId}`;

  // ref
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // kéo xuống dưới khi load convo
  useLayoutEffect(() => {
    if (!messagesEndRef.current) return;

    messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [activeConversationId]);

  const fetchMoreMessages = async () => {
    if (!activeConversationId) {
      return;
    }

    try {
      await fetchMessages(activeConversationId);
    } catch (error) {
      console.error("Lỗi xảy ra khi fetch thêm tin", error);
    }
  };

  const handleScrollSave = () => {
    const container = containerRef.current;
    if (!container || !activeConversationId) {
      return;
    }

    sessionStorage.setItem(
      key,
      JSON.stringify({
        scrollTop: container.scrollTop,
        scrollHeight: container.scrollHeight,
      })
    );
  };

  useLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const item = sessionStorage.getItem(key);

    if (item) {
      const { scrollTop } = JSON.parse(item);
      requestAnimationFrame(() => {
        container.scrollTop = scrollTop;
      });
    }
  }, [key, messages.length]);

  if (!selectedConvo) {
    return <ChatWelcomeScreen />;
  }

  if (!messages?.length) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground ">
        Chưa có tin nhắn nào trong cuộc trò chuyện này.
      </div>
    );
  }

  return (
    <div className="p-4 bg-primary-foreground h-full flex flex-col overflow-hidden">
      <div
        id="scrollableDiv"
        ref={containerRef}
        onScroll={handleScrollSave}
        className="beautiful-scrollbar flex flex-col-reverse overflow-y-auto overflow-x-hidden pr-2"
      >
        <div ref={messagesEndRef}></div>
        <InfiniteScroll
          dataLength={messages.length}
          next={fetchMoreMessages}
          hasMore={hasMore}
          scrollableTarget="scrollableDiv"
          loader={<p>Đang tải...</p>}
          inverse={true}
          style={{
            display: "flex",
            flexDirection: "column-reverse",
            overflow: "visible",
          }}
        >
          {reversedMessages.map((message, index) => (
            <MessageItem
              key={message.clientId ?? message._id ?? index}
              message={message}
              index={index}
              messages={reversedMessages}
              selectedConvo={selectedConvo}
              lastMessageStatus={lastMessageStatus}
              onRevoke={revokeMessage}
              onReply={onReply}
            />
          ))}
        </InfiniteScroll>
      </div>
    </div>
  );
};

export default ChatWindowBody;
