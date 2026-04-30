import type { Conversation } from "@/types/chat";
import ChatCard from "./ChatCard";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { cn } from "@/lib/utils";
import UserAvatar from "./UserAvatar";
import StatusBadge from "./StatusBadge";
import UnreadCountBadge from "./UnreadCountBadge";
import { useSocketStore } from "@/stores/useSocketStore";
import { useNavigate } from "react-router";
import { useState } from "react";
import UserProfileDialog from "../profile/UserProfileDialog";

const DirectMessageCard = ({ convo }: { convo: Conversation }) => {
  const { user } = useAuthStore();
  const { activeConversationId, setActiveConversation, messages, fetchMessages } =
    useChatStore();
  const { onlineUsers } = useSocketStore();
  const navigate = useNavigate();
  const [profileOpen, setProfileOpen] = useState(false);

  if (!user) return null;

  const otherUser = convo.participants.find((p) => p._id !== user._id);
  if (!otherUser) return null;

  const unreadCount = convo.unreadCounts[user._id];
  const lastMessage = convo.lastMessage?.content ?? "";

  const handleSelectConversation = async (id: string) => {
    setActiveConversation(id);
    if (!messages[id]) {
      await fetchMessages();
    }
    navigate("/");
  };

  return (
    <>
      <ChatCard
        convoId={convo._id}
        name={otherUser.displayName ?? ""}
        timestamp={
          convo.lastMessage?.createdAt
            ? new Date(convo.lastMessage.createdAt)
            : undefined
        }
        isActive={activeConversationId === convo._id}
        onSelect={handleSelectConversation}
        unreadCount={unreadCount}
        leftSection={
          <>
            <button
              type="button"
              className="block rounded-full text-left outline-none ring-ring transition hover:scale-105 focus-visible:ring-2"
              aria-label={`Xem thông tin ${otherUser.displayName}`}
              onClick={(event) => {
                event.stopPropagation();
                setProfileOpen(true);
              }}
            >
              <UserAvatar
                type="sidebar"
                name={otherUser.displayName ?? ""}
                avatarUrl={otherUser.avatarUrl ?? undefined}
              />
            </button>
            <StatusBadge
              status={
                onlineUsers.includes(otherUser?._id ?? "") ? "online" : "offline"
              }
            />
            {unreadCount > 0 && <UnreadCountBadge unreadCount={unreadCount} />}
          </>
        }
        subtitle={
          <p
            className={cn(
              "truncate text-sm",
              unreadCount > 0
                ? "font-medium text-foreground"
                : "text-muted-foreground"
            )}
          >
            {lastMessage}
          </p>
        }
      />

      <UserProfileDialog
        open={profileOpen}
        onOpenChange={setProfileOpen}
        userId={otherUser._id}
      />
    </>
  );
};

export default DirectMessageCard;
