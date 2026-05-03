import { useState } from "react";
import { Info } from "lucide-react";

import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useSocketStore } from "@/stores/useSocketStore";
import type { Conversation } from "@/types/chat";
import { Button } from "../ui/button";
import { Separator } from "../ui/separator";
import { SidebarTrigger } from "../ui/sidebar";
import UserProfileDialog from "../profile/UserProfileDialog";
import GroupChatAvatar from "./GroupChatAvatar";
import StatusBadge from "./StatusBadge";
import UserAvatar from "./UserAvatar";

const ChatWindowHeader = ({
  chat,
  onOpenDetails,
}: {
  chat?: Conversation;
  onOpenDetails?: () => void;
}) => {
  const { conversations, activeConversationId } = useChatStore();
  const { user } = useAuthStore();
  const { onlineUsers } = useSocketStore();
  const [profileOpen, setProfileOpen] = useState(false);

  chat = chat ?? conversations.find((c) => c._id === activeConversationId);

  if (!chat) {
    return (
      <header className="sticky top-0 z-10 flex w-full items-center gap-2 px-4 py-2 md:hidden">
        <SidebarTrigger className="-ml-1 text-foreground" />
      </header>
    );
  }

  const otherUser =
    chat.type === "direct"
      ? chat.participants.find((participant) => participant._id !== user?._id)
      : null;

  if (chat.type === "direct" && (!user || !otherUser)) {
    return null;
  }

  return (
    <>
      <header className="sticky top-0 z-10 flex items-center bg-background px-4 py-2">
        <div className="flex w-full items-center gap-2">
          <SidebarTrigger className="-ml-1 text-foreground" />
          <Separator
            orientation="vertical"
            className="mr-2 data-[orientation=vertical]:h-4"
          />

          <div className="flex min-w-0 flex-1 items-center gap-3 p-2">
            <div className="relative">
              {chat.type === "direct" ? (
                <>
                  <button
                    type="button"
                    className="block rounded-full outline-none ring-ring transition hover:scale-105 focus-visible:ring-2"
                    aria-label={`Xem thông tin ${
                      otherUser?.displayName || "Moji"
                    }`}
                    onClick={() => setProfileOpen(true)}
                  >
                    <UserAvatar
                      type="sidebar"
                      name={otherUser?.displayName || "Moji"}
                      avatarUrl={otherUser?.avatarUrl || undefined}
                    />
                  </button>
                  <StatusBadge
                    status={
                      onlineUsers.includes(otherUser?._id ?? "")
                        ? "online"
                        : "offline"
                    }
                  />
                </>
              ) : (
                <GroupChatAvatar
                  participants={chat.participants}
                  type="sidebar"
                  name={chat.group?.name}
                  avatarUrl={chat.group?.avatarUrl}
                />
              )}
            </div>

            <h2 className="truncate font-semibold text-foreground">
              {chat.type === "direct" ? otherUser?.displayName : chat.group?.name}
            </h2>
          </div>

          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="shrink-0 rounded-full"
            onClick={onOpenDetails}
            title="Chi tiết chat"
          >
            <Info className="size-4" />
            <span className="hidden sm:inline">Chi tiết</span>
          </Button>
        </div>
      </header>

      {otherUser && (
        <UserProfileDialog
          open={profileOpen}
          onOpenChange={setProfileOpen}
          userId={otherUser._id}
        />
      )}
    </>
  );
};

export default ChatWindowHeader;
