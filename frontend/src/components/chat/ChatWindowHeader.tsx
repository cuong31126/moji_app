import { useChatStore } from "@/stores/useChatStore";
import type { Conversation } from "@/types/chat";
import { SidebarTrigger } from "../ui/sidebar";
import { useAuthStore } from "@/stores/useAuthStore";
import { Separator } from "../ui/separator";
import UserAvatar from "./UserAvatar";
import StatusBadge from "./StatusBadge";
import GroupChatAvatar from "./GroupChatAvatar";
import { useSocketStore } from "@/stores/useSocketStore";
import { useState } from "react";
import UserProfileDialog from "../profile/UserProfileDialog";

const ChatWindowHeader = ({ chat }: { chat?: Conversation }) => {
  const { conversations, activeConversationId } = useChatStore();
  const { user } = useAuthStore();
  const { onlineUsers } = useSocketStore();
  const [profileOpen, setProfileOpen] = useState(false);

  let otherUser;

  chat = chat ?? conversations.find((c) => c._id === activeConversationId);

  if (!chat) {
    return (
      <header className="md:hidden sticky top-0 z-10 flex items-center gap-2 px-4 py-2 w-full">
        <SidebarTrigger className="-ml-1 text-foreground" />
      </header>
    );
  }

  if (chat.type === "direct") {
    const otherUsers = chat.participants.filter((p) => p._id !== user?._id);
    otherUser = otherUsers.length > 0 ? otherUsers[0] : null;

    if (!user || !otherUser) return;
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

          <div className="flex w-full items-center gap-3 p-2">
            <div className="relative">
              {chat.type === "direct" ? (
                <>
                  <button
                    type="button"
                    className="block rounded-full outline-none ring-ring transition hover:scale-105 focus-visible:ring-2"
                    aria-label={`Xem thông tin ${otherUser?.displayName || "Moji"}`}
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
                />
              )}
            </div>

            <h2 className="font-semibold text-foreground">
              {chat.type === "direct" ? otherUser?.displayName : chat.group?.name}
            </h2>
          </div>
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
