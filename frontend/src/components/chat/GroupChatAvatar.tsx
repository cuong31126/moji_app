import { Ellipsis } from "lucide-react";

import type { Participant } from "@/types/chat";
import UserAvatar from "./UserAvatar";

interface GroupChatAvatarProps {
  participants: Participant[];
  type: "chat" | "sidebar";
  name?: string;
  avatarUrl?: string | null;
}

const GroupChatAvatar = ({
  participants,
  type,
  name,
  avatarUrl,
}: GroupChatAvatarProps) => {
  if (avatarUrl) {
    return (
      <UserAvatar
        type={type}
        name={name || "Nhóm"}
        avatarUrl={avatarUrl}
      />
    );
  }

  const avatars = [];
  const limit = Math.min(participants.length, 4);

  for (let i = 0; i < limit; i++) {
    const member = participants[i];
    avatars.push(
      <UserAvatar
        key={member._id}
        type={type}
        name={member.displayName}
        avatarUrl={member.avatarUrl ?? undefined}
      />
    );
  }

  return (
    <div className="relative flex -space-x-2 *:data-[slot=avatar]:ring-2 *:data-[slot=avatar]:ring-background">
      {avatars}

      {participants.length > limit && (
        <div className="z-10 flex size-8 items-center justify-center rounded-full bg-muted text-muted-foreground ring-2 ring-background">
          <Ellipsis className="size-4" />
        </div>
      )}
    </div>
  );
};

export default GroupChatAvatar;
