import type { FriendRequest } from "@/types/user";
import type { ReactNode } from "react";
import UserAvatar from "../chat/UserAvatar";

interface RequestItemProps {
  requestInfo: FriendRequest;
  actions: ReactNode;
  type: "sent" | "received";
}

const FriendRequestItem = ({ requestInfo, actions, type }: RequestItemProps) => {
  if (!requestInfo) {
    return;
  }
  const info = type === "sent" ? requestInfo.to : requestInfo.from;

  if (!info) {
    return;
  }

  return (
    <div className="flex min-w-0 flex-col gap-3 rounded-lg border border-primary-foreground p-3 shadow-md sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-center gap-3">
        <UserAvatar
          type="sidebar"
          name={info.displayName}
        />
        <div className="min-w-0">
          <p className="truncate font-medium">{info.displayName}</p>
          <p className="truncate text-sm text-muted-foreground">@{info.username}</p>
        </div>
      </div>
      {actions}
    </div>
  );
};

export default FriendRequestItem;
