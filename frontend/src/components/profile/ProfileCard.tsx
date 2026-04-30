import type { ReactNode } from "react";
import type { User } from "@/types/user";
import { Card, CardContent } from "../ui/card";
import UserAvatar from "../chat/UserAvatar";
import { Badge } from "../ui/badge";
import { cn } from "@/lib/utils";
import { useSocketStore } from "@/stores/useSocketStore";
import AvatarUploader from "./AvatarUploader";

interface ProfileCardProps {
  user: User | null;
  editable?: boolean;
  actionSlot?: ReactNode;
}

const ProfileCard = ({ user, editable = true, actionSlot }: ProfileCardProps) => {
  const { onlineUsers } = useSocketStore();
  if (!user) return null;

  const bio = user.bio || "Cùng nhau xây dựng một cộng đồng xanh hơn.";
  const isOnline = onlineUsers.includes(user._id);

  return (
    <Card className="overflow-hidden border-0 bg-gradient-to-r from-emerald-700 via-teal-600 to-sky-500 p-0 shadow-soft">
      <CardContent className="flex min-h-52 flex-col items-center gap-5 px-5 pb-6 pt-10 sm:flex-row sm:items-end sm:pt-20">
        <div className="relative shrink-0">
          <UserAvatar
            type="profile"
            name={user.displayName}
            avatarUrl={user.avatarUrl ?? undefined}
            className="ring-4 ring-white shadow-lg"
          />

          {editable && <AvatarUploader />}
        </div>

        <div className="min-w-0 flex-1 text-center sm:text-left">
          <h1 className="truncate text-2xl font-semibold text-white">
            {user.displayName}
          </h1>
          <p className="mt-1 truncate text-sm text-white/80">@{user.username}</p>
          {user.email && (
            <p className="mt-1 truncate text-sm text-white/75">{user.email}</p>
          )}
          <p className="mt-3 line-clamp-2 text-sm leading-6 text-white/75">{bio}</p>
        </div>

        <div className="flex shrink-0 flex-col items-center gap-2 sm:items-end">
          <Badge
            className={cn(
              "flex items-center gap-1 capitalize",
              isOnline ? "bg-green-100 text-green-700" : "bg-slate-100 text-slate-700"
            )}
          >
            <span
              className={cn(
                "size-2 rounded-full",
                isOnline ? "animate-pulse bg-green-500" : "bg-slate-500"
              )}
            />
            {isOnline ? "online" : "offline"}
          </Badge>

          {actionSlot}
        </div>
      </CardContent>
    </Card>
  );
};

export default ProfileCard;
