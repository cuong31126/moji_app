import { Check, Clock, X } from "lucide-react";
import type { ReactNode } from "react";
import { toast } from "sonner";

import UserAvatar from "@/components/chat/UserAvatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useChatStore } from "@/stores/useChatStore";
import type { GroupInvite } from "@/types/chat";
import type { User } from "@/types/user";

const getConversationName = (invite: GroupInvite) =>
  invite.conversation?.group?.name || "Nhóm chat";

const getUserName = (user?: User | null) =>
  user?.displayName || user?.username || "Người dùng Moji";

const GroupInviteRow = ({
  actions,
  avatarUser,
  meta,
  title,
}: {
  actions: ReactNode;
  avatarUser?: User | null;
  meta: string;
  title: string;
}) => (
  <div className="flex min-w-0 flex-col gap-3 rounded-lg border border-border/70 p-3 shadow-sm sm:flex-row sm:items-center sm:justify-between">
    <div className="flex min-w-0 items-center gap-3">
      <UserAvatar
        type="sidebar"
        name={getUserName(avatarUser)}
        avatarUrl={avatarUser?.avatarUrl}
      />
      <div className="min-w-0">
        <p className="truncate text-sm font-medium">{title}</p>
        <p className="truncate text-xs text-muted-foreground">{meta}</p>
      </div>
    </div>
    <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>
  </div>
);

const GroupInvites = () => {
  const {
    acceptGroupInvite,
    adminGroupInvites,
    approveGroupInvite,
    declineGroupInvite,
    groupInvites,
    inviteActionLoadingById,
    rejectGroupInvite,
  } = useChatStore();

  const handleAccept = async (inviteId: string) => {
    try {
      await acceptGroupInvite(inviteId);
      toast.success("Đã đồng ý lời mời nhóm");
    } catch (error) {
      console.error(error);
      toast.error("Không xử lý được lời mời nhóm");
    }
  };

  const handleReject = async (inviteId: string) => {
    try {
      await rejectGroupInvite(inviteId);
      toast.info("Đã từ chối lời mời nhóm");
    } catch (error) {
      console.error(error);
      toast.error("Không từ chối được lời mời nhóm");
    }
  };

  const handleApprove = async (inviteId: string) => {
    try {
      await approveGroupInvite(inviteId);
      toast.success("Đã duyệt thành viên vào nhóm");
    } catch (error) {
      console.error(error);
      toast.error("Không duyệt được lời mời nhóm");
    }
  };

  const handleDecline = async (inviteId: string) => {
    try {
      await declineGroupInvite(inviteId);
      toast.info("Đã từ chối duyệt lời mời nhóm");
    } catch (error) {
      console.error(error);
      toast.error("Không từ chối được lời mời nhóm");
    }
  };

  if (groupInvites.length === 0 && adminGroupInvites.length === 0) {
    return (
      <p className="mt-4 text-sm text-muted-foreground">
        Chưa có lời mời nhóm nào cần xử lý.
      </p>
    );
  }

  return (
    <div className="mt-4 space-y-5">
      {groupInvites.length > 0 && (
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Clock className="size-4 text-primary" />
            <h3 className="text-sm font-semibold">Cần bạn xác nhận</h3>
          </div>

          {groupInvites.map((invite) => (
            <GroupInviteRow
              key={invite._id}
              avatarUser={invite.invitedBy}
              title={getConversationName(invite)}
              meta={`Mời bởi ${getUserName(invite.invitedBy)}`}
              actions={
                <>
                  <Button
                    size="sm"
                    onClick={() => handleAccept(invite._id)}
                    disabled={Boolean(inviteActionLoadingById[invite._id])}
                  >
                    <Check className="size-4" />
                    Đồng ý
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleReject(invite._id)}
                    disabled={Boolean(inviteActionLoadingById[invite._id])}
                  >
                    <X className="size-4" />
                    Từ chối
                  </Button>
                </>
              }
            />
          ))}
        </section>
      )}

      {adminGroupInvites.length > 0 && (
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Badge variant="outline">Admin</Badge>
            <h3 className="text-sm font-semibold">Chờ duyệt vào nhóm</h3>
          </div>

          {adminGroupInvites.map((invite) => (
            <GroupInviteRow
              key={invite._id}
              avatarUser={invite.invitee}
              title={getUserName(invite.invitee)}
              meta={`Đã đồng ý, đang chờ admin duyệt vào ${getConversationName(
                invite
              )}`}
              actions={
                <>
                  <Button
                    size="sm"
                    onClick={() => handleApprove(invite._id)}
                    disabled={Boolean(inviteActionLoadingById[invite._id])}
                  >
                    <Check className="size-4" />
                    Duyệt
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handleDecline(invite._id)}
                    disabled={Boolean(inviteActionLoadingById[invite._id])}
                  >
                    <X className="size-4" />
                    Từ chối
                  </Button>
                </>
              }
            />
          ))}
        </section>
      )}
    </div>
  );
};

export default GroupInvites;
