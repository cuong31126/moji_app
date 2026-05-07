import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";

import UserAvatar from "@/components/chat/UserAvatar";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { openDirectConversation } from "@/lib/openDirectConversation";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import type { GroupInvite } from "@/types/chat";
import type { FriendRequest, User } from "@/types/user";

type PendingInvite =
  | { kind: "friend"; id: string; request: FriendRequest }
  | { kind: "group"; id: string; invite: GroupInvite }
  | { kind: "group_admin"; id: string; invite: GroupInvite };

const getUserName = (user?: Partial<User> | null) =>
  user?.displayName || user?.username || "Người dùng Moji";

const getConversationName = (invite: GroupInvite) =>
  invite.conversation?.group?.name || "Nhóm chat";

const IncomingInviteDialog = () => {
  const navigate = useNavigate();
  const {
    acceptRequest,
    declineRequest,
    loading: friendLoading,
    receivedList,
  } = useFriendStore();
  const {
    acceptGroupInvite,
    adminGroupInvites,
    approveGroupInvite,
    declineGroupInvite,
    groupInvites,
    inviteActionLoadingById,
    rejectGroupInvite,
  } = useChatStore();
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set());
  const [handlingId, setHandlingId] = useState<string | null>(null);

  const current = useMemo<PendingInvite | null>(() => {
    const friendRequest = receivedList.find(
      (request) => !dismissedIds.has(`friend:${request._id}`)
    );

    if (friendRequest) {
      return {
        kind: "friend",
        id: `friend:${friendRequest._id}`,
        request: friendRequest,
      };
    }

    const groupInvite = groupInvites.find(
      (invite) => !dismissedIds.has(`group:${invite._id}`)
    );

    if (groupInvite) {
      return {
        kind: "group",
        id: `group:${groupInvite._id}`,
        invite: groupInvite,
      };
    }

    const adminInvite = adminGroupInvites.find(
      (invite) => !dismissedIds.has(`group_admin:${invite._id}`)
    );

    return adminInvite
      ? {
          kind: "group_admin",
          id: `group_admin:${adminInvite._id}`,
          invite: adminInvite,
        }
      : null;
  }, [adminGroupInvites, dismissedIds, groupInvites, receivedList]);

  const dismissCurrent = () => {
    if (!current) return;
    setDismissedIds((ids) => new Set(ids).add(current.id));
  };

  const handleAccept = async () => {
    if (!current) return;

    try {
      setHandlingId(current.id);

      if (current.kind === "friend") {
        const friend = await acceptRequest(current.request._id);
        toast.success("Đã chấp nhận lời mời kết bạn");

        if (friend?._id) {
          await openDirectConversation(friend._id);
          navigate("/");
        }
        return;
      }

      if (current.kind === "group") {
        await acceptGroupInvite(current.invite._id);
        toast.success("Đã đồng ý lời mời nhóm");
        navigate("/");
        return;
      }

      await approveGroupInvite(current.invite._id);
      toast.success("Đã duyệt thành viên vào nhóm");
    } catch (error) {
      console.error(error);
      toast.error("Không xử lý được lời mời");
    } finally {
      setHandlingId(null);
    }
  };

  const handleReject = async () => {
    if (!current) return;

    try {
      setHandlingId(current.id);

      if (current.kind === "friend") {
        await declineRequest(current.request._id);
        toast.info("Đã từ chối lời mời kết bạn");
        return;
      }

      if (current.kind === "group") {
        await rejectGroupInvite(current.invite._id);
        toast.info("Đã từ chối lời mời nhóm");
        return;
      }

      await declineGroupInvite(current.invite._id);
      toast.info("Đã từ chối duyệt lời mời nhóm");
    } catch (error) {
      console.error(error);
      toast.error("Không từ chối được lời mời");
    } finally {
      setHandlingId(null);
    }
  };

  const activeGroupInvite =
    current && current.kind !== "friend" ? current.invite : null;
  const isHandling =
    Boolean(current && handlingId === current.id) ||
    friendLoading ||
    Boolean(activeGroupInvite && inviteActionLoadingById[activeGroupInvite._id]);
  const avatarUser =
    current?.kind === "friend"
      ? current.request.from
      : current?.kind === "group"
      ? current.invite.invitedBy
      : current?.invite.invitee;
  const title =
    current?.kind === "friend"
      ? "Lời mời kết bạn"
      : current?.kind === "group"
      ? "Lời mời vào nhóm"
      : "Yêu cầu vào nhóm";
  const description =
    current?.kind === "friend"
      ? `${getUserName(current.request.from)} muốn kết bạn với bạn.`
      : current?.kind === "group"
      ? `${getUserName(current.invite.invitedBy)} mời bạn vào ${getConversationName(
          current.invite
        )}.`
      : current?.kind === "group_admin"
      ? `${getUserName(current.invite.invitee)} đang chờ duyệt vào ${getConversationName(
          current.invite
        )}.`
      : "";

  return (
    <Dialog
      open={Boolean(current)}
      onOpenChange={(open) => {
        if (!open) dismissCurrent();
      }}
    >
      <DialogContent className="z-[10000] w-[calc(100vw-2rem)] sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        {current && (
          <div className="flex items-center gap-3 rounded-lg border border-border/70 p-3">
            <UserAvatar
              type="sidebar"
              name={getUserName(avatarUser)}
              avatarUrl={avatarUser?.avatarUrl}
            />
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">
                {getUserName(avatarUser)}
              </p>
              <p className="truncate text-xs text-muted-foreground">
                {current.kind === "friend"
                  ? current.request.message || "Muốn kết nối với bạn"
                  : getConversationName(current.invite)}
              </p>
            </div>
          </div>
        )}

        <DialogFooter className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <Button
            type="button"
            variant="outline"
            onClick={handleReject}
            disabled={isHandling}
          >
            Từ chối
          </Button>
          <Button
            type="button"
            onClick={handleAccept}
            disabled={isHandling}
          >
            Chấp nhận
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default IncomingInviteDialog;
