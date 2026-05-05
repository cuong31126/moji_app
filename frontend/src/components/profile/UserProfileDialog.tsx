import { type FormEvent, useEffect, useMemo, useState } from "react";
import { Check, Clock, KeyRound, Loader2, MessageCircle, UserPlus } from "lucide-react";
import { useNavigate } from "react-router";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { userService } from "@/services/userService";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import type { RelationshipStatus, User } from "@/types/user";
import ProfileCard from "./ProfileCard";
import { Input } from "../ui/input";
import { Label } from "../ui/label";

interface UserProfileDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  userId?: string | null;
  initialUser?: User | null;
}

const statusLabel: Record<RelationshipStatus, string> = {
  self: "Tài khoản của bạn",
  friends: "Bạn bè",
  request_sent: "Đã gửi lời mời",
  request_received: "Đã nhận lời mời",
  none: "Thêm bạn",
};

const ChangePasswordSection = () => {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();

    if (!oldPassword || !newPassword || !confirmPassword) {
      toast.error("Vui lòng nhập đủ thông tin đổi mật khẩu.");
      return;
    }

    if (newPassword.length < 6) {
      toast.error("Mật khẩu mới phải có ít nhất 6 ký tự.");
      return;
    }

    if (newPassword !== confirmPassword) {
      toast.error("Mật khẩu xác nhận không khớp.");
      return;
    }

    // TODO: call API POST /auth/change-password when backend endpoint is available.
    toast.info("Backend chưa có endpoint đổi mật khẩu. UI đã sẵn sàng để nối API.");
  };

  return (
    <form className="space-y-3 border-t border-border/60 p-4" onSubmit={handleSubmit}>
      <div className="flex items-center gap-2 text-sm font-semibold">
        <KeyRound className="size-4 text-primary" />
        Đổi mật khẩu
      </div>
      <div className="grid gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="profile-old-password">Mật khẩu cũ</Label>
          <Input
            id="profile-old-password"
            type="password"
            value={oldPassword}
            onChange={(event) => setOldPassword(event.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="profile-new-password">Mật khẩu mới</Label>
          <Input
            id="profile-new-password"
            type="password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="profile-confirm-password">Xác nhận mật khẩu</Label>
          <Input
            id="profile-confirm-password"
            type="password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)}
          />
        </div>
      </div>
      <Button type="submit" className="w-full sm:w-auto">
        Lưu
      </Button>
    </form>
  );
};

const UserProfileDialog = ({
  open,
  onOpenChange,
  userId,
  initialUser,
}: UserProfileDialogProps) => {
  const navigate = useNavigate();
  const { user: currentUser } = useAuthStore();
  const { addFriend, acceptRequest } = useFriendStore();
  const [profileUser, setProfileUser] = useState<User | null>(initialUser ?? null);
  const [loadingProfile, setLoadingProfile] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  const targetUserId = userId || initialUser?._id || null;

  useEffect(() => {
    if (!open) {
      return;
    }

    if (initialUser) {
      setProfileUser(initialUser);
    }

    if (!targetUserId) {
      return;
    }

    let cancelled = false;

    const loadProfile = async () => {
      try {
        setLoadingProfile(true);
        const detail = await userService.getUserById(targetUserId);
        if (!cancelled) {
          setProfileUser(detail);
        }
      } catch (error) {
        console.error(error);
        toast.error("Không tải được thông tin người dùng");
      } finally {
        if (!cancelled) {
          setLoadingProfile(false);
        }
      }
    };

    loadProfile();

    return () => {
      cancelled = true;
    };
  }, [initialUser, open, targetUserId]);

  const relationshipStatus: RelationshipStatus = useMemo(() => {
    if (!profileUser) return "none";
    if (profileUser._id === currentUser?._id) return "self";
    return profileUser.relationshipStatus ?? "none";
  }, [currentUser?._id, profileUser]);

  const canMessage = relationshipStatus === "friends";
  const canSendRequest = relationshipStatus === "none";
  const canAcceptRequest =
    relationshipStatus === "request_received" && Boolean(profileUser?.friendRequestId);

  const openDirectConversation = async (targetUserId: string) => {
    const chatState = useChatStore.getState();
    const existingConversation = chatState.conversations.find(
      (conversation) =>
        conversation.type === "direct" &&
        conversation.participants.some(
          (participant) => participant._id === targetUserId
        )
    );

    if (existingConversation) {
      chatState.setActiveConversation(existingConversation._id);

      if (!chatState.messages[existingConversation._id]) {
        await chatState.fetchMessages(existingConversation._id);
      }
    } else {
      await chatState.createConversation("direct", "", [targetUserId]);
    }

    onOpenChange(false);
    navigate("/");
  };

  const handleFriendAction = async () => {
    if (!profileUser || relationshipStatus === "self") {
      return;
    }

    try {
      setActionLoading(true);

      if (canAcceptRequest && profileUser.friendRequestId) {
        await acceptRequest(profileUser.friendRequestId);
        setProfileUser({ ...profileUser, relationshipStatus: "friends" });
        toast.success("Đã chấp nhận lời mời kết bạn");
        await openDirectConversation(profileUser._id);
        return;
      }

      if (canSendRequest) {
        const message = await addFriend(profileUser._id);
        setProfileUser({ ...profileUser, relationshipStatus: "request_sent" });
        toast.success(message);
      }
    } catch (error) {
      console.error(error);
      toast.error(error instanceof Error ? error.message : "Không thực hiện được");
    } finally {
      setActionLoading(false);
    }
  };

  const handleMessage = async () => {
    if (!profileUser || !canMessage) {
      return;
    }

    try {
      setActionLoading(true);

      await openDirectConversation(profileUser._id);
    } catch (error) {
      console.error(error);
      toast.error("Không mở được cuộc trò chuyện");
    } finally {
      setActionLoading(false);
    }
  };

  const friendButtonIcon = () => {
    if (actionLoading) return <Loader2 className="size-4 animate-spin" />;
    if (relationshipStatus === "friends") return <Check className="size-4" />;
    if (relationshipStatus === "request_sent") return <Clock className="size-4" />;
    return <UserPlus className="size-4" />;
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
    >
      <DialogContent className="z-[9999] overflow-hidden border-0 p-0 sm:max-w-xl">
        <DialogHeader className="sr-only">
          <DialogTitle>Thông tin người dùng</DialogTitle>
          <DialogDescription>Xem thông tin và thao tác với người dùng.</DialogDescription>
        </DialogHeader>

        {loadingProfile && !profileUser ? (
          <div className="flex min-h-64 items-center justify-center">
            <Loader2 className="size-6 animate-spin text-primary" />
          </div>
        ) : (
          <div className="bg-background">
            <ProfileCard
              user={profileUser}
              editable={false}
            />

            {profileUser && (
              <div className="grid gap-2 p-4 sm:grid-cols-2">
                <Button
                  type="button"
                  variant={canMessage ? "default" : "outline"}
                  onClick={handleMessage}
                  disabled={!canMessage || actionLoading}
                  title="Mở cuộc trò chuyện"
                >
                  <MessageCircle className="size-4" />
                  Nhắn tin
                </Button>

                <Button
                  type="button"
                  variant={canSendRequest || canAcceptRequest ? "default" : "outline"}
                  onClick={handleFriendAction}
                  title="Kết bạn hoặc chấp nhận lời mời"
                  disabled={
                    actionLoading ||
                    relationshipStatus === "self" ||
                    relationshipStatus === "friends" ||
                    relationshipStatus === "request_sent"
                  }
                >
                  {friendButtonIcon()}
                  {canAcceptRequest ? "Chấp nhận lời mời" : statusLabel[relationshipStatus]}
                </Button>
                {relationshipStatus === "self" && (
                  <div className="sm:col-span-2">
                    <ChangePasswordSection />
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
};

export default UserProfileDialog;
