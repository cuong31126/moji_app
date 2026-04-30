import { useEffect, useMemo, useState } from "react";
import { Check, Clock, Loader2, MessageCircle, UserPlus } from "lucide-react";
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

const UserProfileDialog = ({
  open,
  onOpenChange,
  userId,
  initialUser,
}: UserProfileDialogProps) => {
  const navigate = useNavigate();
  const { user: currentUser } = useAuthStore();
  const { addFriend, acceptRequest } = useFriendStore();
  const {
    conversations,
    messages,
    setActiveConversation,
    fetchMessages,
    createConversation,
  } = useChatStore();
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

  const existingDirectConversation = useMemo(() => {
    if (!profileUser) return null;

    return (
      conversations.find(
        (conversation) =>
          conversation.type === "direct" &&
          conversation.participants.some(
            (participant) => participant._id === profileUser._id
          )
      ) ?? null
    );
  }, [conversations, profileUser]);

  const canMessage = relationshipStatus === "friends";
  const canSendRequest = relationshipStatus === "none";
  const canAcceptRequest =
    relationshipStatus === "request_received" && Boolean(profileUser?.friendRequestId);

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

      if (existingDirectConversation) {
        setActiveConversation(existingDirectConversation._id);
        if (!messages[existingDirectConversation._id]) {
          await fetchMessages(existingDirectConversation._id);
        }
      } else {
        await createConversation("direct", "", [profileUser._id]);
      }

      onOpenChange(false);
      navigate("/");
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
                >
                  <MessageCircle className="size-4" />
                  Nhắn tin
                </Button>

                <Button
                  type="button"
                  variant={canSendRequest || canAcceptRequest ? "default" : "outline"}
                  onClick={handleFriendAction}
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
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
};

export default UserProfileDialog;
