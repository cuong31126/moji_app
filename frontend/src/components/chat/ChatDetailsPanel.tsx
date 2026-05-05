import {
  Camera,
  Check,
  Copy,
  Info,
  Link as LinkIcon,
  Loader2,
  LogOut,
  Save,
  Search,
  ShieldCheck,
  ShieldOff,
  Trash2,
  UserMinus,
  UserPlus,
  X,
} from "lucide-react";
import {
  type ChangeEvent,
  type FormEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { toast } from "sonner";

import type { Conversation, Participant } from "@/types/chat";
import type { Friend } from "@/types/user";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import { cn } from "@/lib/utils";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Separator } from "../ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "../ui/sheet";
import GroupChatAvatar from "./GroupChatAvatar";
import UserAvatar from "./UserAvatar";

interface ChatDetailsPanelProps {
  chat: Conversation;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const MAX_AVATAR_SIZE = 10 * 1024 * 1024;

const getRoleLabel = (role?: "admin" | "member") =>
  role === "admin" ? "Quản trị viên" : "Thành viên";

const getErrorMessage = (error: unknown, fallback: string) => {
  const maybeError = error as {
    message?: string;
    response?: { data?: { message?: string } };
  };

  return maybeError.response?.data?.message || maybeError.message || fallback;
};

const formatDate = (date?: string) => {
  if (!date) return "";

  return new Date(date).toLocaleDateString("vi-VN", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
};

const useIsDesktop = () => {
  const [isDesktop, setIsDesktop] = useState(() =>
    typeof window === "undefined"
      ? false
      : window.matchMedia("(min-width: 1024px)").matches
  );

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const media = window.matchMedia("(min-width: 1024px)");
    const handleChange = () => setIsDesktop(media.matches);

    handleChange();
    media.addEventListener("change", handleChange);

    return () => media.removeEventListener("change", handleChange);
  }, []);

  return isDesktop;
};

const SectionTitle = ({
  children,
  count,
}: {
  children: ReactNode;
  count?: number;
}) => (
  <div className="flex items-center justify-between gap-3 px-1">
    <h3 className="text-xs font-semibold uppercase text-muted-foreground">
      {children}
    </h3>
    {typeof count === "number" && <Badge variant="outline">{count}</Badge>}
  </div>
);

const ActionButton = ({
  children,
  danger,
  disabled,
  onClick,
}: {
  children: ReactNode;
  danger?: boolean;
  disabled?: boolean;
  onClick?: () => void;
}) => (
  <Button
    type="button"
    variant={danger ? "destructiveOutline" : "ghost"}
    className="h-10 w-full justify-start rounded-lg px-3 text-left"
    disabled={disabled}
    onClick={onClick}
  >
    {children}
  </Button>
);

const MemberRoleBadge = ({
  isCreator,
  role,
}: {
  isCreator: boolean;
  role?: "admin" | "member";
}) => (
  <div className="flex shrink-0 flex-wrap justify-end gap-1">
    {isCreator && (
      <Badge variant="outline" className="border-primary/30 text-primary">
        Chủ nhóm
      </Badge>
    )}
    <Badge
      variant="outline"
      className={
        role === "admin"
          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
          : ""
      }
    >
      {getRoleLabel(role)}
    </Badge>
  </div>
);

const ChatDetailsContent = ({
  chat,
  onClose,
}: {
  chat: Conversation;
  onClose: () => void;
}) => {
  const avatarInputRef = useRef<HTMLInputElement>(null);
  const [groupName, setGroupName] = useState(chat.group?.name || "");
  const [uploadingAvatar, setUploadingAvatar] = useState(false);
  const [savingName, setSavingName] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteSearch, setInviteSearch] = useState("");
  const [selectedFriends, setSelectedFriends] = useState<Friend[]>([]);
  const [messageSearch, setMessageSearch] = useState("");
  const { user } = useAuthStore();
  const {
    activeConversationId,
    adminGroupInvites,
    approveGroupInvite,
    declineGroupInvite,
    deleteGroupConversation,
    inviteGroupMembers,
    inviteActionLoadingById,
    leaveGroupConversation,
    loading,
    messages,
    removeGroupMember,
    updateGroupInfo,
    updateGroupMemberRole,
    uploadGroupAvatar,
  } = useChatStore();
  const {
    friends,
    getFriends,
    loading: friendsLoading,
  } = useFriendStore();

  const otherUser =
    chat.type === "direct"
      ? chat.participants.find((participant) => participant._id !== user?._id)
      : null;
  const currentUserRole =
    chat.participants.find((participant) => participant._id === user?._id)
      ?.role || "member";
  const isAdmin = currentUserRole === "admin";
  const memberIds = useMemo(
    () => new Set(chat.participants.map((participant) => participant._id)),
    [chat.participants]
  );
  const pendingApprovals = adminGroupInvites.filter(
    (invite) =>
      invite.conversationId === chat._id || invite.conversation?._id === chat._id
  );
  const groupShareLink = useMemo(() => {
    if (typeof window === "undefined") {
      return `/chat?conversationId=${chat._id}`;
    }

    return `${window.location.origin}/chat?conversationId=${encodeURIComponent(
      chat._id
    )}`;
  }, [chat._id]);
  const messageResults = useMemo(() => {
    const query = messageSearch.trim().toLowerCase();

    if (!query) {
      return [];
    }

    const currentMessages = activeConversationId
      ? messages[activeConversationId]?.items ?? []
      : [];

    return currentMessages
      .filter((message) => message.content?.toLowerCase().includes(query))
      .slice(-8)
      .reverse();
  }, [activeConversationId, messageSearch, messages]);
  const availableFriends = useMemo(() => {
    const query = inviteSearch.trim().toLowerCase();
    const selectedIds = new Set(selectedFriends.map((friend) => friend._id));

    return friends.filter((friend) => {
      if (memberIds.has(friend._id) || selectedIds.has(friend._id)) {
        return false;
      }

      if (!query) {
        return true;
      }

      return (
        friend.displayName.toLowerCase().includes(query) ||
        friend.username?.toLowerCase().includes(query)
      );
    });
  }, [friends, inviteSearch, memberIds, selectedFriends]);

  useEffect(() => {
    setGroupName(chat.group?.name || "");
    setInviteOpen(false);
    setInviteSearch("");
    setSelectedFriends([]);
    setMessageSearch("");
  }, [chat._id, chat.group?.name]);

  const handleAvatarChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";

    if (!file) {
      return;
    }

    if (!file.type.startsWith("image/")) {
      toast.error("Vui lòng chọn file ảnh.");
      return;
    }

    if (file.size > MAX_AVATAR_SIZE) {
      toast.error("Ảnh nhóm không được vượt quá 10MB.");
      return;
    }

    try {
      setUploadingAvatar(true);
      await uploadGroupAvatar(chat._id, file);
      toast.success("Đã cập nhật ảnh nhóm.");
    } catch (error) {
      console.error("Không cập nhật được ảnh nhóm", error);
      toast.error(getErrorMessage(error, "Không cập nhật được ảnh nhóm."));
    } finally {
      setUploadingAvatar(false);
    }
  };

  const handleSaveGroupName = async (event: FormEvent) => {
    event.preventDefault();

    const nextName = groupName.trim();

    if (!nextName || nextName === chat.group?.name) {
      return;
    }

    try {
      setSavingName(true);
      await updateGroupInfo(chat._id, nextName);
      toast.success("Đã đổi tên nhóm.");
    } catch (error) {
      console.error("Không đổi được tên nhóm", error);
      toast.error(getErrorMessage(error, "Không đổi được tên nhóm."));
    } finally {
      setSavingName(false);
    }
  };

  const handleOpenInvite = async () => {
    setInviteOpen(true);

    if (friends.length === 0) {
      await getFriends();
    }
  };

  const handleCopyGroupLink = async () => {
    try {
      await navigator.clipboard.writeText(groupShareLink);
      toast.success("Đã sao chép link nhóm.");
    } catch (error) {
      console.error("Không sao chép được link nhóm", error);
      toast.error("Không sao chép được link nhóm.");
    }
  };

  const handleSelectFriend = (friend: Friend) => {
    setSelectedFriends((current) =>
      current.some((item) => item._id === friend._id)
        ? current
        : [...current, friend]
    );
    setInviteSearch("");
  };

  const handleRemoveSelectedFriend = (friendId: string) => {
    setSelectedFriends((current) =>
      current.filter((friend) => friend._id !== friendId)
    );
  };

  const handleInviteMembers = async () => {
    if (selectedFriends.length === 0) {
      toast.info("Chọn ít nhất một bạn bè để mời vào nhóm.");
      return;
    }

    try {
      const invitedIds = await inviteGroupMembers(
        chat._id,
        selectedFriends.map((friend) => friend._id)
      );

      if (invitedIds.length > 0) {
        toast.success(`Đã gửi ${invitedIds.length} lời mời vào nhóm.`);
      } else {
        toast.info("Không có lời mời mới cần gửi.");
      }

      setSelectedFriends([]);
      setInviteSearch("");
      setInviteOpen(false);
    } catch (error) {
      console.error("Không mời được thành viên", error);
      toast.error(getErrorMessage(error, "Không mời được thành viên."));
    }
  };

  const handleApproveInvite = async (inviteId: string) => {
    try {
      await approveGroupInvite(inviteId);
      toast.success("Đã duyệt thành viên vào nhóm.");
    } catch (error) {
      console.error("Không duyệt được lời mời nhóm", error);
      toast.error(getErrorMessage(error, "Không duyệt được lời mời nhóm."));
    }
  };

  const handleDeclineInvite = async (inviteId: string) => {
    try {
      await declineGroupInvite(inviteId);
      toast.info("Đã từ chối lời mời nhóm.");
    } catch (error) {
      console.error("Không từ chối được lời mời nhóm", error);
      toast.error(getErrorMessage(error, "Không từ chối được lời mời nhóm."));
    }
  };

  const handleRoleChange = async (
    participant: Participant,
    role: "admin" | "member"
  ) => {
    try {
      await updateGroupMemberRole(chat._id, participant._id, role);
      toast.success(
        role === "admin"
          ? `Đã thêm quyền quản trị cho ${participant.displayName}.`
          : `Đã gỡ quyền quản trị của ${participant.displayName}.`
      );
    } catch (error) {
      console.error("Không cập nhật được quyền thành viên", error);
      toast.error(getErrorMessage(error, "Không cập nhật được quyền thành viên."));
    }
  };

  const handleRemoveMember = async (participant: Participant) => {
    const confirmed = window.confirm(
      `Xóa ${participant.displayName} khỏi nhóm này?`
    );

    if (!confirmed) {
      return;
    }

    try {
      await removeGroupMember(chat._id, participant._id);
      toast.success(`Đã xóa ${participant.displayName} khỏi nhóm.`);
    } catch (error) {
      console.error("Không xóa được thành viên khỏi nhóm", error);
      toast.error(getErrorMessage(error, "Không xóa được thành viên khỏi nhóm."));
    }
  };

  const handleLeaveGroup = async () => {
    const confirmed = window.confirm("Bạn chắc chắn muốn rời nhóm này?");

    if (!confirmed) {
      return;
    }

    try {
      await leaveGroupConversation(chat._id);
      toast.success("Đã rời nhóm.");
      onClose();
    } catch (error) {
      console.error("Không rời được nhóm", error);
      toast.error(getErrorMessage(error, "Không rời được nhóm."));
    }
  };

  const handleDeleteGroup = async () => {
    const confirmed = window.confirm(
      "Xóa nhóm này cho tất cả thành viên? Thao tác này không thể hoàn tác."
    );

    if (!confirmed) {
      return;
    }

    try {
      await deleteGroupConversation(chat._id);
      toast.success("Đã xóa nhóm.");
      onClose();
    } catch (error) {
      console.error("Không xóa được nhóm", error);
      toast.error(getErrorMessage(error, "Không xóa được nhóm."));
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <input
        ref={avatarInputRef}
        type="file"
        accept="image/*"
        className="hidden"
        onChange={handleAvatarChange}
      />

      <div className="flex shrink-0 flex-col items-center gap-3 border-b border-border/70 p-5 text-center">
        <div className="relative">
          {chat.type === "direct" ? (
            <UserAvatar
              type="sidebar"
              name={otherUser?.displayName || "Moji"}
              avatarUrl={otherUser?.avatarUrl ?? undefined}
            />
          ) : (
            <GroupChatAvatar
              participants={chat.participants}
              type="sidebar"
              name={chat.group?.name}
              avatarUrl={chat.group?.avatarUrl}
            />
          )}

          {chat.type === "group" && isAdmin && (
            <button
              type="button"
              className="absolute -bottom-1 -right-1 flex size-8 items-center justify-center rounded-full border border-border bg-background text-foreground shadow-sm transition hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
              title="Đổi ảnh nhóm"
              aria-label="Đổi ảnh nhóm"
              disabled={uploadingAvatar || loading}
              onClick={() => avatarInputRef.current?.click()}
            >
              {uploadingAvatar ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Camera className="size-4" />
              )}
            </button>
          )}
        </div>

        <div className="min-w-0">
          <h2 className="truncate text-base font-semibold">
            {chat.type === "direct"
              ? otherUser?.displayName || "Tin nhắn riêng"
              : chat.group?.name || "Nhóm chat"}
          </h2>
          <p className="mt-1 text-xs text-muted-foreground">
            {chat.type === "direct"
              ? otherUser?.username
                ? `@${otherUser.username}`
                : "Bạn bè"
              : `${chat.participants.length} thành viên - ${getRoleLabel(
                  currentUserRole
                )}`}
          </p>
        </div>

        {chat.type === "group" && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="rounded-full"
            disabled={!isAdmin || uploadingAvatar || loading}
            onClick={() => avatarInputRef.current?.click()}
          >
            {uploadingAvatar ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Camera className="size-4" />
            )}
            {isAdmin ? "Đổi ảnh nhóm" : "Chỉ admin đổi ảnh nhóm"}
          </Button>
        )}
      </div>

      <div className="beautiful-scrollbar min-h-0 flex-1 space-y-5 overflow-y-auto p-4">
        <section className="space-y-3">
          <SectionTitle>Tìm trong cuộc trò chuyện</SectionTitle>
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={messageSearch}
              onChange={(event) => setMessageSearch(event.target.value)}
              placeholder="Nhập từ khóa"
              className="h-10 rounded-lg pl-9"
            />
          </div>
          {messageSearch.trim() && (
            <div className="space-y-2">
              {messageResults.length > 0 ? (
                messageResults.map((message) => {
                  const sender = chat.participants.find(
                    (participant) => participant._id === message.senderId
                  );

                  return (
                    <div
                      key={message._id}
                      className="rounded-lg border border-border/70 px-3 py-2 text-sm"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate font-medium">
                          {sender?.displayName || "Moji"}
                        </span>
                        <span className="shrink-0 text-xs text-muted-foreground">
                          {formatDate(message.createdAt)}
                        </span>
                      </div>
                      <p className="mt-1 line-clamp-2 text-muted-foreground">
                        {message.content}
                      </p>
                    </div>
                  );
                })
              ) : (
                <p className="rounded-lg bg-muted/60 p-3 text-sm text-muted-foreground">
                  Không tìm thấy tin nhắn phù hợp.
                </p>
              )}
            </div>
          )}
        </section>

        {chat.type === "direct" ? (
          <>
            <Separator />

            <section className="space-y-3">
              <SectionTitle>Thông tin bạn chat</SectionTitle>
              <div className="space-y-2 rounded-lg border border-border/70 p-3 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-muted-foreground">Tên hiển thị</span>
                  <span className="truncate font-medium">
                    {otherUser?.displayName || "Moji"}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-muted-foreground">Tên đăng nhập</span>
                  <span className="truncate font-medium">
                    {otherUser?.username ? `@${otherUser.username}` : "Chưa có"}
                  </span>
                </div>
              </div>
            </section>
          </>
        ) : (
          <>
            <Separator />

            <section className="space-y-3">
              <SectionTitle>Thông tin nhóm</SectionTitle>
              <form className="space-y-2" onSubmit={handleSaveGroupName}>
                <Label htmlFor="group-name">Tên nhóm</Label>
                <div className="flex gap-2">
                  <Input
                    id="group-name"
                    value={groupName}
                    disabled={!isAdmin || loading || savingName}
                    maxLength={80}
                    onChange={(event) => setGroupName(event.target.value)}
                    className="h-10 rounded-lg"
                  />
                  <Button
                    type="submit"
                    variant="outline"
                    className="h-10 rounded-lg"
                    disabled={
                      !isAdmin ||
                      loading ||
                      savingName ||
                      !groupName.trim() ||
                      groupName.trim() === chat.group?.name
                    }
                  >
                    {savingName ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <Save className="size-4" />
                    )}
                    Lưu
                  </Button>
                </div>
              </form>
              <div className="space-y-2 rounded-lg border border-border/70 p-3">
                <div className="flex items-center gap-2 text-sm font-medium">
                  <LinkIcon className="size-4 text-primary" />
                  Link chia sẻ nhóm
                </div>
                <div
                  className="truncate rounded-md bg-muted/60 px-2 py-1.5 font-mono text-xs text-muted-foreground"
                  title={groupShareLink}
                >
                  {groupShareLink}
                </div>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="flex-1 rounded-lg"
                    onClick={handleCopyGroupLink}
                  >
                    <Copy className="size-4" />
                    Sao chép link
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    className="flex-1 rounded-lg"
                    disabled={loading}
                    onClick={handleOpenInvite}
                  >
                    <UserPlus className="size-4" />
                    Mời vào nhóm
                  </Button>
                </div>
              </div>
              {!isAdmin && (
                <p className="px-1 text-xs text-muted-foreground">
                  Chỉ quản trị viên được đổi tên và ảnh nhóm.
                </p>
              )}
            </section>

            <Separator />

            <section className="space-y-3">
              <SectionTitle count={chat.participants.length}>Thành viên</SectionTitle>

              <div className="space-y-2">
                {chat.participants.map((participant) => {
                  const isSelf = participant._id === user?._id;
                  const isCreator = chat.group?.createdBy === participant._id;
                  const canManageMember = isAdmin && !isSelf && !isCreator;
                  const nextRole =
                    participant.role === "admin" ? "member" : "admin";

                  return (
                    <div
                      key={participant._id}
                      className="flex min-w-0 items-center gap-3 rounded-lg border border-border/70 px-3 py-2"
                    >
                      <UserAvatar
                        type="chat"
                        name={participant.displayName}
                        avatarUrl={participant.avatarUrl ?? undefined}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium">
                          {participant.displayName}
                          {isSelf ? " (bạn)" : ""}
                        </p>
                        <p className="truncate text-xs text-muted-foreground">
                          {participant.username
                            ? `@${participant.username}`
                            : "Thành viên"}
                        </p>
                      </div>

                      <MemberRoleBadge
                        isCreator={isCreator}
                        role={participant.role}
                      />

                      {canManageMember && (
                        <div className="flex shrink-0 items-center gap-1">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-sm"
                            title={
                              nextRole === "admin"
                                ? "Thêm quyền quản trị"
                                : "Gỡ quyền quản trị"
                            }
                            disabled={loading}
                            onClick={() => handleRoleChange(participant, nextRole)}
                          >
                            {nextRole === "admin" ? (
                              <ShieldCheck className="size-4" />
                            ) : (
                              <ShieldOff className="size-4" />
                            )}
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-sm"
                            title="Xóa khỏi nhóm"
                            disabled={loading}
                            onClick={() => handleRemoveMember(participant)}
                          >
                            <UserMinus className="size-4 text-destructive" />
                          </Button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>

            <Separator />

            <section className="space-y-3">
              <div className="flex items-center justify-between gap-3">
                <SectionTitle>Mời thành viên</SectionTitle>
                {!inviteOpen && (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="rounded-full"
                    disabled={loading}
                    onClick={handleOpenInvite}
                  >
                    <UserPlus className="size-4" />
                    Mời
                  </Button>
                )}
              </div>

              {inviteOpen && (
                <div className="space-y-3 rounded-lg border border-border/70 p-3">
                  <div className="flex gap-2">
                    <Input
                      value={inviteSearch}
                      onChange={(event) => setInviteSearch(event.target.value)}
                      placeholder="Tìm bạn bè"
                      className="h-10 rounded-lg"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      title="Đóng"
                      onClick={() => setInviteOpen(false)}
                    >
                      <X className="size-4" />
                    </Button>
                  </div>

                  {selectedFriends.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {selectedFriends.map((friend) => (
                        <Badge
                          key={friend._id}
                          variant="outline"
                          className="gap-1 rounded-full py-1"
                        >
                          {friend.displayName}
                          <button
                            type="button"
                            title="Bỏ chọn"
                            onClick={() => handleRemoveSelectedFriend(friend._id)}
                          >
                            <X className="size-3" />
                          </button>
                        </Badge>
                      ))}
                    </div>
                  )}

                  <div className="max-h-52 space-y-2 overflow-y-auto pr-1">
                    {friendsLoading ? (
                      <div className="flex items-center gap-2 rounded-lg bg-muted/60 p-3 text-sm text-muted-foreground">
                        <Loader2 className="size-4 animate-spin" />
                        Đang tải bạn bè...
                      </div>
                    ) : availableFriends.length > 0 ? (
                      availableFriends.map((friend) => (
                        <button
                          key={friend._id}
                          type="button"
                          className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition hover:bg-accent"
                          onClick={() => handleSelectFriend(friend)}
                        >
                          <UserAvatar
                            type="chat"
                            name={friend.displayName}
                            avatarUrl={friend.avatarUrl ?? undefined}
                          />
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-sm font-medium">
                              {friend.displayName}
                            </p>
                            <p className="truncate text-xs text-muted-foreground">
                              {friend.username ? `@${friend.username}` : "Bạn bè"}
                            </p>
                          </div>
                          <UserPlus className="size-4 text-muted-foreground" />
                        </button>
                      ))
                    ) : (
                      <p className="rounded-lg bg-muted/60 p-3 text-sm text-muted-foreground">
                        Không có bạn bè phù hợp để mời.
                      </p>
                    )}
                  </div>

                  <Button
                    type="button"
                    className="w-full rounded-lg"
                    disabled={loading || selectedFriends.length === 0}
                    onClick={handleInviteMembers}
                  >
                    {loading ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <UserPlus className="size-4" />
                    )}
                    Gửi lời mời
                  </Button>
                </div>
              )}
            </section>

            {pendingApprovals.length > 0 && (
              <>
                <Separator />

                <section className="space-y-3">
                  <SectionTitle count={pendingApprovals.length}>
                    Chờ admin duyệt
                  </SectionTitle>
                  {pendingApprovals.map((invite) => (
                    <div
                      key={invite._id}
                      className="flex items-center gap-3 rounded-lg border border-border/70 p-3"
                    >
                      <UserAvatar
                        type="chat"
                        name={invite.invitee?.displayName || "Moji"}
                        avatarUrl={invite.invitee?.avatarUrl ?? undefined}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium">
                          {invite.invitee?.displayName || "Người dùng Moji"}
                        </p>
                        <p className="truncate text-xs text-muted-foreground">
                          Đã đồng ý tham gia nhóm
                        </p>
                      </div>
                      <Button
                        type="button"
                        variant="outline"
                        size="icon-sm"
                        title="Duyệt"
                        disabled={Boolean(inviteActionLoadingById[invite._id])}
                        onClick={() => handleApproveInvite(invite._id)}
                      >
                        <Check className="size-4" />
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon-sm"
                        title="Từ chối"
                        disabled={Boolean(inviteActionLoadingById[invite._id])}
                        onClick={() => handleDeclineInvite(invite._id)}
                      >
                        <X className="size-4 text-destructive" />
                      </Button>
                    </div>
                  ))}
                </section>
              </>
            )}

            <Separator />

            <section className="space-y-2">
              <SectionTitle>Khu vực nguy hiểm</SectionTitle>
              <ActionButton danger disabled={loading} onClick={handleLeaveGroup}>
                <LogOut className="size-4" />
                Rời nhóm
              </ActionButton>
              {isAdmin && (
                <ActionButton
                  danger
                  disabled={loading}
                  onClick={handleDeleteGroup}
                >
                  <Trash2 className="size-4" />
                  Xóa nhóm
                </ActionButton>
              )}
            </section>
          </>
        )}
      </div>
    </div>
  );
};

const PanelHeader = ({ onClose }: { onClose?: () => void }) => (
  <div className="flex shrink-0 items-start justify-between gap-3 border-b border-border/70 p-4">
    <div>
      <h2 className="flex items-center gap-2 font-semibold">
        <Info className="size-4" />
        Quản lý cuộc trò chuyện
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        Thông tin và thao tác quản lý chat
      </p>
    </div>
    {onClose && (
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="rounded-full"
        onClick={onClose}
      >
        <X className="size-4" />
        <span className="sr-only">Đóng</span>
      </Button>
    )}
  </div>
);

const ChatDetailsPanel = ({
  chat,
  open,
  onOpenChange,
}: ChatDetailsPanelProps) => {
  const isDesktop = useIsDesktop();

  if (isDesktop) {
    if (!open) {
      return null;
    }

    return (
      <aside
        className={cn(
          "hidden min-h-0 w-[380px] shrink-0 flex-col border-l border-border/70 bg-background lg:flex xl:w-[420px]"
        )}
      >
        <PanelHeader onClose={() => onOpenChange(false)} />
        <ChatDetailsContent chat={chat} onClose={() => onOpenChange(false)} />
      </aside>
    );
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full max-w-full p-0 sm:max-w-md">
        <SheetHeader className="border-b border-border/70 pr-12 text-left">
          <SheetTitle className="flex items-center gap-2">
            <Info className="size-4" />
            Quản lý cuộc trò chuyện
          </SheetTitle>
          <SheetDescription>
            Thông tin và thao tác quản lý chat
          </SheetDescription>
        </SheetHeader>
        <ChatDetailsContent chat={chat} onClose={() => onOpenChange(false)} />
      </SheetContent>
    </Sheet>
  );
};

export default ChatDetailsPanel;
