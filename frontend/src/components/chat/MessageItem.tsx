import { useMemo, useState } from "react";
import { cn, formatMessageTime } from "@/lib/utils";
import type {
  Conversation,
  Message,
  MessageReaction,
  MessageReplyPreview,
  Participant,
} from "@/types/chat";
import UserAvatar from "./UserAvatar";
import { Card } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "../ui/dialog";
import { MapPin, RefreshCcw, Reply, RotateCcw, SmilePlus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useNavigate } from "react-router";
import type { TrashReportStatus } from "@/types/report";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useSocketStore } from "@/stores/useSocketStore";
import { notifyChatEvent } from "@/lib/chatAlerts";
import UserProfileDialog from "../profile/UserProfileDialog";

const REACTION_OPTIONS = ["👍", "❤️", "😂", "😮", "😢"];

const getReactionUserId = (reaction: MessageReaction) =>
  typeof reaction.user === "string" ? reaction.user : reaction.user._id;

const getReplyPreviewText = (message?: MessageReplyPreview | Message | null) => {
  if (!message) return "Tin nhắn";
  if (message.content) return message.content;
  if (message.imgUrl) return "Đã gửi một ảnh";
  return "Tin nhắn";
};

interface MessageItemProps {
  message: Message;
  index: number;
  messages: Message[];
  selectedConvo: Conversation;
  lastMessageStatus: "delivered" | "seen";
  onRevoke: (messageId: string) => Promise<void>;
  onReply: (message: Message) => void;
}

const MessageItem = ({
  message,
  index,
  messages,
  selectedConvo,
  lastMessageStatus,
  onRevoke,
  onReply,
}: MessageItemProps) => {
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const {
    confirmOptimisticMessage,
    reactToMessage,
    setMessageStatus,
  } = useChatStore();
  const { sendChatMessage } = useSocketStore();
  const [openDialog, setOpenDialog] = useState(false);
  const [isRevoking, setIsRevoking] = useState(false);
  const [reactionPickerOpen, setReactionPickerOpen] = useState(false);
  const [reacting, setReacting] = useState(false);
  const [profileUserId, setProfileUserId] = useState<string | null>(null);

  const prev = index + 1 < messages.length ? messages[index + 1] : undefined;

  const isShowTime =
    index === 0 ||
    new Date(message.createdAt).getTime() -
      new Date(prev?.createdAt || 0).getTime() >
      300000;

  const isGroupBreak = isShowTime || message.senderId !== prev?.senderId;

  const participant = selectedConvo.participants.find(
    (p: Participant) => p._id.toString() === message.senderId.toString()
  );
  const isPendingMessage =
    message.status === "sending" || message.status === "error";
  const canRevoke = message.isOwn && !message.isRevoked && !isPendingMessage;
  const canReact = !message.isRevoked && !isPendingMessage;
  const canReply = !message.isRevoked && !isPendingMessage;
  const replyTarget = useMemo(() => {
    if (message.replyTo && typeof message.replyTo === "object") {
      return message.replyTo;
    }

    const replyId =
      message.replyToMessageId ||
      (typeof message.replyTo === "string" ? message.replyTo : null);

    if (!replyId) {
      return null;
    }

    return (
      messages.find(
        (item) => item._id === replyId || item.clientId === replyId
      ) ?? null
    );
  }, [message.replyTo, message.replyToMessageId, messages]);
  const replySender =
    replyTarget && "sender" in replyTarget ? replyTarget.sender : undefined;
  const replySenderId = replyTarget?.senderId || replySender?._id;
  const replySenderName =
    replySender?.displayName ||
    selectedConvo.participants.find((item) => item._id === replySenderId)
      ?.displayName ||
    (replySenderId === user?._id ? "Bạn" : "Tin nhắn");
  const reactions = useMemo(() => message.reactions ?? [], [message.reactions]);
  const myReaction = user
    ? reactions.find((reaction) => getReactionUserId(reaction) === user._id)
    : undefined;
  const reactionSummary = useMemo(() => {
    const counts = new Map<string, number>();

    reactions.forEach((reaction) => {
      counts.set(reaction.emoji, (counts.get(reaction.emoji) ?? 0) + 1);
    });

    return Array.from(counts.entries()).map(([emoji, count]) => ({
      emoji,
      count,
    }));
  }, [reactions]);
  const totalReactionCount = reactionSummary.reduce(
    (total, reaction) => total + reaction.count,
    0
  );
  const trashReport =
    message.trashReport && typeof message.trashReport === "object"
      ? message.trashReport
      : null;
  const trashReportId =
    trashReport?._id ||
    (typeof message.trashReport === "string" ? message.trashReport : null);
  const isTrashReportMessage =
    message.messageType === "trash_report" && Boolean(trashReportId);
  const trashStatus = trashReport?.status;
  const statusMeta: Record<TrashReportStatus, { label: string; className: string }> =
    {
      ACTIVE: { label: "Mới báo", className: "bg-red-50 text-red-700" },
      VERIFIED: {
        label: "Đã xác nhận",
        className: "bg-orange-50 text-orange-700",
      },
      CLEANUP_PENDING: {
        label: "Đang dọn",
        className: "bg-sky-50 text-sky-700",
      },
      CLEANED: { label: "Đã sạch", className: "bg-emerald-50 text-emerald-700" },
    };

  if (message.messageType === "system" && !message.isRevoked) {
    return (
      <div className="my-3 flex justify-center">
        <div className="max-w-md rounded-full bg-muted px-3 py-1.5 text-center text-xs text-muted-foreground">
          {message.content}
        </div>
      </div>
    );
  }

  const handleRevokeClick = () => {
    setOpenDialog(true);
  };

  const handleConfirmRevoke = async () => {
    try {
      setIsRevoking(true);
      await onRevoke(message._id);
      toast.success("Đã thu hồi tin nhắn");
      setOpenDialog(false);
    } catch (error) {
      console.error(error);
      toast.error("Không thu hồi được tin nhắn");
    } finally {
      setIsRevoking(false);
    }
  };

  const handleReactionSelect = async (emoji: string) => {
    try {
      setReacting(true);
      await reactToMessage(message._id, emoji);
      setReactionPickerOpen(false);
    } catch (error) {
      console.error(error);
      toast.error("Khong them duoc reaction");
    } finally {
      setReacting(false);
    }
  };

  const handleRetrySend = async () => {
    if (!message.clientId) {
      return;
    }

    if (message.imgUrl?.startsWith("blob:")) {
      toast.error("Ảnh gửi lỗi cần chọn lại.");
      return;
    }

    try {
      setMessageStatus(message.conversationId, message.clientId, "sending");
      const sentMessage = await sendChatMessage({
        conversationId: message.conversationId,
        content: message.content ?? "",
        imgUrl: message.imgUrl ?? undefined,
        replyToMessageId: message.replyToMessageId ?? undefined,
        clientId: message.clientId,
      });
      confirmOptimisticMessage(message.clientId, sentMessage);
      notifyChatEvent({
        title: "Tin nhắn đã gửi",
        body: sentMessage.content || (sentMessage.imgUrl ? "Đã gửi một ảnh" : ""),
        conversationId: message.conversationId,
      });
    } catch (error) {
      console.error(error);
      setMessageStatus(message.conversationId, message.clientId, "error");
      toast.error("Không gửi lại được tin nhắn");
    }
  };

  return (
    <>
      {isShowTime && (
        <span className="flex justify-center px-1 text-xs text-muted-foreground">
          {formatMessageTime(new Date(message.createdAt))}
        </span>
      )}

      <div
        className={cn(
          "group mt-1 flex gap-2 message-bounce",
          message.isOwn ? "justify-end" : "justify-start"
        )}
      >
        {!message.isOwn && (
          <div className="w-8">
            {isGroupBreak && (
              <button
                type="button"
                className="block rounded-full outline-none ring-ring transition hover:scale-105 focus-visible:ring-2"
                aria-label={`Xem thông tin ${participant?.displayName ?? "Moji"}`}
                onClick={() => participant?._id && setProfileUserId(participant._id)}
              >
                <UserAvatar
                  type="chat"
                  name={participant?.displayName ?? "Moji"}
                  avatarUrl={participant?.avatarUrl ?? undefined}
                />
              </button>
            )}
          </div>
        )}

        <div
          className={cn(
            "flex max-w-xs flex-col space-y-1 lg:max-w-md",
            message.isOwn ? "items-end" : "items-start"
          )}
        >
          <div
            className={cn(
              "flex items-center gap-1",
              !message.isOwn && "flex-row-reverse"
            )}
          >
            {canReply && (
              <Button
                type="button"
                variant="ghost"
                size="icon"
                title="Trả lời"
                onClick={() => onReply(message)}
                className="size-7 opacity-100 transition-opacity md:opacity-0 md:group-hover:opacity-100"
              >
                <Reply className="size-3.5" />
              </Button>
            )}

            {canRevoke && (
              <Button
                type="button"
                variant="ghost"
                size="icon"
                title="Thu hồi"
                onClick={handleRevokeClick}
                className="size-7 opacity-100 transition-opacity md:opacity-0 md:group-hover:opacity-100"
              >
                <RotateCcw className="size-3.5" />
              </Button>
            )}

            <div
              className={cn(
                "relative",
                (canReact || reactionSummary.length > 0) && "mb-5"
              )}
            >
              {canReact && (
                <Popover
                  open={reactionPickerOpen}
                  onOpenChange={setReactionPickerOpen}
                >
                  <PopoverTrigger asChild>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      title="Reaction"
                      className={cn(
                        "absolute -bottom-3 z-20 size-7 rounded-full border border-border/60 bg-background shadow-sm opacity-100 transition-opacity hover:bg-accent md:opacity-0 md:group-hover:opacity-100",
                        message.isOwn
                          ? reactionSummary.length > 0
                            ? "-left-10"
                            : "-left-3"
                          : reactionSummary.length > 0
                          ? "-right-10"
                          : "-right-3",
                        reactionPickerOpen && "opacity-100"
                      )}
                    >
                      <SmilePlus className="size-3.5" />
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent
                    side="top"
                    align={message.isOwn ? "start" : "end"}
                    className="flex w-auto gap-1 rounded-full border-border/70 bg-background p-1 shadow-lg"
                  >
                    {REACTION_OPTIONS.map((emoji) => (
                      <Button
                        key={emoji}
                        type="button"
                        variant={myReaction?.emoji === emoji ? "secondary" : "ghost"}
                        size="icon"
                        className="size-8 rounded-full text-base"
                        onClick={() => handleReactionSelect(emoji)}
                        disabled={reacting}
                      >
                        {emoji}
                      </Button>
                    ))}
                  </PopoverContent>
                </Popover>
              )}

            <Card
              className={cn(
                message.imgUrl && !message.isRevoked ? "overflow-hidden p-1" : "p-3",
                isTrashReportMessage &&
                  !message.isRevoked &&
                  "w-72 border border-emerald-200 bg-background text-foreground shadow-soft",
                !isTrashReportMessage &&
                  (message.isOwn
                    ? "chat-bubble-sent border-0"
                    : "chat-bubble-received"),
                message.isRevoked && "bg-muted text-muted-foreground italic"
              )}
            >
              {!message.isRevoked && replyTarget && (
                <div
                  className={cn(
                    "mb-2 rounded-md border-l-2 bg-background/45 px-2 py-1.5 text-left",
                    message.isOwn ? "border-white/70" : "border-primary/60"
                  )}
                >
                  <p className="text-[11px] font-medium opacity-80">
                    Trả lời {replySenderName}
                  </p>
                  <p className="line-clamp-2 text-xs opacity-75">
                    {getReplyPreviewText(replyTarget)}
                  </p>
                </div>
              )}

              {message.isRevoked ? (
                <p className="text-sm leading-relaxed">Tin nhắn đã được thu hồi</p>
              ) : isTrashReportMessage ? (
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <div className="flex size-10 shrink-0 items-center justify-center rounded-full bg-red-100 text-red-600">
                      <Trash2 className="size-5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="line-clamp-1 font-semibold">
                        {trashReport?.title || "Điểm rác được chia sẻ"}
                      </p>
                      <p className="line-clamp-2 text-xs text-muted-foreground">
                        {trashReport?.description ||
                          "Mở bản đồ để xem vị trí và chi tiết."}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between gap-2">
                    {trashStatus && (
                      <span
                        className={cn(
                          "rounded-full px-2 py-1 text-xs font-medium",
                          statusMeta[trashStatus].className
                        )}
                      >
                        {statusMeta[trashStatus].label}
                      </span>
                    )}
                    <Button
                      type="button"
                      size="sm"
                      className="ml-auto h-8 rounded-full"
                      onClick={() => navigate(`/map?reportId=${trashReportId}`)}
                    >
                      <MapPin className="size-3.5" />
                      Xem trên bản đồ
                    </Button>
                  </div>
                </div>
              ) : (
                <>
                  {message.imgUrl && (
                    <a
                      href={message.imgUrl}
                      target="_blank"
                      rel="noreferrer"
                    >
                      <img
                        src={message.imgUrl}
                        alt="Ảnh đã gửi"
                        className="max-h-80 max-w-full rounded-md object-contain"
                      />
                    </a>
                  )}

                  {message.content && (
                    <p
                      className={cn(
                        "break-words text-sm leading-relaxed",
                        message.imgUrl && "px-2 py-1"
                      )}
                    >
                      {message.content}
                    </p>
                  )}
                </>
              )}
            </Card>

              {reactionSummary.length > 0 && (
                <div
                  className={cn(
                    "absolute -bottom-3 z-10 inline-flex h-6 items-center gap-0.5 rounded-full border border-border/60 bg-background px-1.5 text-xs shadow-sm",
                    message.isOwn ? "left-2" : "right-2"
                  )}
                >
                  {reactionSummary.slice(0, 3).map((reaction) => (
                    <span
                      key={reaction.emoji}
                      className="leading-none"
                    >
                      {reaction.emoji}
                    </span>
                  ))}
                  {totalReactionCount > 1 && (
                    <span className="pl-0.5 text-[11px] font-medium text-muted-foreground">
                      {totalReactionCount}
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>

          {message.isOwn && message.status && message.status !== "sent" && (
            <div className="flex items-center gap-1">
              <Badge
                variant="outline"
                className={cn(
                  "h-5 border-0 px-1.5 py-0.5 text-xs",
                  message.status === "sending"
                    ? "bg-muted text-muted-foreground"
                    : "bg-destructive/10 text-destructive"
                )}
              >
                {message.status === "sending" ? "Đang gửi" : "Lỗi"}
              </Badge>
              {message.status === "error" && (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-6"
                  title="Gửi lại"
                  onClick={handleRetrySend}
                >
                  <RefreshCcw className="size-3.5" />
                </Button>
              )}
            </div>
          )}

          {message.isOwn &&
            message.status !== "sending" &&
            message.status !== "error" &&
            message._id === selectedConvo.lastMessage?._id && (
            <Badge
              variant="outline"
              className={cn(
                "h-4 border-0 px-1.5 py-0.5 text-xs",
                lastMessageStatus === "seen"
                  ? "bg-primary/20 text-primary"
                  : "bg-muted text-muted-foreground"
              )}
            >
              {lastMessageStatus}
            </Badge>
          )}
        </div>
      </div>

      <Dialog
        open={openDialog}
        onOpenChange={setOpenDialog}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Thu hồi tin nhắn</DialogTitle>
            <DialogDescription>
              Bạn có chắc chắn muốn thu hồi tin nhắn này không? Hành động này không thể hoàn tác.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setOpenDialog(false)}
              disabled={isRevoking}
            >
              Hủy
            </Button>
            <Button
              variant="destructive"
              onClick={handleConfirmRevoke}
              disabled={isRevoking}
            >
              {isRevoking ? "Đang xử lý..." : "Thu hồi"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <UserProfileDialog
        open={Boolean(profileUserId)}
        onOpenChange={(open) => !open && setProfileUserId(null)}
        userId={profileUserId}
      />
    </>
  );
};

export default MessageItem;
