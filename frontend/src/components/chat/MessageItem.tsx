import { useState } from "react";
import { cn, formatMessageTime } from "@/lib/utils";
import type { Conversation, Message, Participant } from "@/types/chat";
import UserAvatar from "./UserAvatar";
import { Card } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "../ui/dialog";
import { MapPin, RotateCcw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useNavigate } from "react-router";
import type { TrashReportStatus } from "@/types/report";

interface MessageItemProps {
  message: Message;
  index: number;
  messages: Message[];
  selectedConvo: Conversation;
  lastMessageStatus: "delivered" | "seen";
  onRevoke: (messageId: string) => Promise<void>;
}

const MessageItem = ({
  message,
  index,
  messages,
  selectedConvo,
  lastMessageStatus,
  onRevoke,
}: MessageItemProps) => {
  const navigate = useNavigate();
  const [openDialog, setOpenDialog] = useState(false);
  const [isRevoking, setIsRevoking] = useState(false);

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
  const canRevoke = message.isOwn && !message.isRevoked;
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
              <UserAvatar
                type="chat"
                name={participant?.displayName ?? "Moji"}
                avatarUrl={participant?.avatarUrl ?? undefined}
              />
            )}
          </div>
        )}

        <div
          className={cn(
            "flex max-w-xs flex-col space-y-1 lg:max-w-md",
            message.isOwn ? "items-end" : "items-start"
          )}
        >
          <div className="flex items-center gap-1">
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
          </div>

          {message.isOwn && message._id === selectedConvo.lastMessage?._id && (
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
    </>
  );
};

export default MessageItem;
