import type { UseFormRegister } from "react-hook-form";
import type { AddFriendFormValues } from "@/types/form";
import type { RelationshipStatus } from "@/types/user";
import { Label } from "../ui/label";
import { Textarea } from "../ui/textarea";
import { DialogFooter } from "../ui/dialog";
import { Button } from "../ui/button";
import { Check, Clock, MessageCircle, UserPlus } from "lucide-react";

interface SendRequestProps {
  register: UseFormRegister<AddFriendFormValues>;
  loading: boolean;
  searchedUsername: string;
  relationshipStatus?: RelationshipStatus;
  onSubmit?: (e: React.FormEvent<HTMLFormElement>) => void;
  onBack: () => void;
  onMessage: () => void;
}

const SendFriendRequestForm = ({
  register,
  loading,
  searchedUsername,
  relationshipStatus = "none",
  onSubmit,
  onBack,
  onMessage,
}: SendRequestProps) => {
  const friendActionDisabled =
    loading ||
    relationshipStatus === "friends" ||
    relationshipStatus === "request_sent";
  const friendActionLabel =
    relationshipStatus === "friends"
      ? "Đã là bạn"
      : relationshipStatus === "request_sent"
      ? "Đã gửi"
      : relationshipStatus === "request_received"
      ? "Chấp nhận"
      : "Kết Bạn";
  const friendActionIcon =
    relationshipStatus === "friends" ? (
      <Check className="mr-2 size-4" />
    ) : relationshipStatus === "request_sent" ? (
      <Clock className="mr-2 size-4" />
    ) : (
      <UserPlus className="mr-2 size-4" />
    );

  return (
    <form onSubmit={onSubmit}>
      <div className="space-y-4">
        <span className="success-message">
          Tìm thấy <span className="font-semibold">@{searchedUsername}</span> rồi nè
        </span>

        <div className="space-y-4">
          <Label
            htmlFor="message"
            className="text-sm font-semibold"
          >
            Giới thiệu
          </Label>
          <Textarea
            id="message"
            rows={3}
            placeholder="Chào bạn, có thể kết bạn được không?"
            className="glass border-border/50 focus:border-primary/50 transition-smooth resize-none"
            {...register("message")}
          />
        </div>

        <DialogFooter className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          <Button
            type="button"
            variant="outline"
            className="glass hover:text-destructive"
            onClick={onBack}
          >
            Quay lại
          </Button>

          <Button
            type="button"
            variant="outline"
            className="glass"
            onClick={onMessage}
          >
            <MessageCircle className="mr-2 size-4" />
            Nhắn tin
          </Button>

          <Button
            type="submit"
            disabled={friendActionDisabled}
            className="bg-gradient-chat text-white hover:opactity-90 transition-smooth"
          >
            {loading ? (
              <span>Đang gửi...</span>
            ) : (
              <>
                {friendActionIcon} {friendActionLabel}
              </>
            )}
          </Button>
        </DialogFooter>
      </div>
    </form>
  );
};

export default SendFriendRequestForm;
