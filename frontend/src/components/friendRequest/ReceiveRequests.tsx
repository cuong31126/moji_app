import { useNavigate } from "react-router";
import { toast } from "sonner";

import { openDirectConversation } from "@/lib/openDirectConversation";
import { useFriendStore } from "@/stores/useFriendStore";
import { Button } from "../ui/button";
import FriendRequestItem from "./FriendRequestItem";

const getErrorMessage = (error: unknown) =>
  error instanceof Error ? error.message : "Lỗi xảy ra. Hay thử lại";

const ReceivedRequests = () => {
  const { acceptRequest, declineRequest, loading, receivedList } = useFriendStore();
  const navigate = useNavigate();

  const openDirectChat = async (friendId: string) => {
    await openDirectConversation(friendId);
    navigate("/");
  };

  const handleAccept = async (requestId: string) => {
    try {
      const friend = await acceptRequest(requestId);
      toast.success("Đã đồng ý kết bạn thành công");

      if (friend?._id) {
        await openDirectChat(friend._id);
      }
    } catch (error) {
      console.error(error);
      toast.error(getErrorMessage(error));
    }
  };

  const handleDecline = async (requestId: string) => {
    try {
      await declineRequest(requestId);
      toast.info("Đã từ chối kết bạn");
    } catch (error) {
      console.error(error);
      toast.error(getErrorMessage(error));
    }
  };

  if (!receivedList || receivedList.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        Bạn chưa có lời mời kết bạn nào.
      </p>
    );
  }

  return (
    <div className="mt-4 space-y-3">
      {receivedList.map((req) => (
        <FriendRequestItem
          key={req._id}
          requestInfo={req}
          actions={
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="primary"
                onClick={() => handleAccept(req._id)}
                disabled={loading}
              >
                Chấp nhận
              </Button>
              <Button
                size="sm"
                variant="destructiveOutline"
                onClick={() => handleDecline(req._id)}
                disabled={loading}
              >
                Từ chối
              </Button>
            </div>
          }
          type="received"
        />
      ))}
    </div>
  );
};

export default ReceivedRequests;
