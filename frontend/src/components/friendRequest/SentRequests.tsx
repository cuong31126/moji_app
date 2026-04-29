import { useState } from "react";
import { useFriendStore } from "@/stores/useFriendStore";
import FriendRequestItem from "./FriendRequestItem";
import { Button } from "../ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { toast } from "sonner";

const SentRequests = () => {
  const { sentList, loading, withdrawRequest } = useFriendStore();
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedRequestId, setSelectedRequestId] = useState<string | null>(null);

  if (!sentList || sentList.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        Bạn chưa gửi lời mời kết bạn nào.
      </p>
    );
  }

  const handleWithdrawClick = (requestId: string) => {
    setSelectedRequestId(requestId);
    setOpenDialog(true);
  };

  const handleConfirmWithdraw = async () => {
    if (!selectedRequestId) return;

    try {
      await withdrawRequest(selectedRequestId);
      toast.success("Đã thu hồi lời mời kết bạn");
      setOpenDialog(false);
      setSelectedRequestId(null);
    } catch (error) {
      console.error(error);
      toast.error("Không thể thu hồi lời mời kết bạn");
    }
  };

  return (
    <>
      <div className="space-y-3 mt-4">
        <>
          {sentList.map((req) => (
            <FriendRequestItem
              key={req._id}
              requestInfo={req}
              type="sent"
              actions={
                <Button
                  size="sm"
                  variant="destructiveOutline"
                  onClick={() => handleWithdrawClick(req._id)}
                  disabled={loading}
                >
                  Thu hồi
                </Button>
              }
            />
          ))}
        </>
      </div>

      <Dialog
        open={openDialog}
        onOpenChange={setOpenDialog}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Thu hồi lời mời kết bạn</DialogTitle>
            <DialogDescription>
              Bạn có chắc chắn muốn thu hồi lời mời kết bạn này không? Hành động này không thể hoàn tác.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setOpenDialog(false)}
            >
              Hủy
            </Button>
            <Button
              variant="destructive"
              onClick={handleConfirmWithdraw}
              disabled={loading}
            >
              Thu hồi
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default SentRequests;