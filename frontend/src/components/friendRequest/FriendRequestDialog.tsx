import { useEffect, useState, type Dispatch, type SetStateAction } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useFriendStore } from "@/stores/useFriendStore";
import { useChatStore } from "@/stores/useChatStore";
import SentRequests from "./SentRequests";
import ReceivedRequests from "./ReceiveRequests";
import GroupInvites from "../groupInvite/GroupInvites";

interface FriendRequestDialogProps {
  open: boolean;
  setOpen: Dispatch<SetStateAction<boolean>>;
}

const FriendRequestDialog = ({ open, setOpen }: FriendRequestDialogProps) => {
  const [tab, setTab] = useState("received");
  const { getAllFriendRequests } = useFriendStore();
  const { fetchGroupInvites } = useChatStore();

  useEffect(() => {
    if (!open) return;

    const loadRequest = async () => {
      try {
        await getAllFriendRequests();
        await fetchGroupInvites();
      } catch (error) {
        console.error("Lỗi xảy ra khi load requests", error);
      }
    };

    loadRequest();
  }, [fetchGroupInvites, open, getAllFriendRequests]);

  return (
    <Dialog
      open={open}
      onOpenChange={setOpen}
    >
      <DialogContent className="max-h-[calc(100vh-2rem)] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Thông báo</DialogTitle>
        </DialogHeader>
        <Tabs
          value={tab}
          onValueChange={setTab}
          className="w-full"
        >
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="received">Đã nhận</TabsTrigger>
            <TabsTrigger value="sent">Đã gửi</TabsTrigger>
            <TabsTrigger value="group">Nhóm</TabsTrigger>
          </TabsList>

          <TabsContent value="received">
            <ReceivedRequests />
          </TabsContent>

          <TabsContent value="sent">
            <SentRequests />
          </TabsContent>

          <TabsContent value="group">
            <GroupInvites />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
};

export default FriendRequestDialog;
