import { useFriendStore } from "@/stores/useFriendStore";
import {
  DialogClose,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog";
import { MessageCircleMore, Users } from "lucide-react";
import { Card } from "../ui/card";
import UserAvatar from "../chat/UserAvatar";
import { openDirectConversation } from "@/lib/openDirectConversation";
import { useNavigate } from "react-router";

const FriendListModal = () => {
  const { friends } = useFriendStore();
  const navigate = useNavigate();

  const handleAddConversation = async (friendId: string) => {
    await openDirectConversation(friendId);
    navigate("/");
  };

  return (
    <DialogContent className="glass max-h-[calc(100vh-2rem)] w-[calc(100vw-2rem)] max-w-md overflow-hidden p-4 sm:p-6">
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2 text-xl capitalize">
          <MessageCircleMore className="size-5" />
          bắt đầu hội thoại mới
        </DialogTitle>
      </DialogHeader>

      {/* friends list */}
      <div className="space-y-4">
        <h1 className="text-sm font-semibold text-muted-foreground mb-3 uppercase tracking-wide">
          danh sách bạn bè
        </h1>

        <div className="beautiful-scrollbar max-h-60 space-y-2 overflow-y-auto overflow-x-hidden pr-1">
          {friends.map((friend) => (
            <DialogClose asChild key={friend._id}>
              <Card
                onClick={() => void handleAddConversation(friend._id)}
                className="max-w-full cursor-pointer overflow-hidden p-3 transition-smooth hover:shadow-soft glass hover:bg-muted/30 group/friendCard"
              >
                <div className="flex min-w-0 items-center gap-3">
                {/* avatar */}
                <div className="relative">
                  <UserAvatar
                    type="sidebar"
                    name={friend.displayName}
                    avatarUrl={friend.avatarUrl}
                  />
                </div>

                {/* info */}
                <div className="flex-1 min-w-0 flex flex-col">
                  <h2 className="font-semibold text-sm truncate">
                    {friend.displayName}
                  </h2>
                  <span className="truncate text-sm text-muted-foreground">
                    @{friend.username}
                  </span>
                </div>
              </div>
              </Card>
            </DialogClose>
          ))}

          {friends.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              <Users className="size-12 mx-auto mb-3 opacity-50" />
              Chưa có bạn bè. Thêm bạn vô để tám!
            </div>
          )}
        </div>
      </div>
    </DialogContent>
  );
};

export default FriendListModal;
