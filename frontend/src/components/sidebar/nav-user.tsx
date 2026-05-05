import { type FormEvent, useEffect, useState } from "react";
import { Bell, ChevronsUpDown, KeyRound, UserIcon } from "lucide-react";
import { toast } from "sonner";

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { useFriendStore } from "@/stores/useFriendStore";
import type { User } from "@/types/user";
import Logout from "../auth/Logout";
import FriendRequestDialog from "../friendRequest/FriendRequestDialog";
import ProfileDialog from "../profile/ProfileDialog";

const ChangePasswordDialog = ({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) => {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const reset = () => {
    setOldPassword("");
    setNewPassword("");
    setConfirmPassword("");
  };

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
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        onOpenChange(nextOpen);
        if (!nextOpen) reset();
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Đổi mật khẩu</DialogTitle>
        </DialogHeader>
        <form className="space-y-4" onSubmit={handleSubmit}>
          <div className="space-y-2">
            <Label htmlFor="old-password">Mật khẩu cũ</Label>
            <Input
              id="old-password"
              type="password"
              value={oldPassword}
              onChange={(event) => setOldPassword(event.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="new-password">Mật khẩu mới</Label>
            <Input
              id="new-password"
              type="password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-password">Xác nhận mật khẩu</Label>
            <Input
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
            />
          </div>
          <Button type="submit" className="w-full">
            Lưu
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export function NavUser({ user }: { user: User }) {
  const { isMobile } = useSidebar();
  const [friendRequestOpen, setfriendRequestOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);
  const { receivedList, getAllFriendRequests } = useFriendStore();
  const requestCount = receivedList.length;

  useEffect(() => {
    getAllFriendRequests().catch((error) => {
      console.error("Error while loading friend request badge", error);
    });
  }, [getAllFriendRequests]);

  return (
    <>
      <SidebarMenu>
        <SidebarMenuItem>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <SidebarMenuButton
                size="lg"
                className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
              >
                <div className="relative shrink-0">
                  <Avatar className="h-8 w-8 rounded-lg">
                    <AvatarImage
                      src={user.avatarUrl}
                      alt={user.displayName}
                    />
                    <AvatarFallback className="rounded-lg">
                      {user.displayName.charAt(0)}
                    </AvatarFallback>
                  </Avatar>
                  {requestCount > 0 && (
                    <span className="absolute -right-1.5 -top-1.5 flex h-5 min-w-5 items-center justify-center rounded-full border-2 border-sidebar bg-red-500 px-1 text-[10px] font-bold leading-none text-white shadow-sm">
                      {requestCount > 99 ? "99+" : requestCount}
                    </span>
                  )}
                </div>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-medium">{user.displayName}</span>
                  <span className="truncate text-xs">{user.username}</span>
                </div>
                <ChevronsUpDown className="ml-auto size-4" />
              </SidebarMenuButton>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              className="z-[9999] w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg"
              side={isMobile ? "bottom" : "right"}
              align="end"
              sideOffset={4}
            >
              <DropdownMenuLabel className="p-0 font-normal">
                <div className="flex items-center gap-2 px-1 py-1.5 text-left text-sm">
                  <Avatar className="h-8 w-8 rounded-lg">
                    <AvatarImage
                      src={user.avatarUrl}
                      alt={user.username}
                    />
                    <AvatarFallback className="rounded-lg">
                      {user.displayName.charAt(0)}
                    </AvatarFallback>
                  </Avatar>
                  <div className="grid flex-1 text-left text-sm leading-tight">
                    <span className="truncate font-medium">{user.displayName}</span>
                    <span className="truncate text-xs">{user.username}</span>
                  </div>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                <DropdownMenuItem onClick={() => setProfileOpen(true)}>
                  <UserIcon className="text-muted-foreground dark:group-focus:!text-accent-foreground" />
                  Thông tin
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setChangePasswordOpen(true)}>
                  <KeyRound className="text-muted-foreground dark:group-focus:!text-accent-foreground" />
                  Đổi mật khẩu
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setfriendRequestOpen(true)}>
                  <Bell className="text-muted-foreground dark:group-focus:!text-accent-foreground" />
                  Lời mời kết bạn
                  {requestCount > 0 && (
                    <span className="ml-auto rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-bold text-white">
                      {requestCount > 99 ? "99+" : requestCount}
                    </span>
                  )}
                </DropdownMenuItem>
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="cursor-pointer"
                variant="destructive"
              >
                <Logout />
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </SidebarMenuItem>
      </SidebarMenu>

      <FriendRequestDialog
        open={friendRequestOpen}
        setOpen={setfriendRequestOpen}
      />

      <ProfileDialog
        open={profileOpen}
        setOpen={setProfileOpen}
      />

      <ChangePasswordDialog
        open={changePasswordOpen}
        onOpenChange={setChangePasswordOpen}
      />
    </>
  );
}
