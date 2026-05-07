import { NavUser } from "@/components/sidebar/nav-user";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { Leaf, Moon, Sun } from "lucide-react";
import { Switch } from "../ui/switch";
import NewGroupChatModal from "../chat/NewGroupChatModal";
import GroupChatList from "../chat/GroupChatList";
import AddFriendModal from "../chat/AddFriendModal";
import DirectMessageList from "../chat/DirectMessageList";
import FriendListModal from "../createNewChat/FriendListModal";
import { useThemeStore } from "@/stores/useThemeStore";
import { useAuthStore } from "@/stores/useAuthStore";
import { useFriendStore } from "@/stores/useFriendStore";
import ConversationSkeleton from "../skeleton/ConversationSkeleton";
import { useChatStore } from "@/stores/useChatStore";
import { Link, useLocation } from "react-router";
import { Map, MessageCircle, MessageCircleMore } from "lucide-react";
import { Dialog, DialogTrigger } from "../ui/dialog";

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const { isDark, toggleTheme } = useThemeStore();
  const { user } = useAuthStore();
  const { getFriends } = useFriendStore();
  const { convoLoading } = useChatStore();
  const location = useLocation();
  const isMap = location.pathname.startsWith("/map");

  return (
    <Sidebar
      variant="inset"
      {...props}
    >
      {/* Header */}
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              asChild
              className="bg-gradient-primary"
            >
              <Link to="/">
                <div className="flex w-full items-center px-2 justify-between">
                  <div className="flex items-center gap-2">
                    <Leaf className="size-5 text-white" />
                    <h1 className="text-xl font-bold text-white">EcoMoji</h1>
                  </div>
                  <div className="flex items-center gap-2">
                    <Sun className="size-4 text-white/80" />
                    <Switch
                      checked={isDark}
                      onCheckedChange={toggleTheme}
                      className="data-[state=checked]:bg-background/80"
                    />
                    <Moon className="size-4 text-white/80" />
                  </div>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      {/* Content */}
      <SidebarContent className="beautiful-scrollbar">
        <SidebarGroup>
          <SidebarGroupContent>
            <div className="grid grid-cols-2 gap-2 px-2">
              <SidebarMenuButton
                asChild
                className={!isMap ? "bg-sidebar-accent font-semibold" : ""}
              >
                <Link to="/">
                  <MessageCircle className="size-4" />
                  Chat
                </Link>
              </SidebarMenuButton>
              <SidebarMenuButton
                asChild
                className={isMap ? "bg-sidebar-accent font-semibold" : ""}
              >
                <Link to="/map">
                  <Map className="size-4" />
                  Map
                </Link>
              </SidebarMenuButton>
            </div>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Group Chat */}
        <SidebarGroup>
          <div className="flex items-center justify-between">
            <SidebarGroupLabel className="uppercase">nhóm chat</SidebarGroupLabel>
            <NewGroupChatModal />
          </div>

          <SidebarGroupContent>
            {convoLoading ? <ConversationSkeleton /> : <GroupChatList />}
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Dirrect Message */}
        <SidebarGroup>
          <div className="flex items-center justify-between">
            <SidebarGroupLabel className="uppercase">bạn bè</SidebarGroupLabel>
            <div className="flex items-center gap-1 pr-1">
              <Dialog>
                <DialogTrigger asChild>
                  <button
                    type="button"
                    title="Danh sách bạn bè"
                    className="relative z-10 flex size-7 cursor-pointer items-center justify-center rounded-full bg-primary/15 text-primary ring-1 ring-primary/25 transition hover:bg-primary hover:text-primary-foreground"
                    onClick={() => void getFriends()}
                  >
                    <MessageCircleMore className="size-4" />
                    <span className="sr-only">Danh sách bạn bè</span>
                  </button>
                </DialogTrigger>
                <FriendListModal />
              </Dialog>
              <AddFriendModal />
            </div>
          </div>

          <SidebarGroupContent>
            {convoLoading ? <ConversationSkeleton /> : <DirectMessageList />}
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      {/* Footer */}
      <SidebarFooter>{user && <NavUser user={user} />}</SidebarFooter>
    </Sidebar>
  );
}
