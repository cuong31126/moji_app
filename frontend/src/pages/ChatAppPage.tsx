import { lazy, Suspense, useEffect, useRef } from "react";
import { useSearchParams } from "react-router";
import { toast } from "sonner";
import ChatWindowLayout from "@/components/chat/ChatWindowLayout";
import IncomingInviteDialog from "@/components/notifications/IncomingInviteDialog";
import { AppSidebar } from "@/components/sidebar/app-sidebar";
import MapSkeleton from "@/components/skeleton/MapSkeleton";
import { SidebarProvider } from "@/components/ui/sidebar";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";

const EcoMapPage = lazy(() => import("@/components/map/EcoMapPage"));

const withoutConversationParam = (params: URLSearchParams) => {
  const nextParams = new URLSearchParams(params);
  nextParams.delete("conversationId");
  return nextParams;
};

const ChatAppPage = ({ view = "chat" }: { view?: "chat" | "map" }) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const attemptedFetchRef = useRef(false);
  const {
    conversations,
    convoLoading,
    fetchConversations,
    fetchGroupInvites,
    fetchMessages,
    messages,
    setActiveConversation,
  } = useChatStore();
  const { getAllFriendRequests } = useFriendStore();
  const requestedConversationId = searchParams.get("conversationId");

  useEffect(() => {
    void fetchConversations();
    void fetchGroupInvites();
    void getAllFriendRequests();
  }, [fetchConversations, fetchGroupInvites, getAllFriendRequests]);

  useEffect(() => {
    attemptedFetchRef.current = false;
  }, [requestedConversationId]);

  useEffect(() => {
    if (!requestedConversationId || convoLoading) {
      return;
    }

    const targetConversation = conversations.find(
      (conversation) => conversation._id === requestedConversationId
    );

    if (!targetConversation && !attemptedFetchRef.current) {
      attemptedFetchRef.current = true;
      void fetchConversations();
      return;
    }

    if (!targetConversation) {
      toast.error("Bạn chưa có quyền truy cập nhóm này hoặc link không hợp lệ.");
      setSearchParams(withoutConversationParam(searchParams), { replace: true });
      return;
    }

    setActiveConversation(targetConversation._id);

    if (!messages[targetConversation._id]) {
      void fetchMessages(targetConversation._id);
    }

    setSearchParams(withoutConversationParam(searchParams), { replace: true });
  }, [
    conversations,
    convoLoading,
    fetchConversations,
    fetchMessages,
    messages,
    requestedConversationId,
    searchParams,
    setActiveConversation,
    setSearchParams,
  ]);

  return (
    <SidebarProvider>
      <AppSidebar />
      <IncomingInviteDialog />

      <div className="flex h-screen w-full p-2">
        {view === "map" ? (
          <Suspense fallback={<MapSkeleton />}>
            <EcoMapPage />
          </Suspense>
        ) : (
          <ChatWindowLayout />
        )}
      </div>
    </SidebarProvider>
  );
};

export default ChatAppPage;
