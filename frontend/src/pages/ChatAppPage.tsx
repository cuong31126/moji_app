import { lazy, Suspense } from "react";
import ChatWindowLayout from "@/components/chat/ChatWindowLayout";
import { AppSidebar } from "@/components/sidebar/app-sidebar";
import { SidebarProvider } from "@/components/ui/sidebar";

const EcoMapPage = lazy(() => import("@/components/map/EcoMapPage"));

const ChatAppPage = ({ view = "chat" }: { view?: "chat" | "map" }) => {
  return (
    <SidebarProvider>
      <AppSidebar />

      <div className="flex h-screen w-full p-2">
        {view === "map" ? (
          <Suspense
            fallback={
              <div className="flex flex-1 items-center justify-center rounded-2xl bg-primary-foreground text-muted-foreground">
                Đang tải bản đồ...
              </div>
            }
          >
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
