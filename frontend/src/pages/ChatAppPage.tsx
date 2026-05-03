import { lazy, Suspense } from "react";
import ChatWindowLayout from "@/components/chat/ChatWindowLayout";
import { AppSidebar } from "@/components/sidebar/app-sidebar";
import MapSkeleton from "@/components/skeleton/MapSkeleton";
import { SidebarProvider } from "@/components/ui/sidebar";

const EcoMapPage = lazy(() => import("@/components/map/EcoMapPage"));

const ChatAppPage = ({ view = "chat" }: { view?: "chat" | "map" }) => {
  return (
    <SidebarProvider>
      <AppSidebar />

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
