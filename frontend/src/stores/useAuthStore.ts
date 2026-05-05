import { create } from "zustand";
import { toast } from "sonner";
import { authService } from "@/services/authService";
import type { AuthState } from "@/types/store";
import { persist } from "zustand/middleware";
import { getChatState, registerAuthStore } from "./storeBridge";

const resetChatState = () => {
  getChatState()?.reset();
};

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      user: null,
      loading: false,

      setAccessToken: (accessToken) => {
        set({ accessToken });
      },
      setUser: (user) => {
        set({ user });
      },
      clearState: () => {
        set({ accessToken: null, user: null, loading: false });
        resetChatState();
        localStorage.clear();
        sessionStorage.clear();
      },
      signUp: async (username, password, email, firstName, lastName) => {
        try {
          set({ loading: true });
          await authService.signUp(username, password, email, firstName, lastName);
          toast.success("Đăng ký thành công! Bạn có thể đăng nhập ngay.");
        } catch (error) {
          console.error(error);
          toast.error("Đăng ký không thành công");
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      signIn: async (username, password) => {
        try {
          get().clearState();
          set({ loading: true });

          const { accessToken, user } = await authService.signIn(username, password);
          get().setAccessToken(accessToken);
          get().setUser(user);

          void getChatState()?.fetchConversations();
          toast.success("Chào mừng bạn quay lại với Moji");
        } catch (error) {
          console.error(error);
          toast.error("Đăng nhập không thành công!");
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      signOut: async () => {
        try {
          await authService.signOut();
          get().clearState();
          toast.success("Logout thành công!");
        } catch (error) {
          console.error(error);
          get().clearState();
          toast.error("Lỗi xảy ra khi logout. Hãy thử lại!");
        }
      },
      fetchMe: async () => {
        try {
          set({ loading: true });
          const user = await authService.fetchMe();
          set({ user });
        } catch (error) {
          console.error(error);
          set({ user: null, accessToken: null });
          toast.error("Lỗi xảy ra khi lấy dữ liệu người dùng. Hãy thử lại!");
          throw error;
        } finally {
          set({ loading: false });
        }
      },
      refresh: async (options) => {
        try {
          set({ loading: true });
          const { accessToken, user } = await authService.refresh();

          get().setAccessToken(accessToken);
          get().setUser(user);
        } catch (error) {
          console.warn("[auth] Refresh failed", error);

          if (!options?.silent) {
            toast.error("Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại!");
          }

          get().clearState();
          throw error;
        } finally {
          set({ loading: false });
        }
      },
    }),
    {
      name: "auth-storage",
      partialize: (state) => ({ user: state.user }),
    }
  )
);

registerAuthStore(useAuthStore);
