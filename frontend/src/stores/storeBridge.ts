import type { StoreApi } from "zustand";
import type { AuthState, ChatState, SocketState } from "@/types/store";

let authStore: StoreApi<AuthState> | null = null;
let chatStore: StoreApi<ChatState> | null = null;
let socketStore: StoreApi<SocketState> | null = null;

export const registerAuthStore = (store: StoreApi<AuthState>) => {
  authStore = store;
};

export const registerChatStore = (store: StoreApi<ChatState>) => {
  chatStore = store;
};

export const registerSocketStore = (store: StoreApi<SocketState>) => {
  socketStore = store;
};

export const getAuthState = () => authStore?.getState();

export const getChatState = () => chatStore?.getState();

export const getSocketState = () => socketStore?.getState();
