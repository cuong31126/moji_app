import api from "@/lib/axios";
import type { User } from "@/types/user";
import axios from "axios";

const getApiErrorMessage = (error: unknown, fallback: string) => {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as { message?: string } | undefined;
    return data?.message || fallback;
  }

  return error instanceof Error ? error.message : fallback;
};

const throwFriendError = (error: unknown, fallback: string): never => {
  throw new Error(getApiErrorMessage(error, fallback));
};

export const friendService = {
  async searchByUsername(username: string): Promise<User | null> {
    try {
      const query = encodeURIComponent(username.trim());
      const res = await api.get(`/users/search?username=${query}`);
      return res.data.user;
    } catch (error) {
      return throwFriendError(error, "Không tìm được người dùng");
    }
  },

  async searchUsers(keyword: string): Promise<User[]> {
    try {
      const query = encodeURIComponent(keyword.trim());
      const res = await api.get(`/users/search?q=${query}`);
      return res.data.users ?? [];
    } catch (error) {
      return throwFriendError(error, "Không tìm được người dùng");
    }
  },

  async sendFriendRequest(to: string, message?: string) {
    try {
      const res = await api.post("/friends/requests", { to, message });
      return res.data;
    } catch (error) {
      throwFriendError(error, "Không gửi được lời mời kết bạn");
    }
  },

  async getAllFriendRequest() {
    try {
      const res = await api.get("/friends/requests");
      const { sent, received } = res.data;
      return { sent, received };
    } catch (error) {
      throwFriendError(error, "Không tải được danh sách lời mời kết bạn");
    }
  },

  async acceptRequest(requestId: string) {
    try {
      const res = await api.post(`/friends/requests/${requestId}/accept`);
      return res.data.newFriend;
    } catch (error) {
      throwFriendError(error, "Không chấp nhận được lời mời kết bạn");
    }
  },

  async declineRequest(requestId: string) {
    try {
      await api.post(`/friends/requests/${requestId}/decline`);
    } catch (error) {
      throwFriendError(error, "Không từ chối được lời mời kết bạn");
    }
  },

  async withdrawRequest(requestId: string) {
    try {
      await api.post(`/friends/requests/${requestId}/withdraw`);
    } catch (error) {
      throwFriendError(error, "Không thu hồi được lời mời kết bạn");
    }
  },

  async getFriendList() {
    const res = await api.get("/friends");
    return res.data.friends;
  },
};
