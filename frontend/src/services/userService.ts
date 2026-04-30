import api from "@/lib/axios";
import type { User } from "@/types/user";

export const userService = {
  uploadAvatar: async (formData: FormData) => {
    const res = await api.post("/users/uploadAvatar", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    if (res.status === 400) {
      throw new Error(res.data.message);
    }

    return res.data;
  },

  getUserById: async (userId: string): Promise<User> => {
    const res = await api.get(`/users/${userId}`);
    return res.data.user;
  },
};
