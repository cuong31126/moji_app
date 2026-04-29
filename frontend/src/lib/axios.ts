import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true,
});

const getAuthStore = async () => {
  const { useAuthStore } = await import("@/stores/useAuthStore");
  return useAuthStore;
};

api.interceptors.request.use(async (config) => {
  const { accessToken } = (await getAuthStore()).getState();

  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }

  return config;
});

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config;
    const status = error.response?.status;

    if (!originalRequest?.url) {
      return Promise.reject(error);
    }

    if (
      originalRequest.url.includes("/auth/signin") ||
      originalRequest.url.includes("/auth/signup") ||
      originalRequest.url.includes("/auth/refresh")
    ) {
      return Promise.reject(error);
    }

    originalRequest._retryCount = originalRequest._retryCount || 0;

    if ((status === 401 || status === 403) && originalRequest._retryCount < 4) {
      originalRequest._retryCount += 1;

      try {
        const res = await api.post("/auth/refresh");
        const { accessToken: newAccessToken, user } = res.data;
        const authStore = await getAuthStore();

        authStore.getState().setAccessToken(newAccessToken);
        if (user) {
          authStore.getState().setUser(user);
        }

        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        console.warn("[axios] Refresh failed while retrying request", refreshError);
        const authStore = await getAuthStore();
        authStore.getState().clearState();
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
