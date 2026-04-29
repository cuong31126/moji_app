import { useAuthStore } from "@/stores/useAuthStore";
import { useEffect, useState } from "react";
import { Navigate, Outlet } from "react-router";

const ProtectedRoute = () => {
  // Chúng ta không lấy accessToken trực tiếp ở đây để tránh bị dùng giá trị cũ trong hàm async
  const { refresh, fetchMe, loading } = useAuthStore();
  const [starting, setStarting] = useState(true);

  useEffect(() => {
    const init = async () => {
      try {
        // 1. Kiểm tra token hiện tại trong Store (giá trị mới nhất)
        let currentToken = useAuthStore.getState().accessToken;

        // 2. Nếu chưa có token, thử chạy refresh để lấy lại từ cookie
        if (!currentToken) {
          await refresh({ silent: true });
          currentToken = useAuthStore.getState().accessToken; // Cập nhật lại biến sau khi refresh
        }

        // 3. Nếu đã có token nhưng chưa có thông tin user, hãy fetch thông tin user
        if (currentToken && !useAuthStore.getState().user) {
          await fetchMe();
        }
      } catch (error) {
        console.error("Xác thực thất bại:", error);
      } finally {
        // Luôn luôn tắt trạng thái loading ban đầu dù thành công hay thất bại
        setStarting(false);
      }
    };

    init();
  }, [refresh, fetchMe]);

  // Đang trong quá trình kiểm tra (Starting) hoặc Store đang xử lý (Loading)
  if (starting || loading) {
    return (
      <div className="flex h-screen items-center justify-center font-medium">
        <div className="animate-pulse">Đang xác thực phiên đăng nhập...</div>
      </div>
    );
  }

  // Sau khi init xong, nếu vẫn không có accessToken thì mới đá về Signin
  if (!useAuthStore.getState().accessToken) {
    return <Navigate to="/signin" replace />;
  }

  // Nếu mọi thứ ổn, cho phép vào trang
  return <Outlet />;
};

export default ProtectedRoute;
