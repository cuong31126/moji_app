import { useEffect } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { useAuthStore } from "@/stores/useAuthStore";

const SocialCallbackPage = () => {
  const navigate = useNavigate();
  const { refresh } = useAuthStore();

  useEffect(() => {
    const finishSocialLogin = async () => {
      try {
        await refresh({ silent: true });
        toast.success("Đăng nhập thành công");
        navigate("/", { replace: true });
      } catch (error) {
        console.warn("[auth] Social login refresh failed", error);
        toast.error("Đăng nhập social không thành công");
        navigate("/signin", { replace: true });
      }
    };

    finishSocialLogin();
  }, [navigate, refresh]);

  return (
    <div className="flex h-screen items-center justify-center bg-background font-medium">
      <div className="animate-pulse">Đang hoàn tất đăng nhập...</div>
    </div>
  );
};

export default SocialCallbackPage;
