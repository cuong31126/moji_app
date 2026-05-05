import { Shield, Bell, ShieldBan } from "lucide-react";
import { toast } from "sonner";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { requestChatNotificationPermission } from "@/lib/chatAlerts";

const PrivacySettings = () => {
  const handlePassword = () => {
    toast.info("Đổi mật khẩu sẽ được mở khi backend có endpoint bảo mật.");
  };

  const handleNotification = async () => {
    const permission = await requestChatNotificationPermission();

    if (permission === "granted") {
      toast.success("Thông báo trình duyệt đã được bật.");
      return;
    }

    toast.info("Bạn có thể bật thông báo trong cài đặt trình duyệt.");
  };

  const handleBlockReport = () => {
    toast.info("Tính năng chặn và báo cáo đang được chuẩn bị.");
  };

  const handleDeleteAccount = () => {
    toast.error("Xóa tài khoản cần xác nhận từ backend trước khi thực hiện.");
  };

  return (
    <Card className="glass-strong border-border/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          Quyền riêng tư & Bảo mật
        </CardTitle>
        <CardDescription>
          Quản lý bảo mật tài khoản và quyền thông báo của Moji.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="space-y-4">
          <Button
            type="button"
            variant="outline"
            className="glass-light w-full justify-start border-border/30 hover:text-warning"
            onClick={handlePassword}
          >
            <Shield className="mr-2 h-4 w-4" />
            Đổi mật khẩu
          </Button>

          <Button
            type="button"
            variant="outline"
            className="glass-light w-full justify-start border-border/30 hover:text-info"
            onClick={handleNotification}
          >
            <Bell className="mr-2 h-4 w-4" />
            Bật thông báo Chrome
          </Button>

          <Button
            type="button"
            variant="outline"
            className="glass-light w-full justify-start border-border/30 hover:text-destructive"
            onClick={handleBlockReport}
          >
            <ShieldBan className="mr-2 size-4" />
            Chặn & Báo cáo
          </Button>
        </div>

        <div className="border-t border-border/30 pt-4">
          <h4 className="mb-3 font-medium text-destructive">Khu vực nguy hiểm</h4>
          <Button
            type="button"
            variant="destructive"
            className="w-full"
            onClick={handleDeleteAccount}
          >
            Xoá tài khoản
          </Button>
        </div>
      </CardContent>
    </Card>
  );
};

export default PrivacySettings;
