import { type FormEvent, useMemo, useState } from "react";
import { Heart, Save } from "lucide-react";
import { toast } from "sonner";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import type { User } from "@/types/user";
import { useAuthStore } from "@/stores/useAuthStore";

type EditableField = {
  key: keyof Pick<User, "displayName" | "username" | "email" | "phone">;
  label: string;
  type?: string;
};

type ProfileFormState = Pick<
  User,
  "displayName" | "username" | "email" | "phone" | "bio"
>;

const PERSONAL_FIELDS: EditableField[] = [
  { key: "displayName", label: "Tên hiển thị" },
  { key: "username", label: "Tên người dùng" },
  { key: "email", label: "Email", type: "email" },
  { key: "phone", label: "Số điện thoại" },
];

type Props = {
  userInfo: User | null;
};

const toFormState = (userInfo: User): ProfileFormState => ({
  displayName: userInfo.displayName ?? "",
  username: userInfo.username ?? "",
  email: userInfo.email ?? "",
  phone: userInfo.phone ?? "",
  bio: userInfo.bio ?? "",
});

const PersonalInfoForm = ({ userInfo }: Props) => {
  const { setUser } = useAuthStore();
  const [formState, setFormState] = useState<ProfileFormState | null>(
    userInfo ? toFormState(userInfo) : null
  );

  const hasChanges = useMemo(() => {
    if (!userInfo || !formState) {
      return false;
    }

    const current = toFormState(userInfo);
    return Object.keys(current).some((key) => {
      const field = key as keyof ProfileFormState;
      return (current[field] ?? "") !== (formState[field] ?? "");
    });
  }, [formState, userInfo]);

  if (!userInfo || !formState) return null;

  const handleChange = (key: keyof ProfileFormState, value: string) => {
    setFormState((current) => (current ? { ...current, [key]: value } : current));
  };

  const handleSave = (event: FormEvent) => {
    event.preventDefault();

    const displayName = formState.displayName.trim();
    const username = formState.username.trim();

    if (!displayName || !username) {
      toast.error("Tên hiển thị và tên người dùng không được để trống.");
      return;
    }

    setUser({
      ...userInfo,
      ...formState,
      displayName,
      username,
      email: formState.email?.trim(),
      phone: formState.phone?.trim(),
      bio: formState.bio?.trim(),
    });
    toast.success("Đã lưu thông tin tài khoản trên thiết bị này.");
  };

  return (
    <Card className="glass-strong border-border/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Heart className="size-5 text-primary" />
          Thông tin cá nhân
        </CardTitle>
        <CardDescription>
          Cập nhật tên hiển thị, tài khoản và phần giới thiệu của bạn.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <form className="space-y-4" onSubmit={handleSave}>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {PERSONAL_FIELDS.map(({ key, label, type }) => (
              <div key={key} className="space-y-2">
                <Label htmlFor={key}>{label}</Label>
                <Input
                  id={key}
                  type={type ?? "text"}
                  value={formState[key] ?? ""}
                  onChange={(event) => handleChange(key, event.target.value)}
                  className="glass-light border-border/30"
                />
              </div>
            ))}
          </div>

          <div className="space-y-2">
            <Label htmlFor="bio">Giới thiệu</Label>
            <Textarea
              id="bio"
              rows={3}
              value={formState.bio ?? ""}
              onChange={(event) => handleChange("bio", event.target.value)}
              className="glass-light resize-none border-border/30"
            />
          </div>

          <Button
            type="submit"
            className="w-full bg-gradient-primary transition-opacity hover:opacity-90 md:w-auto"
            disabled={!hasChanges}
          >
            <Save className="size-4" />
            Lưu thay đổi
          </Button>
        </form>
      </CardContent>
    </Card>
  );
};

export default PersonalInfoForm;
