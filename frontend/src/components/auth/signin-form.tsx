import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Label } from "../ui/label";
import { useAuthStore } from "@/stores/useAuthStore";
import { useNavigate, useSearchParams } from "react-router";
import { useEffect } from "react";
import { toast } from "sonner";
import { SocialLoginButtons } from "./SocialLoginButtons";

const signInSchema = z.object({
  username: z.string().min(3, "Tên đăng nhập phải có ít nhất 3 ký tự"),
  password: z.string().min(6, "Mật khẩu phải có ít nhất 6 ký tự"),
});

type SignInFormValues = z.infer<typeof signInSchema>;

export function SigninForm({ className, ...props }: React.ComponentProps<"div">) {
  const { signIn } = useAuthStore();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SignInFormValues>({
    resolver: zodResolver(signInSchema),
  });

  const onSubmit = async (data: SignInFormValues) => {
    const { username, password } = data;
    await signIn(username, password);
    navigate("/");
  };

  useEffect(() => {
    const socialError = searchParams.get("socialError");

    if (!socialError) {
      return;
    }

    const provider = socialError.split("_")[0];
    const reason = socialError.includes("not_configured")
      ? "chưa được cấu hình trên backend"
      : "không thành công";

    toast.error(`Đăng nhập ${provider} ${reason}.`);
  }, [searchParams]);

  return (
    <div
      className={cn("flex w-full flex-col gap-4", className)}
      {...props}
    >
      <Card className="w-full overflow-hidden border border-primary/20 bg-card/95 p-0 shadow-soft dark:border-primary/30 dark:bg-card/95">
        <CardContent className="grid p-0 md:min-h-[560px] md:grid-cols-[0.95fr_1.05fr]">
          <form
            className="p-5 sm:p-6 md:p-8"
            onSubmit={handleSubmit(onSubmit)}
          >
            <div className="mx-auto flex max-w-sm flex-col gap-5">
              {/* header - logo */}
              <div className="flex flex-col items-center text-center gap-2">
                <a
                  href="/"
                  className="mx-auto inline-flex w-fit rounded-2xl bg-transparent p-1 ring-1 ring-border/40 dark:ring-primary/25"
                >
                  <img
                    src="/logo23-transparent.png"
                    alt="EcoMoji logo"
                    className="h-12 w-auto object-contain"
                  />
                </a>

                <h1 className="text-2xl font-bold">Chào mừng quay lại</h1>
                <p className="text-muted-foreground text-balance">
                  Đăng nhập vào tài khoản EcoMoji của bạn
                </p>
              </div>

              {/* username */}
              <div className="flex flex-col gap-3">
                <Label
                  htmlFor="username"
                  className="block text-sm"
                >
                  Tên đăng nhập
                </Label>
                <Input
                  type="text"
                  id="username"
                  placeholder="moji"
                  {...register("username")}
                />
                {errors.username && (
                  <p className="text-destructive text-sm">
                    {errors.username.message}
                  </p>
                )}
              </div>

              {/* password */}
              <div className="flex flex-col gap-3">
                <Label
                  htmlFor="password"
                  className="block text-sm"
                >
                  Mật khẩu
                </Label>
                <Input
                  type="password"
                  id="password"
                  {...register("password")}
                />
                {errors.password && (
                  <p className="text-destructive text-sm">
                    {errors.password.message}
                  </p>
                )}
              </div>

              {/* nút đăng nhập */}
              <Button
                type="submit"
                className="w-full"
                disabled={isSubmitting}
              >
                Đăng nhập
              </Button>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t border-border" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">Hoặc</span>
                </div>
              </div>

              <SocialLoginButtons />

              <div className="text-center text-sm">
                Chưa có tài khoản?{" "}
                <a
                  href="/signup"
                  className="underline underline-offset-4"
                >
                  Đăng ký
                </a>
              </div>
            </div>
          </form>
          <div className="bg-muted relative hidden min-h-[560px] md:block">
            <img
              src="/placeholder.png"
              alt="Image"
              className="absolute inset-0 h-full w-full object-cover"
            />
          </div>
        </CardContent>
      </Card>
      <div className="px-4 text-center text-xs text-balance text-muted-foreground *:[a]:underline *:[a]:underline-offetset-4 *:[a]:hover:text-primary">
        Bằng cách tiếp tục, bạn đồng ý với <a href="#">Điều khoản dịch vụ</a> và{" "}
        <a href="#">Chính sách bảo mật</a> của chúng tôi.
      </div>
    </div>
  );
}
