import { useState } from "react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

const API_URL = import.meta.env.VITE_API_URL;

const socialProviders = [
  { id: "google", label: "Continue with Google", mark: "G" },
  { id: "github", label: "Continue with GitHub", mark: "GH" },
  { id: "facebook", label: "Continue with Facebook", mark: "f" },
];

const getAuthUrl = (provider: string) => {
  const baseUrl = String(API_URL || "").replace(/\/$/, "");
  return `${baseUrl}/auth/${provider}`;
};

export function SocialLoginButtons() {
  const [loadingProvider, setLoadingProvider] = useState<string | null>(null);

  const handleSocialLogin = (provider: string) => {
    if (!API_URL) {
      toast.error("Thiếu VITE_API_URL để đăng nhập social.");
      return;
    }

    setLoadingProvider(provider);
    window.location.assign(getAuthUrl(provider));
  };

  return (
    <div className="grid gap-2">
      {socialProviders.map((provider) => {
        const isLoading = loadingProvider === provider.id;

        return (
          <Button
            key={provider.id}
            type="button"
            variant="outline"
            className="w-full justify-start gap-3"
            onClick={() => handleSocialLogin(provider.id)}
            disabled={Boolean(loadingProvider)}
          >
            <span className="flex size-6 items-center justify-center rounded-full bg-muted text-xs font-bold">
              {isLoading ? <Loader2 className="size-3 animate-spin" /> : provider.mark}
            </span>
            {isLoading ? "Đang chuyển hướng..." : provider.label}
          </Button>
        );
      })}
    </div>
  );
}
