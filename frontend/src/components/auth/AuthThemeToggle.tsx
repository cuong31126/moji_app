import { Moon, Sun } from "lucide-react";
import { Button } from "../ui/button";
import { useThemeStore } from "@/stores/useThemeStore";

const AuthThemeToggle = () => {
  const { isDark, toggleTheme } = useThemeStore();

  return (
    <Button
      type="button"
      variant="outline"
      size="icon"
      aria-label={isDark ? "Chuyển sang chế độ sáng" : "Chuyển sang chế độ tối"}
      className="fixed right-4 top-4 z-20 rounded-full border-primary/30 bg-background/80 text-primary shadow-soft backdrop-blur hover:bg-primary/10 dark:border-primary/40 dark:bg-background/80"
      onClick={toggleTheme}
    >
      {isDark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </Button>
  );
};

export default AuthThemeToggle;
