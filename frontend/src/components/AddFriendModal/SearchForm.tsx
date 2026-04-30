import type { FieldErrors, UseFormRegister } from "react-hook-form";
import { Search } from "lucide-react";

import type { AddFriendFormValues } from "@/types/form";
import type { RelationshipStatus, User } from "@/types/user";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { DialogClose, DialogFooter } from "../ui/dialog";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import UserAvatar from "../chat/UserAvatar";

interface SearchFormProps {
  register: UseFormRegister<AddFriendFormValues>;
  errors: FieldErrors<AddFriendFormValues>;
  loading: boolean;
  usernameValue: string;
  isFound: boolean | null;
  searchedUsername: string;
  suggestions: User[];
  onSubmit?: (e: React.FormEvent<HTMLFormElement>) => void;
  onCancel: () => void;
  onSelectSuggestion: (user: User) => void;
}

const relationshipLabels: Record<RelationshipStatus, string> = {
  self: "Bạn",
  friends: "Bạn bè",
  request_sent: "Đã gửi",
  request_received: "Đã nhận lời mời",
  none: "Thêm bạn",
};

const relationshipClasses: Record<RelationshipStatus, string> = {
  self: "border-slate-200 bg-slate-50 text-slate-700 dark:bg-slate-900/60",
  friends: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:bg-emerald-950/50",
  request_sent: "border-amber-200 bg-amber-50 text-amber-700 dark:bg-amber-950/50",
  request_received: "border-sky-200 bg-sky-50 text-sky-700 dark:bg-sky-950/50",
  none: "border-primary/30 bg-primary/10 text-primary",
};

const SearchForm = ({
  register,
  errors,
  usernameValue,
  loading,
  isFound,
  searchedUsername,
  suggestions,
  onSubmit,
  onCancel,
  onSelectSuggestion,
}: SearchFormProps) => {
  const hasQuery = Boolean(usernameValue?.trim());

  return (
    <form
      onSubmit={onSubmit}
      className="space-y-4"
    >
      <div className="space-y-2">
        <Label
          htmlFor="username"
          className="text-sm font-semibold"
        >
          Tìm bạn bè
        </Label>

        <Input
          id="username"
          placeholder="Nhập tên, username hoặc email..."
          className="glass border-border/50 transition-smooth focus:border-primary/50"
          autoComplete="off"
          {...register("username", {
            required: "Bạn chưa nhập từ khóa tìm kiếm",
          })}
        />
        {errors.username && (
          <p className="error-message">{errors.username.message}</p>
        )}

        {suggestions.length > 0 && (
          <div className="beautiful-scrollbar max-h-64 overflow-y-auto rounded-lg border border-border/70 bg-background/95 p-1 shadow-soft">
            {suggestions.map((user) => {
              const relationship = user.relationshipStatus ?? "none";

              return (
                <button
                  key={user._id}
                  type="button"
                  className="flex w-full items-center gap-3 rounded-md p-2 text-left transition hover:bg-muted"
                  onClick={() => onSelectSuggestion(user)}
                >
                  <UserAvatar
                    type="chat"
                    name={user.displayName}
                    avatarUrl={user.avatarUrl}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">
                      {user.displayName}
                    </span>
                    <span className="block truncate text-xs text-muted-foreground">
                      @{user.username}
                      {user.email ? ` · ${user.email}` : ""}
                    </span>
                  </span>
                  <Badge
                    variant="outline"
                    className={relationshipClasses[relationship]}
                  >
                    {relationshipLabels[relationship]}
                  </Badge>
                </button>
              );
            })}
          </div>
        )}

        {isFound === false && hasQuery && suggestions.length === 0 && !loading && (
          <span className="error-message">
            Không tìm thấy <span className="font-semibold">@{searchedUsername}</span>
          </span>
        )}
      </div>

      <DialogFooter>
        <DialogClose asChild>
          <Button
            type="button"
            variant="outline"
            className="flex-1 glass hover:text-destructive"
            onClick={onCancel}
          >
            Hủy
          </Button>
        </DialogClose>

        <Button
          type="submit"
          disabled={loading || !usernameValue?.trim()}
          className="flex-1 bg-gradient-chat text-white transition-smooth hover:opacity-90"
        >
          {loading ? (
            <span>Đang tìm...</span>
          ) : (
            <>
              <Search className="mr-2 size-4" /> Tìm
            </>
          )}
        </Button>
      </DialogFooter>
    </form>
  );
};

export default SearchForm;
