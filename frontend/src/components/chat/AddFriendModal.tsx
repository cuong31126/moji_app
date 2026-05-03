import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "../ui/dialog";
import { UserPlus } from "lucide-react";
import type { User } from "@/types/user";
import { useFriendStore } from "@/stores/useFriendStore";
import { useForm, useWatch } from "react-hook-form";
import { toast } from "sonner";
import SearchForm from "@/components/AddFriendModal/SearchForm";
import SendFriendRequestForm from "@/components/AddFriendModal/SendFriendRequestForm";
import type { AddFriendFormValues } from "@/types/form";
import UserProfileDialog from "../profile/UserProfileDialog";

const getErrorMessage = (error: unknown) =>
  error instanceof Error ? error.message : "Lỗi xảy ra. Hãy thử lại";

const AddFriendModal = () => {
  const [open, setOpen] = useState(false);
  const [isFound, setIsFound] = useState<boolean | null>(null);
  const [searchUser, setSearchUser] = useState<User>();
  const [suggestions, setSuggestions] = useState<User[]>([]);
  const [previewUser, setPreviewUser] = useState<User | null>(null);
  const [searchedUsername, setSearchedUsername] = useState("");
  const { loading, searchByUsername, searchUsers, addFriend } = useFriendStore();

  const {
    register,
    handleSubmit,
    control,
    reset,
    formState: { errors },
  } = useForm<AddFriendFormValues>({
    defaultValues: { username: "", message: "" },
  });

  const usernameValue = useWatch({ control, name: "username" });

  useEffect(() => {
    const query = usernameValue?.trim();

    if (!open || isFound || !query) {
      setSuggestions([]);
      if (!query) {
        setIsFound(null);
        setSearchedUsername("");
      }
      return;
    }

    const timer = window.setTimeout(async () => {
      try {
        const users = await searchUsers(query);
        setSuggestions(users);
        setSearchedUsername(query);
        setIsFound(users.length > 0 ? null : false);
      } catch (error) {
        console.error(error);
        setSuggestions([]);
        setIsFound(false);
      }
    }, 300);

    return () => window.clearTimeout(timer);
  }, [isFound, open, searchUsers, usernameValue]);

  const handleCancel = () => {
    reset();
    setSearchUser(undefined);
    setSuggestions([]);
    setPreviewUser(null);
    setSearchedUsername("");
    setIsFound(null);
  };

  const handleSearch = handleSubmit(async (data) => {
    const username = data.username.trim();
    if (!username) return;

    setIsFound(null);
    setSearchUser(undefined);
    setSearchedUsername(username);

    try {
      const foundUser = await searchByUsername(username);
      if (foundUser) {
        setIsFound(true);
        setSearchUser(foundUser);
        setSuggestions([]);
      } else {
        setIsFound(false);
      }
    } catch (error) {
      console.error(error);
      setIsFound(false);
      toast.error(getErrorMessage(error));
    }
  });

  const handleSend = handleSubmit(async (data) => {
    if (!searchUser) return;

    if (searchUser.relationshipStatus === "friends") {
      toast.info("Hai bạn đã là bạn bè rồi");
      return;
    }

    if (searchUser.relationshipStatus === "request_sent") {
      toast.info("Bạn đã gửi lời mời cho người này");
      return;
    }

    try {
      const message = await addFriend(searchUser._id, data.message.trim());
      toast.success(message);

      handleCancel();
      setOpen(false);
    } catch (error) {
      console.error("Error while sending friend request from form", error);
      toast.error(getErrorMessage(error));
    }
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(nextOpen) => {
        setOpen(nextOpen);
        if (!nextOpen) handleCancel();
      }}
    >
      <DialogTrigger asChild>
        <div className="flex justify-center items-center size-5 rounded-full hover:bg-sidebar-accent cursor-pointer z-10">
          <UserPlus className="size-4" />
          <span className="sr-only">Kết bạn</span>
        </div>
      </DialogTrigger>

      <DialogContent className="max-h-[calc(100vh-2rem)] w-[calc(100vw-2rem)] overflow-hidden border-none p-4 sm:max-w-[425px] sm:p-6">
        <DialogHeader>
          <DialogTitle>Kết Bạn</DialogTitle>
        </DialogHeader>

        {!isFound && (
          <SearchForm
            register={register}
            errors={errors}
            usernameValue={usernameValue}
            loading={loading}
            isFound={isFound}
            searchedUsername={searchedUsername}
            suggestions={suggestions}
            onSubmit={handleSearch}
            onCancel={handleCancel}
            onSelectSuggestion={setPreviewUser}
          />
        )}

        {isFound && (
          <SendFriendRequestForm
            register={register}
            loading={loading}
            searchedUsername={searchedUsername}
            onSubmit={handleSend}
            onBack={() => setIsFound(null)}
          />
        )}
      </DialogContent>

      <UserProfileDialog
        open={Boolean(previewUser)}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) setPreviewUser(null);
        }}
        userId={previewUser?._id}
        initialUser={previewUser}
      />
    </Dialog>
  );
};

export default AddFriendModal;
