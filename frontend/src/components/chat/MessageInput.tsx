import { useAuthStore } from "@/stores/useAuthStore";
import type { Conversation } from "@/types/chat";
import { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "../ui/button";
import { ImagePlus, Loader2, Send, Sparkles, X } from "lucide-react";
import { Input } from "../ui/input";
import EmojiPicker from "./EmojiPicker";
import { useChatStore } from "@/stores/useChatStore";
import { toast } from "sonner";
import { chatService } from "@/services/chatService";
import { aiService } from "@/services/aiService";

const MAX_IMAGE_SIZE = 10 * 1024 * 1024;

const MessageInput = ({ selectedConvo }: { selectedConvo: Conversation }) => {
  const { user } = useAuthStore();
  const { sendDirectMessage, sendGroupMessage } = useChatStore();
  const [value, setValue] = useState("");
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [sending, setSending] = useState(false);
  const [suggestedEmojis, setSuggestedEmojis] = useState<string[]>([]);
  const [suggestingEmojis, setSuggestingEmojis] = useState(false);
  const [emojiError, setEmojiError] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messageInputRef = useRef<HTMLInputElement>(null);

  const previewUrl = useMemo(
    () => (imageFile ? URL.createObjectURL(imageFile) : null),
    [imageFile]
  );

  useEffect(() => {
    return () => {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
    };
  }, [previewUrl]);

  if (!user) return null;

  const handleImageSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";

    if (!file) return;

    if (!file.type.startsWith("image/")) {
      toast.error("Bạn chỉ có thể gửi file ảnh.");
      return;
    }

    if (file.size > MAX_IMAGE_SIZE) {
      toast.error("Ảnh không được vượt quá 10MB.");
      return;
    }

    setImageFile(file);
  };

  const clearImage = () => {
    setImageFile(null);
  };

  const appendEmoji = (emoji: string) => {
    setValue((current) => `${current}${emoji}`);
  };

  const focusMessageInput = () => {
    requestAnimationFrame(() => {
      messageInputRef.current?.focus();
    });
  };

  const suggestEmojis = async () => {
    const text = value.trim();

    if (!text || suggestingEmojis) {
      return;
    }

    try {
      setSuggestingEmojis(true);
      setEmojiError("");
      const result = await aiService.suggestEmojis(text);
      setSuggestedEmojis(result.emojis);

      if (result.fallback) {
        setEmojiError("AI đang bận, thử lại sau.");
      }
    } catch (error) {
      console.error(error);
      focusMessageInput();
      setSuggestedEmojis([]);
      setEmojiError("AI đang bận, thử lại sau.");
    } finally {
      setSuggestingEmojis(false);
    }
  };

  const sendMessage = async () => {
    const text = value.trim();

    if ((!text && !imageFile) || sending) return;

    setSending(true);

    try {
      let imgUrl: string | undefined;

      if (imageFile) {
        const formData = new FormData();
        formData.append("file", imageFile);
        imgUrl = await chatService.uploadMessageImage(formData);
      }

      if (selectedConvo.type === "direct") {
        const otherUser = selectedConvo.participants.find((p) => p._id !== user._id);

        if (!otherUser) {
          throw new Error("Không tìm thấy người nhận.");
        }

        await sendDirectMessage(otherUser._id, text, imgUrl);
      } else {
        await sendGroupMessage(selectedConvo._id, text, imgUrl);
      }

      setValue("");
      setImageFile(null);
      setSuggestedEmojis([]);
      setEmojiError("");
      focusMessageInput();
    } catch (error) {
      console.error(error);
      toast.error("Lỗi xảy ra khi gửi tin nhắn. Bạn hãy thử lại!");
      focusMessageInput();
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="bg-background p-3">
      {previewUrl && (
        <div className="mb-2 flex items-end gap-2">
          <div className="relative max-w-40 overflow-hidden rounded-md border border-border/60 bg-muted">
            <img
              src={previewUrl}
              alt="Ảnh chuẩn bị gửi"
              className="max-h-32 w-full object-contain"
            />
            <Button
              type="button"
              variant="secondary"
              size="icon"
              className="absolute right-1 top-1 size-6 rounded-full"
              onClick={clearImage}
              disabled={sending}
            >
              <X className="size-3" />
            </Button>
          </div>
        </div>
      )}

      {(suggestingEmojis || suggestedEmojis.length > 0 || emojiError) && (
        <div className="mb-2 flex flex-wrap items-center gap-2 rounded-xl border border-border/70 bg-muted/60 px-3 py-2">
          {suggestingEmojis && (
            <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="size-3 animate-spin" />
              Đang gợi ý...
            </span>
          )}
          {emojiError && (
            <span className="text-xs text-muted-foreground">{emojiError}</span>
          )}
          {suggestedEmojis.map((emoji) => (
            <Button
              key={emoji}
              type="button"
              variant="secondary"
              size="icon"
              className="size-8 rounded-full text-base"
              onClick={() => appendEmoji(emoji)}
            >
              {emoji}
            </Button>
          ))}
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="ml-auto size-7 rounded-full"
            onClick={() => {
              setSuggestedEmojis([]);
              setEmojiError("");
            }}
          >
            <X className="size-3.5" />
          </Button>
        </div>
      )}

      <div className="flex min-h-[56px] items-center gap-2">
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={handleImageSelect}
        />

        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="hover:bg-primary/10 transition-smooth"
          onClick={() => fileInputRef.current?.click()}
          disabled={sending}
        >
          <ImagePlus className="size-4" />
        </Button>

        <div className="relative flex-1">
          <Input
            ref={messageInputRef}
            onKeyDown={handleKeyDown}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Soạn tin nhắn..."
            disabled={sending}
            className="h-9 resize-none border-border/50 bg-white pr-28 transition-smooth focus:border-primary/50"
          />
          <div className="absolute right-2 top-1/2 flex -translate-y-1/2 transform items-center gap-1">
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-8 hover:bg-primary/10 transition-smooth"
              onClick={suggestEmojis}
              disabled={sending || suggestingEmojis || !value.trim()}
              title="Gợi ý emoji bằng AI"
            >
              {suggestingEmojis ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Sparkles className="size-4" />
              )}
            </Button>
            <Button
              asChild
              variant="ghost"
              size="icon"
              className="size-8 hover:bg-primary/10 transition-smooth"
            >
              <div>
                <EmojiPicker
                  onChange={(emoji: string) => appendEmoji(emoji)}
                />
              </div>
            </Button>
          </div>
        </div>

        <Button
          onClick={sendMessage}
          className="bg-gradient-chat transition-smooth hover:scale-105 hover:shadow-glow"
          disabled={sending || (!value.trim() && !imageFile)}
        >
          {sending ? (
            <Loader2 className="size-4 animate-spin text-white" />
          ) : (
            <Send className="size-4 text-white" />
          )}
        </Button>
      </div>
    </div>
  );
};

export default MessageInput;
