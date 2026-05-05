import { useAuthStore } from "@/stores/useAuthStore";
import type { Conversation, Message } from "@/types/chat";
import { useEffect, useMemo, useRef, useState } from "react";
import { Button } from "../ui/button";
import { ImagePlus, Loader2, Send, Sparkles, X } from "lucide-react";
import { Textarea } from "../ui/textarea";
import EmojiPicker from "./EmojiPicker";
import { useChatStore } from "@/stores/useChatStore";
import { useSocketStore } from "@/stores/useSocketStore";
import { toast } from "sonner";
import { chatService } from "@/services/chatService";
import { aiService } from "@/services/aiService";
import { notifyChatEvent } from "@/lib/chatAlerts";

const MAX_IMAGE_SIZE = 10 * 1024 * 1024;

const createClientId = () =>
  globalThis.crypto?.randomUUID?.() ??
  `${Date.now()}-${Math.random().toString(16).slice(2)}`;

const getReplyPreviewText = (message: Message) => {
  if (message.content) return message.content;
  if (message.imgUrl) return "Đã gửi một ảnh";
  return "Tin nhắn";
};

const MessageInput = ({
  selectedConvo,
  replyToMessage,
  onCancelReply,
}: {
  selectedConvo: Conversation;
  replyToMessage: Message | null;
  onCancelReply: () => void;
}) => {
  const { user } = useAuthStore();
  const {
    addOptimisticMessage,
    confirmOptimisticMessage,
    setMessageStatus,
  } = useChatStore();
  const { sendChatMessage } = useSocketStore();
  const [value, setValue] = useState("");
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [suggestedEmojis, setSuggestedEmojis] = useState<string[]>([]);
  const [suggestingEmojis, setSuggestingEmojis] = useState(false);
  const [emojiError, setEmojiError] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const replySenderName = useMemo(() => {
    if (!replyToMessage) {
      return "";
    }

    if (replyToMessage.senderId === user?._id) {
      return "Bạn";
    }

    return (
      selectedConvo.participants.find(
        (participant) => participant._id === replyToMessage.senderId
      )?.displayName || "Moji"
    );
  }, [replyToMessage, selectedConvo.participants, user?._id]);

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
    window.setTimeout(() => {
      textareaRef.current?.focus();
    }, 0);
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
    const file = imageFile;
    const reply = replyToMessage;

    if (!text && !file) return;

    const clientId = createClientId();
    const localImageUrl = file ? URL.createObjectURL(file) : undefined;
    const createdAt = new Date().toISOString();
    const optimisticMessage: Message = {
      _id: clientId,
      clientId,
      conversationId: selectedConvo._id,
      senderId: user._id,
      content: text || null,
      imgUrl: localImageUrl,
      replyToMessageId: reply?._id ?? null,
      replyTo: reply
        ? {
            _id: reply._id,
            content: reply.content,
            imgUrl: reply.imgUrl,
            senderId: reply.senderId,
          }
        : null,
      messageType: file && !text ? "image" : "text",
      createdAt,
      isOwn: true,
      status: "sending",
    };

    addOptimisticMessage(optimisticMessage);
    setValue("");
    setImageFile(null);
    setSuggestedEmojis([]);
    setEmojiError("");
    onCancelReply();
    focusMessageInput();

    void (async () => {
      let imgUrl: string | undefined;

      try {
        if (file) {
          const formData = new FormData();
          formData.append("file", file);
          imgUrl = await chatService.uploadMessageImage(formData);
        }

        const sentMessage = await sendChatMessage({
          conversationId: selectedConvo._id,
          content: text,
          imgUrl,
          replyToMessageId: reply?._id,
          clientId,
        });

        confirmOptimisticMessage(clientId, sentMessage);
        notifyChatEvent({
          title: "Tin nhắn đã gửi",
          body: sentMessage.content || (sentMessage.imgUrl ? "Đã gửi một ảnh" : ""),
          conversationId: selectedConvo._id,
        });

        if (localImageUrl) {
          URL.revokeObjectURL(localImageUrl);
        }
      } catch (error) {
        console.error(error);
        setMessageStatus(selectedConvo._id, clientId, "error");
        toast.error("Không gửi được tin nhắn. Bạn hãy thử lại!");
      }
    })();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void sendMessage();
    }
  };

  return (
    <div className="bg-background p-3">
      {replyToMessage && (
        <div className="mb-2 flex items-start gap-3 rounded-xl border border-primary/20 bg-primary/5 px-3 py-2">
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium text-primary">
              Đang trả lời {replySenderName}
            </p>
            <p className="line-clamp-2 text-sm text-muted-foreground">
              {getReplyPreviewText(replyToMessage)}
            </p>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-7 rounded-full"
            onClick={onCancelReply}
          >
            <X className="size-3.5" />
          </Button>
        </div>
      )}

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
        >
          <ImagePlus className="size-4" />
        </Button>

        <div className="relative flex-1">
          <Textarea
            ref={textareaRef}
            onKeyDown={handleKeyDown}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Soạn tin nhắn..."
            rows={1}
            className="max-h-32 min-h-10 resize-none overflow-y-auto border-border/50 bg-white py-2 pr-28 transition-smooth focus:border-primary/50"
          />
          <div className="absolute right-2 top-1/2 flex -translate-y-1/2 transform items-center gap-1">
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-8 hover:bg-primary/10 transition-smooth"
              onClick={suggestEmojis}
              disabled={suggestingEmojis || !value.trim()}
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
                <EmojiPicker onChange={(emoji: string) => appendEmoji(emoji)} />
              </div>
            </Button>
          </div>
        </div>

        <Button
          type="button"
          onClick={sendMessage}
          className="bg-gradient-chat transition-smooth hover:scale-105 hover:shadow-glow"
          disabled={!value.trim() && !imageFile}
        >
          <Send className="size-4 text-white" />
        </Button>
      </div>
    </div>
  );
};

export default MessageInput;
