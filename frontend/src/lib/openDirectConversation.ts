import { useChatStore } from "@/stores/useChatStore";

export const openDirectConversation = async (targetUserId: string) => {
  const chatState = useChatStore.getState();
  const existingConversation = chatState.conversations.find(
    (conversation) =>
      conversation.type === "direct" &&
      conversation.participants.some(
        (participant) => participant._id === targetUserId
      )
  );

  if (existingConversation) {
    chatState.setActiveConversation(existingConversation._id);

    if (!chatState.messages[existingConversation._id]) {
      await chatState.fetchMessages(existingConversation._id);
    }

    return existingConversation._id;
  }

  const conversation = await chatState.createConversation("direct", "", [
    targetUserId,
  ]);

  if (conversation?._id && !useChatStore.getState().messages[conversation._id]) {
    await useChatStore.getState().fetchMessages(conversation._id);
  }

  return conversation?._id ?? useChatStore.getState().activeConversationId;
};
