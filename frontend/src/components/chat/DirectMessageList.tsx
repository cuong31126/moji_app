import { useChatStore } from "@/stores/useChatStore";
import DirectMessageCard from "./DirectMessageCard";

const DirectMessageList = () => {
  const { conversations } = useChatStore();

  if (!conversations) return;

  const directConversations = conversations.filter(
    (convo) => convo.type === "direct"
  );

  return (
    <div className="beautiful-scrollbar flex-1 space-y-2 overflow-y-auto p-2 pr-1">
      {directConversations.map((convo) => (
        <DirectMessageCard
          convo={convo}
          key={convo._id}
        />
      ))}
    </div>
  );
};

export default DirectMessageList;
