import { GoogleGenerativeAI } from "@google/generative-ai";

const MAX_SUMMARY_MESSAGES = 30;
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

const getGeminiModel = () => {
  if (!process.env.GEMINI_API_KEY) {
    throw new Error("Missing GEMINI_API_KEY");
  }

  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  return genAI.getGenerativeModel({ model: GEMINI_MODEL });
};

const sanitizeText = (value, maxLength = 1000) => {
  return String(value || "")
    .trim()
    .slice(0, maxLength);
};

const extractJsonArray = (text) => {
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) return null;

  try {
    const parsed = JSON.parse(match[0]);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

export const summarizeChat = async (req, res) => {
  try {
    const { messages } = req.body;

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ message: "Cần gửi danh sách tin nhắn" });
    }

    const recentMessages = messages
      .slice(-MAX_SUMMARY_MESSAGES)
      .map((item) => ({
        senderName: sanitizeText(item.senderName, 80) || "Người dùng",
        content: sanitizeText(item.content, 1000),
      }))
      .filter((item) => item.content);

    if (recentMessages.length === 0) {
      return res.status(400).json({ message: "Không có nội dung để tóm tắt" });
    }

    const chatText = recentMessages
      .map((item) => `${item.senderName}: ${item.content}`)
      .join("\n");

    const prompt = [
      "Hãy tóm tắt đoạn chat sau bằng tiếng Việt, ngắn gọn, dễ hiểu, tối đa 5 gạch đầu dòng. Không bịa thêm thông tin.",
      "",
      chatText,
    ].join("\n");

    const model = getGeminiModel();
    const result = await model.generateContent(prompt);
    const summary = result.response.text().trim();

    return res.status(200).json({
      summary:
        summary ||
        "AI đang bận, chưa thể tóm tắt đoạn chat này. Bạn thử lại sau nhé.",
    });
  } catch (error) {
    console.error("[ai.summarizeChat] Gemini error", error);
    return res.status(200).json({
      summary: "AI đang bận, chưa thể tóm tắt đoạn chat này. Bạn thử lại sau nhé.",
      fallback: true,
    });
  }
};

export const suggestEmojis = async (req, res) => {
  try {
    const text = sanitizeText(req.body?.text, 500);

    if (!text) {
      return res.status(400).json({ message: "Cần nội dung tin nhắn" });
    }

    const prompt = [
      "Dựa vào nội dung tin nhắn, hãy gợi ý tối đa 5 emoji phù hợp. Chỉ trả về JSON array emoji, không giải thích.",
      "",
      `Tin nhắn: ${text}`,
    ].join("\n");

    const model = getGeminiModel();
    const result = await model.generateContent(prompt);
    const rawText = result.response.text().trim();
    const parsed = extractJsonArray(rawText);
    const emojis = (parsed || [])
      .filter((item) => typeof item === "string" && item.trim())
      .slice(0, 5);

    return res.status(200).json({
      emojis: emojis.length > 0 ? emojis : ["🙂", "👍", "✨"],
    });
  } catch (error) {
    console.error("[ai.suggestEmojis] Gemini error", error);
    return res.status(200).json({
      emojis: ["🙂", "👍", "✨"],
      fallback: true,
    });
  }
};
