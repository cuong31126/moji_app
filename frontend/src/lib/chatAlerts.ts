type ChatAlertPayload = {
  title: string;
  body?: string;
  conversationId?: string;
};

let audioContext: AudioContext | null = null;

const getAudioContext = () => {
  const windowWithAudio = window as Window & {
    webkitAudioContext?: typeof AudioContext;
  };
  const AudioContextCtor = window.AudioContext || windowWithAudio.webkitAudioContext;

  if (!AudioContextCtor) {
    return null;
  }

  audioContext ??= new AudioContextCtor();
  return audioContext;
};

export const requestChatNotificationPermission = async () => {
  if (typeof window === "undefined" || !("Notification" in window)) {
    return "denied";
  }

  if (Notification.permission !== "default") {
    return Notification.permission;
  }

  return Notification.requestPermission();
};

const playChatSound = () => {
  if (typeof window === "undefined") {
    return;
  }

  try {
    const context = getAudioContext();

    if (!context) {
      return;
    }

    if (context.state === "suspended") {
      void context.resume();
    }

    const oscillator = context.createOscillator();
    const gain = context.createGain();
    const now = context.currentTime;

    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(720, now);
    oscillator.frequency.exponentialRampToValueAtTime(540, now + 0.14);
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.exponentialRampToValueAtTime(0.08, now + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.16);

    oscillator.connect(gain);
    gain.connect(context.destination);
    oscillator.start(now);
    oscillator.stop(now + 0.18);
  } catch (error) {
    console.warn("[chat-alert] Cannot play sound", error);
  }
};

export const notifyChatEvent = ({
  title,
  body,
  conversationId,
}: ChatAlertPayload) => {
  playChatSound();

  if (typeof window === "undefined" || !("Notification" in window)) {
    return;
  }

  if (Notification.permission !== "granted") {
    return;
  }

  const notification = new Notification(title, {
    body,
    icon: "/logo.svg",
    silent: true,
    tag: conversationId ? `moji-chat-${conversationId}` : "moji-chat",
  });

  window.setTimeout(() => notification.close(), 5000);
};
