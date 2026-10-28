import { getBackend } from '../backend';
import type { AccountId, BaseId, ObjectId, ChatMessage, ChatSummary } from '../backend/types';

export function hero(account: AccountId, base: BaseId) {
  const backend = getBackend();
  return {
    chats: (): Promise<ChatSummary[]> => backend.heroChats(account, base),
    chatFor: (project: ObjectId | null) => backend.heroChatFor(account, base, project),
    newChat: () => backend.heroNewChat(account, base),
    messages: (chat: ObjectId): Promise<ChatMessage[]> => backend.heroMessages(account, base, chat),
    send: (chat: ObjectId, text: string, focus: ObjectId | null) => backend.heroSend(account, base, chat, text, focus),
    stop: (chat: ObjectId) => backend.heroStop(account, base, chat),
    answer: (chat: ObjectId, requested: BaseId, allow: boolean) => backend.heroAnswer(account, base, chat, requested, allow),
    retry: (chat: ObjectId) => backend.heroRetry(account, base, chat),
    onEvent: backend.onEvent.bind(backend),
    getObject: backend.getObject.bind(backend),
  };
}
