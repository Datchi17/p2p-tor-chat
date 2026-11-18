// Typed bridge to the Rust core. The UI never handles keys or ciphertext: it only sends
// user actions (text, passphrases) and renders what the core returns.
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

export type AppState = 'no_vault' | 'locked' | 'unlocked'

export interface Contact {
  id: number
  name: string
  onion: string
  verified: boolean
  online: boolean
  disappear_secs: number
  unread: number
  queued: number
}

export interface Message {
  id: string
  contact_id: number
  outgoing: boolean
  kind: 'text' | 'file' | 'system'
  body: string
  ts: number
  sent_at: number
  status: 'queued' | 'delivered' | 'read' | 'failed' | 'unread' | 'seen'
  expires_at: number | null
  file: FileInfo | null
}

export interface FileInfo {
  name: string
  size: number
  done: number
  total: number
  state: 'sending' | 'sent' | 'receiving' | 'received' | 'failed'
}

export interface MyCode {
  code: string
  qr_svg: string
  onion: string
  name: string
}

export interface Settings {
  read_receipts: boolean
  auto_lock_minutes: number
  notifications: boolean
  bridges: string[]
}

export type CoreEvent =
  | { type: 'tor'; progress: number; ready: boolean; error: string | null }
  | { type: 'presence'; contact_id: number; online: boolean }
  | { type: 'message'; message: Message }
  | { type: 'deleted'; contact_id: number; ids: string[] }
  | { type: 'contacts' }
  | { type: 'security'; contact_id: number; message: string }
  | { type: 'locked' }

export const api = {
  state: () => invoke<AppState>('app_state'),
  createVault: (name: string, passphrase: string) => invoke<void>('create_vault', { name, passphrase }),
  unlock: (passphrase: string) => invoke<void>('unlock', { passphrase }),
  verifyPassphrase: (passphrase: string) => invoke<boolean>('verify_passphrase', { passphrase }),
  lock: () => invoke<void>('lock'),
  changePassphrase: (oldPassphrase: string, newPassphrase: string) =>
    invoke<void>('change_passphrase', { oldPassphrase, newPassphrase }),
  panicWipe: () => invoke<void>('panic_wipe'),
  myCode: () => invoke<MyCode>('my_code'),
  addContact: (code: string, nickname: string | null) => invoke<number>('add_contact', { code, nickname }),
  contacts: () => invoke<Contact[]>('contacts'),
  safetyNumber: (contactId: number) => invoke<string[]>('safety_number', { contactId }),
  verifyContact: (contactId: number, proof: [number, string][]) => invoke<void>('verify_contact', { contactId, proof }),
  unverifyContact: (contactId: number) => invoke<void>('unverify_contact', { contactId }),
  renameContact: (contactId: number, name: string) => invoke<void>('rename_contact', { contactId, name }),
  deleteContact: (contactId: number) => invoke<void>('delete_contact', { contactId }),
  messages: (contactId: number, beforeTs: number | null) =>
    invoke<Message[]>('messages', { contactId, beforeTs }),
  sendText: (contactId: number, text: string) => invoke<Message>('send_text', { contactId, text }),
  /** Opens the native file picker in the core; null if cancelled. */
  sendFile: (contactId: number) => invoke<Message | null>('send_file', { contactId }),
  /** Opens the native save dialog in the core; false if cancelled. */
  saveFile: (messageId: string) => invoke<boolean>('save_file', { messageId }),
  markRead: (contactId: number) => invoke<void>('mark_read', { contactId }),
  setDisappearing: (contactId: number, secs: number) => invoke<void>('set_disappearing', { contactId, secs }),
  settings: () => invoke<Settings>('get_settings'),
  setSettings: (settings: Settings) => invoke<void>('set_settings', { settings }),
  torLog: () => invoke<string[]>('tor_log'),
  attention: () => invoke<void>('request_attention'),
  buildAgeDays: () => invoke<number | null>('build_age_days'),
}

export function onCoreEvent(handler: (e: CoreEvent) => void): Promise<UnlistenFn> {
  return listen<CoreEvent>('core-event', (e) => handler(e.payload))
}

/** Errors from Tauri commands arrive as strings. */
export function errorText(e: unknown): string {
  if (typeof e === 'string') return e
  if (e instanceof Error) return e.message
  return 'Something went wrong.'
}
