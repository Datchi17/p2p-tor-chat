import { createEffect, createSignal, For, on, Show } from 'solid-js'
import { api, errorText, type Contact, type FileInfo, type Message } from '../api'

const TIMERS: [number, string][] = [
  [0, 'Off'],
  [300, '5 minutes'],
  [3600, '1 hour'],
  [86400, '1 day'],
  [604800, '1 week'],
]

const STATUS: Record<string, string> = { queued: '🕓', delivered: '✓', read: '✓✓', failed: '⚠ not delivered' }

function size(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

function fileStatus(f: FileInfo) {
  const pct = f.total ? Math.floor((f.done * 100) / f.total) : 0
  switch (f.state) {
    case 'sending':
      return `sending… ${pct}%`
    case 'receiving':
      return `receiving… ${pct}%`
    case 'failed':
      return '⚠ transfer failed'
    default:
      return ''
  }
}

function until(ms: number) {
  const left = ms - Date.now()
  if (left <= 0) return 'soon'
  const h = left / 3600_000
  if (h >= 48) return `in ${Math.round(h / 24)} days`
  if (h >= 1) return `in ${Math.round(h)} h`
  return `in ${Math.max(1, Math.round(left / 60_000))} min`
}

function time(ms: number) {
  const d = new Date(ms)
  const today = new Date()
  const sameDay = d.toDateString() === today.toDateString()
  return sameDay
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
}

export default function Chat(props: {
  contact: Contact
  messages: Message[]
  onSend: (text: string) => Promise<string | null>
  onVerify: () => void
  onChanged: () => void
  onLoadOlder: () => Promise<void>
}) {
  const [text, setText] = createSignal('')
  const [error, setError] = createSignal('')
  const [menu, setMenu] = createSignal(false)
  const [confirmDelete, setConfirmDelete] = createSignal(false)
  const [renaming, setRenaming] = createSignal<string | null>(null)
  let list: HTMLDivElement | undefined
  let input: HTMLTextAreaElement | undefined

  // Keep the view pinned to the newest message when the user is at the bottom.
  createEffect(
    on(
      () => props.messages.length,
      () => {
        if (!list) return
        const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 120
        if (nearBottom) queueMicrotask(() => list && (list.scrollTop = list.scrollHeight))
      },
    ),
  )
  createEffect(
    on(
      () => props.contact.id,
      () => {
        setText('')
        setError('')
        setMenu(false)
        setConfirmDelete(false)
        setRenaming(null)
        queueMicrotask(() => {
          if (list) list.scrollTop = list.scrollHeight
          input?.focus()
        })
      },
    ),
  )

  const send = async () => {
    const t = text()
    if (!t.trim()) return
    const err = await props.onSend(t)
    if (err) setError(err)
    else {
      setText('')
      setError('')
    }
  }

  const rename = async (e: Event) => {
    e.preventDefault()
    const name = renaming()
    if (name === null) return
    try {
      await api.renameContact(props.contact.id, name)
      props.onChanged()
      setRenaming(null)
    } catch (err) {
      setError(errorText(err))
    }
  }

  const remove = async () => {
    await api.deleteContact(props.contact.id)
    props.onChanged()
  }

  const [sendingFile, setSendingFile] = createSignal(false)
  const sendFile = async () => {
    setSendingFile(true)
    try {
      await api.sendFile(props.contact.id)
      setError('')
    } catch (e) {
      setError(errorText(e))
    } finally {
      setSendingFile(false)
    }
  }
  const saveFile = async (id: string) => {
    try {
      await api.saveFile(id)
    } catch (e) {
      setError(errorText(e))
    }
  }

  const setTimer = async (secs: number) => {
    try {
      await api.setDisappearing(props.contact.id, secs)
    } catch (e) {
      setError(errorText(e))
    }
  }

  return (
    <div class="chat">
      <header class="chat-head">
        <div>
          <div class="chat-title">
            {props.contact.name}{' '}
            <Show when={props.contact.verified} fallback={<span class="badge warn">not verified</span>}>
              <span class="badge ok" title="Safety number verified">
                ✅ verified
              </span>
            </Show>
          </div>
          <div class="muted small">{props.contact.online ? '🟢 reachable now' : '⚪ offline — messages will wait'}</div>
        </div>
        <div class="row gap">
          <label class="small muted" title="Disappearing messages: each message is deleted on both sides this long after it is received">
            ⏱{' '}
            <select
              value={props.contact.disappear_secs}
              disabled={!props.contact.verified}
              onChange={(e) => setTimer(Number(e.currentTarget.value))}
            >
              <For each={TIMERS}>{([s, l]) => <option value={s}>{l}</option>}</For>
              <Show when={!TIMERS.some(([s]) => s === props.contact.disappear_secs)}>
                <option value={props.contact.disappear_secs}>{props.contact.disappear_secs}s</option>
              </Show>
            </select>
          </label>
          <button class="icon" onClick={() => setMenu(!menu())} title="More">
            ⋮
          </button>
          <Show when={menu()}>
            <div class="menu">
              <button onClick={() => (setMenu(false), props.onVerify())}>Verify safety number</button>
              <button onClick={() => (setMenu(false), setRenaming(props.contact.name))}>Rename</button>
              <button class="danger-text" onClick={() => setConfirmDelete(true)}>
                Delete contact…
              </button>
            </div>
          </Show>
        </div>
      </header>

      <Show when={renaming() !== null}>
        <form class="banner row gap" onSubmit={rename}>
          <input value={renaming() ?? ''} onInput={(e) => setRenaming(e.currentTarget.value)} maxLength={64} autofocus spellcheck={false} autocorrect="off" autocapitalize="off" autocomplete="off" />
          <button class="primary small-btn">Save</button>
          <button type="button" class="link" onClick={() => setRenaming(null)}>
            Cancel
          </button>
        </form>
      </Show>
      <Show when={confirmDelete()}>
        <div class="banner danger">
          Delete {props.contact.name} and all messages? You would need to pair again.{' '}
          <button class="danger" onClick={remove}>
            Delete
          </button>{' '}
          <button class="link" onClick={() => (setConfirmDelete(false), setMenu(false))}>
            Cancel
          </button>
        </div>
      </Show>
      <Show when={!props.contact.verified}>
        <div class="banner warn">
          You haven't verified {props.contact.name}'s safety number yet. Until you do, someone could be impersonating
          them, and sending is disabled.{' '}
          <button class="primary small-btn" onClick={props.onVerify}>
            Verify now
          </button>
        </div>
      </Show>

      <div class="messages" ref={list}>
        <Show when={props.messages.length >= 100}>
          <button class="link center" onClick={props.onLoadOlder}>
            Load older messages
          </button>
        </Show>
        <For each={props.messages}>
          {(m) => (
            <Show
              when={m.kind !== 'system'}
              fallback={
                <div class="system">
                  {m.body} · {time(m.ts)}
                </div>
              }
            >
              <div class={`bubble ${m.outgoing ? 'out' : 'in'}`}>
                {/* Plain text only: message bodies are never interpreted as HTML. */}
                <Show when={m.file} fallback={<div class="body">{m.body}</div>}>
                  {(f) => (
                    <div class="file">
                      <div class="body">
                        📄 <strong>{f().name}</strong> <span class="small">({size(f().size)})</span>
                      </div>
                      <Show when={fileStatus(f())}>
                        <div class="small">{fileStatus(f())}</div>
                      </Show>
                      <Show when={!m.outgoing && f().state === 'received'}>
                        <button class="small-btn" onClick={() => void saveFile(m.id)}>
                          Save…
                        </button>
                        <div class="small muted-on-bubble">Only open files you expected. Files can contain malware.</div>
                      </Show>
                    </div>
                  )}
                </Show>
                <div class="meta">
                  <Show when={m.expires_at}>
                    {(t) => <span title={`Disappears ${until(t())}`}>⏱ </span>}
                  </Show>
                  {time(m.ts)}
                  <Show when={m.outgoing}>
                    {' '}
                    <span class={`status ${m.status}`}>{STATUS[m.status] ?? ''}</span>
                  </Show>
                </div>
              </div>
            </Show>
          )}
        </For>
      </div>

      <Show when={error()}>
        <div class="error pad">{error()}</div>
      </Show>
      <form
        class="composer"
        onSubmit={(e) => {
          e.preventDefault()
          void send()
        }}
      >
        <button
          type="button"
          class="icon attach"
          title="Send a file (up to 64 MB)"
          disabled={!props.contact.verified || sendingFile()}
          onClick={() => void sendFile()}
        >
          📎
        </button>
        <textarea
          ref={input}
          rows={2}
          value={text()}
          spellcheck={false}
          autocorrect="off"
          autocapitalize="off"
          autocomplete="off"
          maxLength={16000}
          disabled={!props.contact.verified}
          placeholder={props.contact.verified ? 'Type a message… (Enter to send, Shift+Enter for a new line)' : 'Verify this contact to send messages'}
          onInput={(e) => setText(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              void send()
            }
          }}
        />
        <button class="primary" disabled={!props.contact.verified || !text().trim()}>
          Send
        </button>
      </form>
    </div>
  )
}
